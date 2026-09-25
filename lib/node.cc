// Copyright 2021 Google LLC
// Copyright 2008-2021 Alexander Galanin <al@galanin.nnov.ru>
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

#include "node.h"

#include <algorithm>
#include <cassert>
#include <cstdio>
#include <ctime>
#include <memory>
#include <tuple>
#include <vector>

#include <boost/functional/hash.hpp>

#include <zip.h>

#include "error.h"
#include "extra_field.h"

HashedStringView::HashedStringView(std::string_view s) : string(s), hash(0) {
  for (const char c : s) {
    boost::hash_combine(hash, c);
  }
}

std::ostream& operator<<(std::ostream& out, const FileType t) {
  switch (t) {
    case FileType::BlockDevice:
      return out << "Block Device";
    case FileType::CharDevice:
      return out << "Character Device";
    case FileType::Directory:
      return out << "Directory";
    case FileType::Fifo:
      return out << "FIFO";
    case FileType::File:
      return out << "File";
    case FileType::Socket:
      return out << "Socket";
    case FileType::Symlink:
      return out << "Symlink";
    default:
      return out << "Unknown";
  }
}

// Time this filesystem was mounted. Used as the default value of every
// timestamp below, which only matters for nodes not backed by a real archive
// entry (the root directory, and any intermediate directory implied by a nested
// path but not itself listed in the archive): those have no real timestamp to
// derive one from. This means such a directory's displayed timestamps depend on
// when it was mounted, not on the archive's own contents, unlike every other
// node's.
static const Time g_now = Time::Now();
const uid_t Node::g_uid = getuid();
const gid_t Node::g_gid = getgid();
mode_t Node::fmask = 0022;
mode_t Node::dmask = 0022;
bool Node::enforce_permissions = false;

ino_t Node::ino_count = 0;

void Node::Init() {
  assert(zip);
  zip_stat_t st;
  if (zip_stat_index(zip, id, 0, &st) < 0) {
    throw ZipError("Cannot stat file", zip);
  }

  // check that all used fields are valid
  [[maybe_unused]] const zip_uint64_t need_valid =
      ZIP_STAT_NAME | ZIP_STAT_INDEX | ZIP_STAT_SIZE | ZIP_STAT_MTIME;
  // required fields are always valid for existing items or newly added
  // directories (see zip_stat_index.c from libzip)
  assert((st.valid & need_valid) == need_valid);

  if (!IsDir()) {
    size = st.size;
  }

  mtime = st.mtime;

  bool has_pkware_field = false;

  // Gets timestamp, owner and group information from extra fields.
  // Process the extra fields in this precise order because of the following
  // precedences:
  // - Times from timestamp have precedence over the UNIX field times.
  // - High-precision NTFS timestamps precedence over the UNIX timestamps.
  // - UIDs and GIDs from UNIX fields with bigger field IDs have higher
  // - precedence.
  using enum FieldId;
  for (FieldId const field_id :
       {PKWARE_UNIX, INFOZIP_UNIX_1, INFOZIP_UNIX_2, INFOZIP_UNIX_3,
        UNIX_TIMESTAMP, NTFS_TIMESTAMP}) {
    zip_flags_t const flags = ZIP_FL_CENTRAL | ZIP_FL_LOCAL;
    using u16 = zip_uint16_t;
    u16 const n =
        zip_file_extra_fields_count_by_id(zip, id, u16(field_id), flags);

    for (u16 i = 0; i < n; ++i) {
      u16 field_size;
      const auto* const field_data = zip_file_extra_field_get_by_id(
          zip, id, u16(field_id), i, &field_size, flags);

      if (field_data && field_size > 0 &&
          Parse(field_id, Bytes(field_data, field_size), this) &&
          field_id == PKWARE_UNIX) {
        has_pkware_field = true;
      }
    }
  }

  // Use PKWARE link target only if link target in Info-ZIP format is not
  // specified (empty file content).
  if (S_ISLNK(mode) && size == 0) {
    size = target.size();
  }

  // InfoZIP may produce FIFO-marked node with content, PkZip - can't.
  if (S_ISFIFO(mode) && (size != 0 || !has_pkware_field)) {
    SetFileType(&mode, FileType::File);
  }
}

Stat Node::GetStat() const {
  Stat z = {};
  const Node* const t = GetTarget();
  assert(t);
  z.st_nlink = t->nlink;
  assert(z.st_nlink > 0);
  z.st_ino = ino;
  z.st_blksize = block_size;
  z.st_blocks = GetBlockCount();
  z.st_size = size;
  z.st_rdev = dev;

  const Time& atime = t->atime;

#if __APPLE__
  z.st_ctimespec = z.st_mtimespec = mtime.ValueOr(g_now);
  z.st_atimespec = atime.ValueOr(z.st_mtimespec);
  z.st_birthtimespec = btime.ValueOr(z.st_mtimespec);
#else
  z.st_ctim = z.st_mtim = mtime.ValueOr(g_now);
  z.st_atim = atime.ValueOr(z.st_mtim);
  // Linux's struct stat has no birthtime field at all (unlike Apple's and
  // FreeBSD's): that's what the statx FUSE operation is for.
#ifdef __FreeBSD__
  z.st_birthtim = btime.ValueOr(z.st_mtim);
#endif
#endif

  if (enforce_permissions) {
    z.st_uid = uid;
    z.st_gid = gid;
    z.st_mode = mode;
    switch (GetType()) {
      case FileType::Directory:
        z.st_mode &= ~dmask;
        break;

      case FileType::Symlink:
        break;

      default:
        z.st_mode &= ~fmask;
    }
  } else {
    z.st_uid = g_uid;
    z.st_gid = g_gid;
    const FileType ft = GetType();
    switch (ft) {
      case FileType::Directory:
        z.st_mode = static_cast<mode_t>(S_IFDIR | (0777 & ~dmask));
        break;

      case FileType::Symlink:
        z.st_mode = static_cast<mode_t>(S_IFLNK | 0777);
        break;

      default:
        z.st_mode = 0666;
        if (const mode_t xbits = 0111; (mode & xbits) != 0) {
          z.st_mode |= xbits;
        }
        z.st_mode &= ~fmask;
        SetFileType(&z.st_mode, ft);
    }
  }

  return z;
}

std::string Node::GetPath() const {
  if (IsRoot()) {
    assert(name == "/");
    return "/";
  }

  std::vector<const Node*> nodes;
  nodes.reserve(32);

  size_t n = 0;
  const Node* node = this;
  do {
    assert(!node->IsRoot());
    nodes.push_back(node);
    n += node->name.size() + 1;
    node = node->parent;
  } while (!node->IsRoot());

  assert(node);
  assert(node->IsRoot());
  assert(node->name == "/");

  std::string path;
  path.reserve(n);

  do {
    assert(!nodes.empty());
    path += '/';
    path += nodes.back()->name;
    nodes.pop_back();
  } while (!nodes.empty());

  assert(nodes.empty());
  assert(path.size() == n);
  return path;
}

bool Node::HasPath(std::string_view path) const {
  const Node* node = this;

  if (!node->IsRoot()) {
    while (true) {
      if (!path.ends_with(node->name)) {
        return false;
      }

      path.remove_suffix(node->name.size());
      node = node->parent;
      if (node->IsRoot()) {
        break;
      }

      if (!path.ends_with('/')) {
        return false;
      }

      path.remove_suffix(1);
    }
  }

  assert(node->IsRoot());
  return path == node->name;
}

// Recomputes this Node's path length and hash.
void Node::ComputePathHash() {
  path_length = 0;
  path_hash = 0;

  if (!IsRoot()) {
    path_length = parent->path_length;
    path_hash = parent->path_hash;
    if (!parent->IsRoot()) {
      ++path_length;
      boost::hash_combine(path_hash, '/');
    }
  }

  path_length += name.size();
  for (char const c : name) {
    boost::hash_combine(path_hash, c);
  }
}

void Node::AddChild(Node* const child) {
  assert(IsDir());
  assert(!hardlink_target);
  assert(nlink >= 2);
  assert(child);
  assert(child->parent == this);
  children.push_back(*child);
  size += block_size;
  assert(children.size() == GetBlockCount());
  nlink += child->IsDir();
}

Node* Node::GetUniqueChildDirectory() {
  if (!IsDir()) {
    // LOG(DEBUG) << *this << " is not a dir";
    return nullptr;
  }

  Node::Children::iterator const it = children.begin();
  if (it == children.end()) {
    // LOG(DEBUG) << *this << " has no children";
    return nullptr;
  }

  if (std::next(it) != children.end()) {
    // LOG(DEBUG) << *this << " has more than one child";
    return nullptr;
  }

  if (!it->IsDir()) {
    // LOG(DEBUG) << *it << " is not a dir";
    return nullptr;
  }

  return &*it;
}

namespace {

// Returns true if `file` (entry `id` of `zip`) can be safely passed to
// zip_fseek().
bool IsSeekable(zip_t* const zip, i64 const id, zip_file_t* const file) {
#if LIBZIP_VERSION_MAJOR > 1 || \
    LIBZIP_VERSION_MAJOR == 1 && LIBZIP_VERSION_MINOR >= 9

  using Version = std::tuple<int, int, int>;

  // Gets the runtime libzip version.
  const auto get_libzip_version = [] {
    int major = 0, minor = 0, micro = 0;
    std::sscanf(zip_libzip_version(), "%d.%d.%d", &major, &minor, &micro);
    return Version(major, minor, micro);
  };

  // zip_file_is_seekable() was introduced in libzip 1.9.0, but it can only be
  // trusted for libzip > 1.11.4 because of:
  // https://github.com/nih-at/libzip/issues/583
  // https://github.com/fdegros/zipmount/issues/1
  static const bool trusted = get_libzip_version() > Version(1, 11, 4);
  if (trusted) {
    return zip_file_is_seekable(file) > 0;
  }
#else
  (void)file;
#endif

  // Fallback way of determining if a file is seekable.
  zip_stat_t st;
  return zip_stat_index(zip, static_cast<zip_uint64_t>(id), 0, &st) == 0 &&
         (st.valid & ZIP_STAT_COMP_METHOD) != 0 &&
         st.comp_method == ZIP_CM_STORE &&
         (st.valid & ZIP_STAT_ENCRYPTION_METHOD) != 0 &&
         st.encryption_method == ZIP_EM_NONE;
}

}  // namespace

bool Node::CacheAll(std::function<void(ssize_t)> progress) {
  Node* const t = GetTarget();
  assert(!t->reader);
  if (t->size == 0) {
    LOG(DEBUG) << "No need to cache " << *this << ": Empty file";
    return false;
  }

  ZipFile file = Reader::Open(t->zip, t->id);
  assert(file);

  const bool seekable = IsSeekable(t->zip, t->id, file.get());

  if (seekable) {
    LOG(DEBUG) << "No need to cache " << *this << ": File is seekable";
    return false;
  }

  t->reader = CacheFile(std::move(file), t->id, t->size, std::move(progress));
  return true;
}

Reader::Ptr Node::GetReader() {
  Node* const t = GetTarget();
  if (t->reader) {
    LOG(DEBUG) << *t->reader << ": Reusing Cached " << *t->reader << " for "
               << *this;
    return t->reader->AddRef();
  }

  if (!t->target.empty()) {
    return Reader::Ptr(new StringReader(t->target));
  }

  ZipFile file = Reader::Open(t->zip, t->id);
  assert(file);

  const bool seekable = IsSeekable(t->zip, t->id, file.get());

  Reader::Ptr reader(seekable
                         ? new UnbufferedReader(std::move(file), t->id, t->size)
                         : new BufferedReader(t->zip, std::move(file), t->id,
                                              t->size, &t->reader));

  LOG(DEBUG) << *reader << ": Opened " << *this << ", seekable = " << seekable;
  return reader;
}

std::ostream& operator<<(std::ostream& out, const Node& node) {
  out << node.GetType() << " [" << node.ino;

  if (node.hardlink_target) {
    out << "->" << node.hardlink_target->ino;
  }

  return out << "] " << Path(node.GetPath());
}
