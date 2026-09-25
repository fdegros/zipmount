// Copyright 2021 Google LLC
// Copyright 2008-2020 Alexander Galanin <al@galanin.nnov.ru>
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

#include "tree.h"

#include <algorithm>
#include <array>
#include <bit>
#include <cassert>
#include <cctype>
#include <cerrno>
#include <cstring>
#include <functional>
#include <iomanip>
#include <iostream>
#include <iterator>
#include <memory>
#include <stdexcept>
#include <vector>

#include <limits.h>
#include <termios.h>
#include <unicode/putil.h>
#include <unicode/uclean.h>
#include <unicode/ucnv.h>
#include <unicode/ucsdet.h>
#include <unicode/udata.h>
#include <unistd.h>
#include <zip.h>

#include <boost/functional/hash.hpp>

#include "error.h"
#include "extra_field.h"
#include "file_descriptor.h"
#include "log.h"

namespace {

i64 SafeAdd(i64 const a, i64 const b) {
  i64 r;
  if (__builtin_add_overflow(a, b, &r)) {
    std::string msg = StrCat("Integer overflow with ", a, " + ", b);
    LOG(ERROR) << msg;
    throw std::overflow_error(std::move(msg));
  }

  return r;
}

}  // namespace

enum CompressionMethod : int;

std::ostream& operator<<(std::ostream& out, const CompressionMethod cm) {
  out << "ZIP_CM_";

  switch (cm) {
#define PRINT(s)   \
  case ZIP_CM_##s: \
    return out << #s;

    PRINT(STORE)
    PRINT(SHRINK)
    PRINT(REDUCE_1)
    PRINT(REDUCE_2)
    PRINT(REDUCE_3)
    PRINT(REDUCE_4)
    PRINT(IMPLODE)
    PRINT(DEFLATE)
    PRINT(DEFLATE64)
    PRINT(PKWARE_IMPLODE)
    PRINT(BZIP2)
    PRINT(LZMA)
    PRINT(TERSE)
    PRINT(LZ77)
    PRINT(LZMA2)
    PRINT(XZ)
    PRINT(JPEG)
    PRINT(WAVPACK)
    PRINT(PPMD)
#undef PRINT
  }

  return out << static_cast<int>(cm);
}

enum EncryptionMethod : int;

std::ostream& operator<<(std::ostream& out, const EncryptionMethod em) {
  out << "ZIP_EM_";

  switch (em) {
#define PRINT(s)   \
  case ZIP_EM_##s: \
    return out << #s;

    PRINT(NONE)
    PRINT(TRAD_PKWARE)
    PRINT(AES_128)
    PRINT(AES_192)
    PRINT(AES_256)
    PRINT(UNKNOWN)
#undef PRINT
  }

  return out << static_cast<int>(em);
}

namespace {

// Temporarily suppresses the echo on the terminal.
// Used when waiting for password to be typed.
class SuppressEcho {
 public:
  explicit SuppressEcho() {
    if (tcgetattr(STDIN_FILENO, &tattr_) < 0) {
      return;
    }

    reset_ = true;

    struct termios tattr = tattr_;
    tattr.c_lflag &= ~ECHO;
    tcsetattr(STDIN_FILENO, TCSAFLUSH, &tattr);
  }

  ~SuppressEcho() {
    if (reset_) {
      tcsetattr(STDIN_FILENO, TCSAFLUSH, &tattr_);
    }
  }

  explicit operator bool() const { return reset_; }

 private:
  struct termios tattr_;
  bool reset_ = false;
};

// Checks if the given character is an ASCII digit.
bool IsAsciiDigit(const char c) {
  return c >= '0' && c <= '9';
}

// Removes the numeric suffix at the end of the given string `s`. Does nothing
// if the string does not end with a numeric suffix. A numeric suffix is a
// decimal number between parentheses and preceded by a space, like:
// * " (1)" or
// * " (142857)".
void RemoveNumericSuffix(std::string& s) {
  size_t i = s.size();

  if (i == 0 || s[--i] != ')') {
    return;
  }

  if (i == 0 || !IsAsciiDigit(s[--i])) {
    return;
  }

  while (i > 0 && IsAsciiDigit(s[i - 1])) {
    --i;
  }

  if (i == 0 || s[--i] != '(') {
    return;
  }

  if (i == 0 || s[--i] != ' ') {
    return;
  }

  s.resize(i);
}

struct Segment {
  std::string_view name;
  size_t path_length;
  size_t path_hash;
};

using Segments = std::vector<Segment>;

Segments GetSegments(std::string_view const path) {
  Segments segments;
  segments.reserve(std::ranges::count(path, '/'));
  size_t path_hash = 0;
  assert(path.starts_with('/'));

  size_t i = 0;
  size_t segment_begin = i + 1;
  boost::hash_combine(path_hash, path[i]);

  while (++i < path.size()) {
    char const c = path[i];
    if (c == '/') {
      assert(segment_begin < i);
      segments.emplace_back(path.substr(segment_begin, i - segment_begin), i,
                            path_hash);
      segment_begin = i + 1;
    }
    boost::hash_combine(path_hash, c);
  }

  assert(segment_begin < i);
  segments.emplace_back(path.substr(segment_begin, i - segment_begin), i,
                        path_hash);
  return segments;
}

}  // namespace

bool Tree::ReadPasswordFromStdIn() {
  std::string password;

  {
    const SuppressEcho guard;
    if (guard) {
      std::cout << "Password > " << std::flush;
    }

    // Read password from standard input.
    if (!std::getline(std::cin, password)) {
      password.clear();
    }

    if (guard) {
      std::cout << "Got it!" << std::endl;
    }
  }

  // Remove newline at the end of password.
  while (password.ends_with('\n')) {
    password.pop_back();
  }

  if (password.empty()) {
    LOG(DEBUG) << "Got an empty password";
    return false;
  }

  LOG(DEBUG) << "Got a password of " << password.size() << " bytes";

  for (const auto& [zip, zip_path] : zips_) {
    zip_t* const z = zip.get();
    if (zip_set_default_password(z, password.c_str()) < 0) {
      throw ZipError(StrCat("Cannot set password for ", Path(zip_path)), z);
    }
  }

  return true;
}

namespace {

#ifdef CHROME_ICU
// Initializes and cleans up the ICU library.
class IcuGuard {
 public:
  // Initializes the ICU library with the given ICU data file.
  // Throws an runtime_error in case of error.
  IcuGuard(const char* const data_file) : mapped_file_(data_file) {
    UErrorCode error = U_ZERO_ERROR;
    udata_setCommonData(mapped_file_.data(), &error);
    udata_setFileAccess(UDATA_ONLY_PACKAGES, &error);
    u_init(&error);
    if (U_FAILURE(error)) {
      throw std::runtime_error(
          StrCat("Cannot initialize ICU: ", u_errorName(error)));
    }
  }

  // Cleans up the ICU library.
  ~IcuGuard() { u_cleanup(); }

  // No copy.
  IcuGuard(const IcuGuard&) = delete;
  IcuGuard& operator=(const IcuGuard&) = delete;

 private:
  // Memory-mapped ICU data file.
  const FileMapping mapped_file_;
};
#endif

struct Closer {
  void operator()(UConverter* const conv) const { ucnv_close(conv); }
  void operator()(UCharsetDetector* const csd) const { ucsdet_close(csd); }
};

using ConverterPtr = std::unique_ptr<UConverter, Closer>;
using CharsetDetectorPtr = std::unique_ptr<UCharsetDetector, Closer>;

class ConverterToUtf8 {
 public:
  // Creates a converter that will convert strings from the given encoding to
  // UTF-8. Allocates internal buffers to handle strings up to
  // `maxInputLength`. Throws an exception in case of error.
  ConverterToUtf8(const char* const fromEncoding, const size_t maxInputLength)
      : from(Open(fromEncoding)), to(Open("UTF-8")) {
    utf16.resize(2 * maxInputLength + 1);
    utf8.resize(3 * maxInputLength + 1);
  }

  // Converts the given string to UTF-8. Returns a string_view to the internal
  // buffer holding the null-terminated result. Returns an empty string_view in
  // case of error.
  std::string_view operator()(const std::string_view in) {
    UErrorCode error = U_ZERO_ERROR;
    const int32_t len16 = ucnv_toUChars(from.get(), utf16.data(), utf16.size(),
                                        in.data(), in.size(), &error);

    if (U_FAILURE(error)) {
      LOG(ERROR) << "Cannot convert to UTF-16: " << u_errorName(error);
      return {};
    }

    const int32_t len8 = ucnv_fromUChars(to.get(), utf8.data(), utf8.size(),
                                         utf16.data(), len16, &error);

    if (U_FAILURE(error)) {
      LOG(ERROR) << "Cannot convert to UTF-8: " << u_errorName(error);
      return {};
    }

    assert(!utf8[len8]);
    return std::string_view(utf8.data(), len8);
  }

 private:
  // Opens an ICU converter for the given encoding.
  // Throws a runtime_error in case of error.
  static ConverterPtr Open(const char* const encoding) {
    UErrorCode error = U_ZERO_ERROR;
    ConverterPtr conv(ucnv_open(encoding, &error));

    if (U_FAILURE(error)) {
      throw std::runtime_error(StrCat("Cannot open converter for encoding '",
                                      encoding, "': ", u_errorName(error)));
    }

    assert(conv);
    return conv;
  }

  const ConverterPtr from, to;
  std::vector<UChar> utf16;
  std::vector<char> utf8;
};

// Detects the encoding of the given string.
// Returns the encoding name, or an empty string in case of error.
std::string DetectEncoding(const std::string_view bytes) {
  UErrorCode error = U_ZERO_ERROR;
  const CharsetDetectorPtr csd(ucsdet_open(&error));
  ucsdet_setText(csd.get(), bytes.data(), static_cast<int32_t>(bytes.size()),
                 &error);

  // Get most plausible encoding.
  const UCharsetMatch* const ucm = ucsdet_detect(csd.get(), &error);
  const char* const encoding = ucsdet_getName(ucm, &error);
  if (U_FAILURE(error)) {
    LOG(ERROR) << "Cannot detect encoding: " << u_errorName(error);
    return std::string();
  }

  LOG(DEBUG) << "Detected encoding " << encoding << " with "
             << ucsdet_getConfidence(ucm, &error) << "% confidence";

  // Check if we want to convert the detected encoding via ICU.
  const std::string_view candidates[] = {
      "Shift_JIS",   "Big5",        "EUC-JP",      "EUC-KR", "GB18030",
      "ISO-2022-CN", "ISO-2022-JP", "ISO-2022-KR", "KOI8-R"};

  for (const std::string_view candidate : candidates) {
    if (candidate == encoding) {
      return encoding;
    }
  }

  // Not handled by ICU.
  return std::string();
}

}  // namespace

Tree::NodesByPath::~NodesByPath() {
#ifndef NDEBUG
  for (Node& node : *this) {
    node.children.clear();
  }
#endif

  clear_and_dispose(std::default_delete<Node>());
}

void Tree::RehashIfNecessary() {
  if (nodes_by_path_.size() > nodes_by_path_.bucket_count()) {
    const size_t n = nodes_by_path_.bucket_count() * 2;
    std::vector<NodesByPath::bucket_type> new_buckets(n);
    nodes_by_path_.rehash({new_buckets.data(), n});
    buckets_by_path_.swap(new_buckets);
  }
}

Tree::Tree(std::span<const std::string> paths, Options opts)
    : Tree(OpenZips(paths), std::move(opts)) {
  assert(root_);
  assert(root_->IsRoot());

  // Sum of all uncompressed file sizes.
  i64 total_uncompressed_size = 0;
  zip_stat_t sb;

  // Concatenate all the names in a buffer in order to guess the encoding.
  std::string all_names;
  all_names.reserve(10000);
  size_t max_name_length = 0;

  for (const auto& [zip, zip_path] : zips_) {
    zip_t* const z = zip.get();
    const i64 n = zip_get_num_entries(z, 0);
    for (i64 id = 0; id < n; ++id) {
      if (zip_stat_index(z, id, ZIP_FL_ENC_RAW, &sb) < 0) {
        throw ZipError(
            StrCat("Cannot read entry #", id, " of ", Path(zip_path)), z);
      }

      if ((sb.valid & ZIP_STAT_SIZE) != 0) {
        total_uncompressed_size = SafeAdd(total_uncompressed_size, sb.size);
      }

      if ((sb.valid & ZIP_STAT_NAME) == 0 || !sb.name || !*sb.name) {
        continue;
      }

      const std::string_view name = sb.name;
      if (max_name_length < name.size()) {
        max_name_length = name.size();
      }

      if (all_names.size() + name.size() <= all_names.capacity()) {
        all_names.append(name);
      }
    }
  }

  LOG(DEBUG) << "Total uncompressed size = " << total_uncompressed_size
             << " bytes";

#ifdef CHROME_ICU
  // Initialize ICU library and ensure it will be cleaned up.
  const IcuGuard guard("/opt/google/chrome/icudtl.dat");
#endif

  // Detect filename encoding.
  std::string encoding;
  if (opts_.encoding) {
    encoding = opts_.encoding;
  }

  if (encoding.empty() || encoding == "auto") {
    encoding = DetectEncoding(all_names);
  }

  all_names.clear();

  // Prepare functor to convert filenames to UTF-8.
  // By default, just rely on the conversion to UTF-8 provided by libzip.
  ToUtf8 toUtf8 = [](std::string_view s) { return s; };
  zip_flags_t zipFlags = ZIP_FL_ENC_GUESS;

  // But if the filename encoding is one of the encodings we want to convert
  // using ICU, prepare and use the ICU converter.
  if (!encoding.empty() && encoding != "libzip") {
    try {
      if (encoding != "raw") {
        toUtf8 = [converter = std::make_shared<ConverterToUtf8>(
                      encoding.c_str(), max_name_length)](std::string_view s) {
          return (*converter)(s);
        };
      }
      zipFlags = ZIP_FL_ENC_RAW;
    } catch (const std::exception& e) {
      LOG(ERROR) << e.what();
    }
  }

  Beat should_display_progress;
  i64 total_extracted_size = 0;
  const auto progress = [&should_display_progress, &total_uncompressed_size,
                         &total_extracted_size](const ssize_t chunk_size) {
    assert(chunk_size >= 0);
    total_extracted_size = SafeAdd(total_extracted_size, chunk_size);
    if (should_display_progress) {
      LOG(INFO) << "Loading... "
                << ProgressMessage(total_extracted_size <
                                           total_uncompressed_size
                                       ? 100 * total_extracted_size /
                                             total_uncompressed_size
                                       : 100);
    }
  };

  std::string path;
  path.reserve(PATH_MAX);
  std::vector<Node*> hard_links;

  // Add zip entries for all items except hard links
  for (const auto& [zip, zip_path] : zips_) {
    path = '/';
    if (!opts_.merge) {
      Node::Ptr archive_node(new Node{
          .parent = root_,
          .name = std::string(Path(zip_path).Split().second.WithoutExtension()),
          .mode = mode_t(S_IFDIR | 0777),
          .nlink = 2});
      Node* const node = RenameIfCollision(std::move(archive_node));
      assert(node->IsDir());
      root_->AddChild(node);
      total_block_count_++;
      path += node->name;
    }

    assert(path.capacity() >= PATH_MAX);

    size_t const initial_path_length = path.size();

    zip_t* const z = zip.get();
    current_archive = z;
    hard_links.clear();
    nodes_by_original_path_.clear();

    const i64 n = zip_get_num_entries(z, 0);
    for (i64 id = 0; id < n; ++id) {
      if (zip_stat_index(z, id, zipFlags, &sb) < 0) {
        throw ZipError(
            StrCat("Cannot read entry #", id, " of ", Path(zip_path)), z);
      }

      const Path original_path =
          (sb.valid & ZIP_STAT_NAME) != 0 && sb.name && *sb.name ? sb.name
                                                                 : "-";
      path.resize(initial_path_length);
      Path(toUtf8(original_path)).NormalizeAppend(&path);
      const i64 size = (sb.valid & ZIP_STAT_SIZE) != 0 ? sb.size : 0;
      const auto [mode, is_hard_link] =
          GetEntryAttributes(z, id, original_path);
      const FileType type = GetFileType(mode);

      if (type == FileType::Directory) {
        if (!opts_.include_directories) {
          LOG(INFO) << "Skipped " << type << " [" << ++Node::ino_count << "] "
                    << Path(path);
          continue;
        }

        Node* const node = GetOrCreateDirNode(path);
        assert(node);
        assert(!node->hardlink_target);
        assert(node->IsDir());
        node->zip = z;
        node->id = id;
        node->mode = mode;
        node->Init();
        assert(total_uncompressed_size >= size);
        total_uncompressed_size -= size;
        assert(node->IsDir());
        continue;
      }

      if (type != FileType::File &&
          (type == FileType::Symlink ? !opts_.include_symlinks
                                     : !opts_.include_special_files)) {
        LOG(INFO) << "Skipped " << type << " [" << ++Node::ino_count << "] "
                  << Path(path);
        assert(total_uncompressed_size >= size);
        total_uncompressed_size -= size;
        continue;
      }

      if (is_hard_link && !opts_.include_hard_links) {
        LOG(INFO) << "Skipped " << type << " [" << ++Node::ino_count << "] "
                  << Path(path);
        assert(total_uncompressed_size >= size);
        total_uncompressed_size -= size;
        continue;
      }

      const auto [parent_path, name] = Path(path).Split();
      Node* const parent = GetOrCreateDirNode(parent_path);
      Node* const node = CreateFile(z, id, parent, name, mode);
      assert(!node->IsDir());
      parent->AddChild(node);
      total_block_count_++;

      if (is_hard_link) {
        hard_links.push_back(node);
        continue;
      }

      total_block_count_ += node->GetBlockCount();

      if (!zip_encryption_method_supported(sb.encryption_method, 1)) {
        ZipError e(StrCat("Cannot decrypt ", *node, ": ",
                          EncryptionMethod(sb.encryption_method)),
                   ZIP_ER_ENCRNOTSUPP);
        if (opts_.check_compression) {
          throw std::move(e);
        }
        LOG(ERROR) << e.what();
      }

      if (!zip_compression_method_supported(sb.comp_method, 1)) {
        ZipError e(StrCat("Cannot decompress ", *node, ": ",
                          CompressionMethod(sb.comp_method)),
                   ZIP_ER_COMPNOTSUPP);
        if (opts_.check_compression) {
          throw std::move(e);
        }
        LOG(ERROR) << e.what();
      }

      // Check the password on encrypted files.
      if ((sb.valid & ZIP_STAT_ENCRYPTION_METHOD) != 0 &&
          sb.encryption_method != ZIP_EM_NONE) {
        CheckPassword(node);
      }

      // Cache file data if necessary.
      if (opts_.pre_cache) {
        try {
          if (!node->CacheAll(progress)) {
            assert(total_uncompressed_size >= size);
            total_uncompressed_size -= size;
          }
        } catch (const ZipError& error) {
          LOG(ERROR) << "Cannot cache " << *node << ": " << error.what();
          if (opts_.check_password) {
            LOG(INFO) << "Use the -o force option to continue even if some "
                         "files cannot be cached";
            throw;
          }
        }
      }
    }

    // Add hard links
    for (Node* const node : hard_links) {
      path.resize(initial_path_length);
      Path(toUtf8(node->target)).NormalizeAppend(&path);
      Node* const target = FindNodeByOriginalPath(path);
      if (!target) {
        LOG(ERROR) << "Cannot find target for hard link " << *node << " -> "
                   << path;
        continue;
      }

      CreateHardLink(node, target);
    }
  }

  current_archive = nullptr;
  NodesByOriginalPath().swap(nodes_by_original_path_);

  if (should_display_progress.Count()) {
    LOG(INFO) << "Loading... " << ProgressMessage(100);
  }

  // Trim the top level if necessary.
  if (opts_.trim) {
    assert(root_);
    if (opts_.merge) {
      Trim(*root_);
    } else {
      for (Node& c : root_->children) {
        Trim(c);
      }
    }
  }

  LOG(DEBUG) << "Nodes = " << GetNodeCount();
  LOG(DEBUG) << "Blocks = " << total_block_count_;
}

void Tree::CheckPassword(const Node* const node) {
  assert(node);

  if (checked_password_) {
    return;
  }

  LOG(INFO) << "Need password for " << *node;
  ReadPasswordFromStdIn();

  try {
    LOG(DEBUG) << "Checking password on " << *node << "...";

    // Try to open the file and read a few bytes from it.
    const ZipFile file(zip_fopen_index(node->zip, node->id, 0));
    if (!file) {
      throw ZipError(StrCat("Cannot open ", *node), node->zip);
    }

    std::array<char, 16> buf;
    if (zip_fread(file.get(), buf.data(), buf.size()) < 0) {
      throw ZipError(StrCat("Cannot read ", *node), file.get());
    }

    LOG(INFO) << "Password is Ok";
  } catch (const ZipError& error) {
    if (opts_.check_password) {
      LOG(INFO) << "Use the -o force option to mount an encrypted ZIP with a "
                   "wrong password";
      throw;
    }

    LOG(DEBUG) << error.what();
    LOG(INFO) << "Continuing despite wrong password because of -o force option";
  }

  checked_password_ = true;
}

Tree::EntryAttributes Tree::GetEntryAttributes(
    zip_t* const z,
    const i64 id,
    const std::string_view original_path) {
  const bool is_dir = original_path.ends_with('/');

  zip_uint8_t opsys;
  zip_uint32_t attr;
  if (zip_file_get_external_attributes(z, id, 0, &opsys, &attr) < 0) {
    throw ZipError(StrCat("Cannot get attributes of entry #", id), z);
  }

  mode_t mode = mode_t(attr >> 16);
  bool is_hard_link = false;

  // PKWARE describes "OS made by" now (since 1998) as follows: The upper byte
  // indicates the compatibility of the file attribute information. If the
  // external file attributes are compatible with MS-DOS and can be read by
  // PKZIP for DOS version 2.04g then this value will be zero.
  if (opsys == ZIP_OPSYS_DOS && GetFileType(mode) != FileType::Unknown) {
    opsys = ZIP_OPSYS_UNIX;
  }

  switch (opsys) {
    case ZIP_OPSYS_UNIX:
      // force is_dir value
      if (is_dir) {
        SetFileType(&mode, FileType::Directory);
      } else if (const FileType ft = GetFileType(mode);
                 ft == FileType::Unknown || ft == FileType::Directory) {
        // If unknown type or mislabeled as directory, relabel as regular file.
        SetFileType(&mode, FileType::File);
      }

      // Always ignore hard link flag for dirs
      is_hard_link = (attr & 0x800) != 0 && !is_dir;
      break;

    case ZIP_OPSYS_DOS:
    case ZIP_OPSYS_WINDOWS_NTFS:
    case ZIP_OPSYS_MVS:
      // Both WINDOWS_NTFS and OPSYS_MVS used here because of difference in
      // constant assignment by PKWARE and Info-ZIP.
      mode = 0444;

      // http://msdn.microsoft.com/en-us/library/windows/desktop/gg258117%28v=vs.85%29.aspx
      // http://en.wikipedia.org/wiki/File_Allocation_Table#attributes
      // FILE_ATTRIBUTE_READONLY
      if ((attr & 1) == 0) {
        mode |= 0222;
      }

      if (is_dir) {
        mode |= S_IFDIR | 0111;
      } else {
        mode |= S_IFREG;
      }

      break;

    default:
      if (is_dir) {
        mode = S_IFDIR | 0777;
      } else {
        mode = S_IFREG | 0666;
      }
  }

  return {mode, is_hard_link};
}

Node* Tree::RenameIfCollision(Node::Ptr node) {
  assert(node);
  RehashIfNecessary();
  node->ComputePathHash();
  const auto [pos, ok] = nodes_by_path_.insert(*node);
  if (ok) {
    return node.release();  // Now owned by |nodes_by_path_|.
  }

  if (!node->renamed) {
    node->renamed = true;
    assert(!node->IsRoot());
    if (!node->IsDir() && node->zip == current_archive) {
      nodes_by_original_path_.insert({.renamed_node = node.get(),
                                      .original_name = node->name,
                                      .path_length = node->path_length,
                                      .path_hash = node->path_hash});
    }
  }

  // There is a name collision
  LOG(DEBUG) << *node << " conflicts with " << *pos;

  // Extract filename extension
  std::string& f = node->name;
  const std::string::size_type e = Path(f).ExtensionPosition();
  const std::string ext(f, e);
  f.resize(e);
  RemoveNumericSuffix(f);
  const std::string base = f;

  // Add a number before the extension
  for (int* i = nullptr;;) {
    const std::string suffix =
        StrCat(" (", std::to_string(i ? ++*i + 1 : 1), ")", ext);
    f.assign(base, 0, Path(base).TruncationPosition(NAME_MAX - suffix.size()));
    f += suffix;

    node->ComputePathHash();
    const auto [pos, ok] = nodes_by_path_.insert(*node);
    if (ok) {
      LOG(DEBUG) << "Resolved conflict for " << *node;
      return node.release();  // Now owned by |nodes_by_path_|.
    }

    LOG(DEBUG) << *node << " conflicts with " << *pos;
    if (!i) {
      i = &pos->collision_count;
    }
  }
}

Node* Tree::CreateFile(zip_t* const z,
                       i64 id,
                       Node* parent,
                       std::string_view name,
                       mode_t mode) {
  assert(parent);
  assert(!name.empty());
  assert(id >= 0);
  Node::Ptr node(new Node{.id = id,
                          .zip = z,
                          .parent = parent,
                          .name = std::string(name),
                          .mode = mode});
  node->Init();
  return RenameIfCollision(std::move(node));
}

void Tree::CreateHardLink(Node* const node, Node* const target) {
  assert(node);
  assert(target);

  if (node->GetTarget() == target->GetTarget()) {
    LOG(ERROR) << "Self-referencial hard link " << *node << " -> " << *target;
    return;
  }

  if (target->GetType() != node->GetType()) {
    // PkZip saves hard-link flag for symlinks with inode link count > 1.
    if (node->GetType() != FileType::Symlink) {
      LOG(ERROR) << "Mismatched types for hard link " << *node << " -> "
                 << *target;
    }

    return;
  }

  node->hardlink_target = target->GetTarget();
  node->hardlink_target->nlink++;

  // Copy metadata for the Copy Model (fast direct access).
  node->ino = node->hardlink_target->ino;
  node->mode = node->hardlink_target->mode;
  node->size = node->hardlink_target->size;
  node->dev = node->hardlink_target->dev;
  node->mtime = node->hardlink_target->mtime;
  node->atime = node->hardlink_target->atime;
  node->btime = node->hardlink_target->btime;
  node->uid = node->hardlink_target->uid;
  node->gid = node->hardlink_target->gid;

  LOG(DEBUG) << "Created hard link " << *node << " -> " << *target;
}

bool Tree::OriginalName::HasPath(std::string_view path) const {
  if (!path.ends_with(original_name)) {
    return false;
  }

  path.remove_suffix(original_name.size());

  assert(renamed_node);
  assert(renamed_node->renamed);
  const Node* const parent = renamed_node->parent;
  assert(parent);

  if (parent->IsRoot()) {
    return parent->HasPath(path);
  }

  if (!path.ends_with('/')) {
    return false;
  }

  path.remove_suffix(1);
  return parent->HasPath(path);
}

Node* Tree::FindNode(const HashedStringView& path) {
  auto const it = nodes_by_path_.find(path, nodes_by_path_.hash_function(),
                                      nodes_by_path_.key_eq());
  return it == nodes_by_path_.end() ? nullptr : &*it;
}

Node* Tree::FindNodeByOriginalPath(const HashedStringView& path) {
  auto const it = nodes_by_original_path_.find(path);
  if (it != nodes_by_original_path_.end()) {
    Node* const node = it->renamed_node;
    assert(node);
    assert(node->renamed);
    assert(node->zip == current_archive);
    return node;
  }

  Node* const node = FindNode(path);
  return node && !node->renamed && node->zip == current_archive ? node
                                                                : nullptr;
}

Node* Tree::GetOrCreateDirNode(std::string_view path) {
  if (!opts_.include_directories || path.size() <= 1) {
    return root_;
  }

  Segments const segments = GetSegments(path);
  Node* node = nullptr;
  size_t i = segments.size();

  // Find the deepest directory that already exists.
  while (!node && i > 0) {
    const Segment& segment = segments[--i];
    node = FindNode(HashedStringView(path.substr(0, segment.path_length),
                                     segment.path_hash));
  }

  Node::Ptr to_rename;
  if (!node) {
    assert(i == 0);
    node = root_;
    --i;
  } else if (!node->IsDir()) {
    // There is an existing node but it is not a directory. We'll rename it
    // because we need a directory at this location.
    LOG(DEBUG) << "Found conflicting " << *node << " while creating Dir "
               << Path(path);

    // Remove it from nodes_by_path_, in order to insert it again later with a
    // different name.
    nodes_by_path_.erase(nodes_by_path_.iterator_to(*node));
    to_rename.reset(node);
    node = node->parent;
    --i;
  }

  assert(node);
  assert(node->IsDir());

  // Create and index all missing directories.
  while (++i < segments.size()) {
    const Segment& segment = segments[i];
    Node::Ptr child(new Node{.parent = node,
                             .path_length = segment.path_length,
                             .path_hash = segment.path_hash,
                             .name = std::string(segment.name),
                             .mode = mode_t(S_IFDIR | 0777),
                             .nlink = 2});
    assert(child->IsDir());
    node->AddChild(child.get());
    total_block_count_++;

#ifndef NDEBUG
    child->ComputePathHash();
    assert(child->path_length == segment.path_length);
    assert(child->path_hash == segment.path_hash);
#endif

    RehashIfNecessary();
    [[maybe_unused]] const auto [pos, ok] = nodes_by_path_.insert(*child);
    assert(ok);
    node = child.release();
  }

  if (to_rename) {
    RenameIfCollision(std::move(to_rename));
  }

  return node;
}

Tree::Zips Tree::OpenZips(std::span<const std::string> paths) {
  Zips zips;
  zips.reserve(paths.size());

  for (const std::string& path : paths) {
    int err;
    Zip z(zip_open(path.c_str(), ZIP_RDONLY, &err));

    if (!z) {
      throw ZipError(StrCat("Cannot open ZIP archive ", Path(path)), err);
    }

    LOG(DEBUG) << "Opened " << Path(path);
    zips.push_back({std::move(z), path});
  }

  return zips;
}

void Tree::Trim(Node& a) {
  Node* p = a.GetUniqueChildDirectory();
  if (!p) {
    return;
  }

  Deindex(*p);
  a.children.clear();

  while (Node* const q = p->GetUniqueChildDirectory()) {
    p->children.clear();
    p = q;
  }

  LOG(DEBUG) << "Collapsing " << *p << " into " << a;

  // Move `p`'s data into `a`.
  a.uid = p->uid;
  a.gid = p->gid;
  a.dev = p->dev;
  a.size = p->size;
  a.mtime = p->mtime;
  a.atime = p->atime;
  a.btime = p->btime;
  a.target = std::move(p->target);
  a.reader = std::move(p->reader);
  a.mode = p->mode;
  a.nlink = p->nlink;
  a.zip = p->zip;
  a.id = p->id;

  // a.parent and a.name stay as they are.

  // They should be Directories, therefore they don't have hard link targets.
  assert(!p->hardlink_target);
  assert(!a.hardlink_target);
  a.children = std::move(p->children);
  assert(p->children.empty());

  for (Node& c : a.children) {
    assert(c.parent == p);
    c.parent = &a;
    Reindex(c);
  }

  LOG(INFO) << "Collapsed " << *p << " into " << a;
  LOG(INFO)
      << "Use `-o notrim` if you want to keep these intermediate directories";

  while (p != &a) {
    total_block_count_--;
    Node* const q = p->parent;
    delete p;
    p = q;
  }
}

void Tree::Deindex(Node& node) {
  for (Node& c : node.children) {
    Deindex(c);
  }
  nodes_by_path_.erase(nodes_by_path_.iterator_to(node));
}

void Tree::Reindex(Node& node) {
  node.ComputePathHash();
  [[maybe_unused]] bool const ok = nodes_by_path_.insert(node).second;
  assert(ok);

  for (Node& c : node.children) {
    Reindex(c);
  }
}
