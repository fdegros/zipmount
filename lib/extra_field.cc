// Copyright 2021 Google LLC
// Copyright 2014-2019 Alexander Galanin <al@galanin.nnov.ru>
// http://galanin.nnov.ru/~al
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

#include "extra_field.h"

#include <sys/stat.h>
#if __has_include(<sys/sysmacros.h>)
#include <sys/sysmacros.h>
#endif

#include <algorithm>
#include <cassert>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <limits>
#include <stdexcept>
#include <type_traits>

#include "log.h"

namespace {

using u8 = std::uint8_t;
using u16 = std::uint16_t;
using u32 = std::uint32_t;
using u64 = std::uint64_t;
using i32 = std::int32_t;
using i64 = std::int64_t;

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__

template <typename T>
T letoh(T x) {
  return x;
}

#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__

u8 letoh(u8 x) {
  return x;
}

u16 letoh(u16 x) {
  return __builtin_bswap16(x);
}

u32 letoh(u32 x) {
  return __builtin_bswap32(x);
}

u64 letoh(u64 x) {
  return __builtin_bswap64(x);
}

#else
#error "Unexpected byte order"
#endif

template <typename T>
T Read(Bytes& b) {
  T res;
  if (b.size() < sizeof(res)) {
    throw std::out_of_range("Not enough bytes in buffer to read from");
  }
  assert(b.size() >= sizeof(res));
  std::memcpy(&res, b.data(), sizeof(res));
  b.remove_prefix(sizeof(res));
  return letoh(res);
}

template <typename T>
T ReadVariableLength(Bytes& b) {
  ssize_t const n = Read<u8>(b);
  if (b.size() < n) {
    throw std::out_of_range("Not enough bytes in buffer to read from");
  }

  Bytes p = b.first(n);
  b.remove_prefix(n);

  std::make_unsigned_t<T> res = 0;
  if (p.size() > sizeof(res)) {
    if (std::ranges::any_of(p.subspan(sizeof(res)),
                            [](std::byte c) { return c != std::byte(); })) {
      throw std::overflow_error("Too big");
    }

    p = p.first(sizeof(res));
  }

  for (size_t i = p.size(); i > 0;) {
    res <<= 8;
    res |= static_cast<u8>(p[--i]);
  }

  return res;
}

// Reads a 32-bit Unix timestamp. Per the Info-Zip UT/UX and PKWARE-Unix
// extra field specs, these are signed (to allow pre-1970 dates), so this
// must sign-extend rather than zero-extend into the wider time_t.
time_t ReadTime32(Bytes& b) {
  return static_cast<time_t>(static_cast<i32>(Read<u32>(b)));
}

timespec ntfs2timespec(i64 const t) {
  if (t < 0) {
    throw std::overflow_error("NTFS time stamp is negative");
  }

  i64 const offset = static_cast<i64>(369 * 365 + 89) * 24 * 3600 * 10'000'000;
  i64 const value = t - offset;

  // FILETIME (t) has no sign ambiguity - it's unsigned ticks since
  // 1601-01-01 - so a value below |offset| is a perfectly legitimate
  // pre-1970 date, not malformed data: don't reject it.
  //
  // t/% truncate toward zero, not toward -infinity, so for a negative
  // |value| that isn't an exact multiple of 10'000'000, the remainder
  // would itself come out negative. Adjust to floor division so tv_nsec
  // always ends up in [0, 999'999'999], with the sign folded entirely
  // into tv_sec, as timespec requires.
  i64 quot = value / 10'000'000;
  i64 rem = value % 10'000'000;
  if (rem < 0) {
    --quot;
    rem += 10'000'000;
  }

  if (quot > std::numeric_limits<time_t>::max() ||
      quot < std::numeric_limits<time_t>::min()) {
    throw std::overflow_error("NTFS time stamp is out of range");
  }

  return {.tv_sec = static_cast<time_t>(quot),
          .tv_nsec = static_cast<long int>(rem) * 100};
}

}  // namespace

bool Parse(FieldId const id, Bytes b, Node* const node) try {
  assert(node);

  switch (id) {
    case FieldId::UNIX_TIMESTAMP: {
      const u8 flags = Read<u8>(b);

      if (flags & 1) {
        node->mtime = ReadTime32(b);
        if (b.empty()) {
          return true;
        }
      }

      if (flags & 2) {
        node->atime = ReadTime32(b);
      }

      if (flags & 4) {
        // Info-ZIP's own spec calls this third value "creation time", not
        // POSIX ctime (inode change time), which ZIP has no way to record.
        node->btime = ReadTime32(b);
      }

      return true;
    }

    case FieldId::INFOZIP_UNIX_1:
      node->atime = ReadTime32(b);
      node->mtime = ReadTime32(b);
      [[fallthrough]];

    case FieldId::INFOZIP_UNIX_2:
      if (b.empty()) {
        return true;
      }

      node->uid = Read<u16>(b);
      node->gid = Read<u16>(b);
      return true;

    case FieldId::INFOZIP_UNIX_3:
      // Check version
      if (Read<u8>(b) != 1) {
        return false;
      }

      node->uid = ReadVariableLength<uid_t>(b);
      node->gid = ReadVariableLength<gid_t>(b);
      return true;

    case FieldId::PKWARE_UNIX:
      node->atime = ReadTime32(b);
      node->mtime = ReadTime32(b);
      node->uid = Read<u16>(b);
      node->gid = Read<u16>(b);

      // variable data field
      if (S_ISBLK(node->mode) || S_ISCHR(node->mode)) {
        unsigned int const maj = Read<u32>(b);
        unsigned int const min = Read<u32>(b);
        node->dev = makedev(maj, min);
      } else {
        node->target.assign(reinterpret_cast<const char*>(b.data()), b.size());
      }

      return true;

    case FieldId::NTFS_TIMESTAMP: {
      Read<u32>(b);  // skip 'Reserved' field

      bool has_times = false;
      while (!b.empty()) {
        u16 const tag = Read<u16>(b);
        u16 const size = Read<u16>(b);
        if (b.size() < size) {
          return false;
        }

        if (tag == 0x0001) {
          // A component of 0 means "not set" and doesn't convert to a valid
          // NTFS FILETIME (which is relative to 1601-01-01). Skip it rather
          // than letting the whole field fail to parse because of it.
          Bytes p = b.first(size);
          if (u64 const v = Read<u64>(p)) {
            node->mtime = ntfs2timespec(v);
          }
          if (u64 const v = Read<u64>(p)) {
            node->atime = ntfs2timespec(v);
          }
          if (u64 const v = Read<u64>(p)) {
            // The APPNOTE spec labels this third value "Ctime", but it's a
            // creation/birth time, not the POSIX inode change-time ctime.
            node->btime = ntfs2timespec(v);
          }
          has_times = true;
        }

        b.remove_prefix(size);
      }

      return has_times;
    }

    default:
      return false;
  }
} catch (...) {
  return false;
}
