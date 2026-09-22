// Copyright 2021 Google LLC
// Copyright 2014-2021 Alexander Galanin <al@galanin.nnov.ru>
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

#include <gtest/gtest.h>

#include <sys/stat.h>
#ifdef __APPLE__
#include <sys/types.h>
#else
#include <sys/sysmacros.h>
#endif

#include <cstdint>

namespace {

using u8 = std::uint8_t;

// LOCAL extra field with both mtime and atime present in flags
TEST(ExtraFieldTest, TimestampMtimeAtimePresentLocal) {
  const u8 data[] = {1 | 2, 0xD4, 0x6F, 0xCE, 0x51, 0x72, 0xE3, 0xC7, 0x52};
  ExtraFields f;
  EXPECT_TRUE(f.Parse(FieldId::UNIX_TIMESTAMP, data));
  EXPECT_EQ(f.mtime.tv_sec, 0x51CE6FD4);
  EXPECT_EQ(f.mtime.tv_nsec, 0);
  EXPECT_EQ(f.atime.tv_sec, 0x52C7E372);
  EXPECT_EQ(f.atime.tv_nsec, 0);
  EXPECT_EQ(f.ctime.tv_sec, -1);
  EXPECT_EQ(f.ctime.tv_nsec, 0);
}

// LOCAL extra field with both mtime and creation time present in flags
TEST(ExtraFieldTest, TimestampMtimeCtimePresentLocal) {
  const u8 data[] = {1 | 4, 0xD4, 0x6F, 0xCE, 0x51, 0x72, 0xE3, 0xC7, 0x52};
  ExtraFields f;
  EXPECT_TRUE(f.Parse(FieldId::UNIX_TIMESTAMP, data));
  EXPECT_EQ(f.mtime.tv_sec, 0x51CE6FD4);
  EXPECT_EQ(f.mtime.tv_nsec, 0);
  EXPECT_EQ(f.atime.tv_sec, -1);
  EXPECT_EQ(f.atime.tv_nsec, 0);
  EXPECT_EQ(f.ctime.tv_sec, 0x52C7E372);
  EXPECT_EQ(f.ctime.tv_nsec, 0);
}

// Bad timestamp
TEST(ExtraFieldTest, TimestampBad) {
  const u8 data[] = {1 | 2 | 4, 0x72, 0xE3, 0xC7, 0x52};
  ExtraFields f;
  EXPECT_TRUE(f.Parse(FieldId::UNIX_TIMESTAMP, data));
  EXPECT_EQ(f.mtime.tv_sec, 0x52C7E372);
  EXPECT_EQ(f.mtime.tv_nsec, 0);
  EXPECT_EQ(f.atime.tv_sec, -1);
  EXPECT_EQ(f.atime.tv_nsec, 0);
  EXPECT_EQ(f.ctime.tv_sec, -1);
  EXPECT_EQ(f.ctime.tv_nsec, 0);
}

// Parse PKWARE Unix Extra Field - regular file
TEST(ExtraFieldTest, UnixPkwareRegular) {
  const u8 data[] = {
      0xD4, 0x6F, 0xCE, 0x51,  // atime
      0x72, 0xE3, 0xC7, 0x52,  // mtime
      0x02, 0x01,              // UID
      0x04, 0x03               // GID
  };

  ExtraFields f(S_IFREG | 0666);
  EXPECT_TRUE(f.Parse(FieldId::PKWARE_UNIX, data));
  EXPECT_EQ(f.atime.tv_sec, 0x51CE6FD4);
  EXPECT_EQ(f.atime.tv_nsec, 0);
  EXPECT_EQ(f.mtime.tv_sec, 0x52C7E372);
  EXPECT_EQ(f.mtime.tv_nsec, 0);
  EXPECT_EQ(f.ctime.tv_sec, -1);
  EXPECT_EQ(f.ctime.tv_nsec, 0);
  EXPECT_EQ(f.uid, 0x0102);
  EXPECT_EQ(f.gid, 0x0304);
  EXPECT_EQ(f.dev, -1);
  EXPECT_TRUE(f.target.empty());
}

// Parse PKWARE Unix Extra Field - block device
TEST(ExtraFieldTest, UnixPkwareDevice) {
  const u8 data[] = {
      0xC8, 0x76, 0x45, 0x5D,  // atime
      0xC8, 0x76, 0x45, 0x5D,  // mtime
      0x00, 0x00,              // UID
      0x06, 0x00,              // GID
      0x08, 0x00, 0x00, 0x00,  // major
      0x01, 0x00, 0x00, 0x00   // minor
  };

  ExtraFields f(S_IFBLK | 0666);
  EXPECT_TRUE(f.Parse(FieldId::PKWARE_UNIX, data));
  EXPECT_EQ(f.atime.tv_sec, 0x5D4576C8);
  EXPECT_EQ(f.atime.tv_nsec, 0);
  EXPECT_EQ(f.mtime.tv_sec, 0x5D4576C8);
  EXPECT_EQ(f.mtime.tv_nsec, 0);
  EXPECT_EQ(f.ctime.tv_sec, -1);
  EXPECT_EQ(f.ctime.tv_nsec, 0);
  EXPECT_EQ(f.uid, 0x0000);
  EXPECT_EQ(f.gid, 0x0006);
  EXPECT_EQ(f.dev, makedev(8, 1));
  EXPECT_TRUE(f.target.empty());
}

// Parse PKWARE Unix Extra Field - symlink
TEST(ExtraFieldTest, UnixPkwareLink) {
  const u8 data[] = {
      0xF3, 0x73, 0x49, 0x5D,                   // atime
      0xA9, 0x7B, 0x45, 0x5D,                   // mtime
      0xE8, 0x03,                               // UID
      0xE8, 0x03,                               // GID
      0x72, 0x65, 0x67, 0x75, 0x6C, 0x61, 0x72  // link target
  };

  ExtraFields f(S_IFLNK | 0777);
  EXPECT_TRUE(f.Parse(FieldId::PKWARE_UNIX, data));
  EXPECT_EQ(f.atime.tv_sec, 0x5D4973F3);
  EXPECT_EQ(f.atime.tv_nsec, 0);
  EXPECT_EQ(f.mtime.tv_sec, 0x5D457BA9);
  EXPECT_EQ(f.mtime.tv_nsec, 0);
  EXPECT_EQ(f.ctime.tv_sec, -1);
  EXPECT_EQ(f.ctime.tv_nsec, 0);
  EXPECT_EQ(f.uid, 1000);
  EXPECT_EQ(f.gid, 1000);
  EXPECT_EQ(f.dev, -1);
  EXPECT_EQ(f.target, "regular");
}

// Parse Info-ZIP Unix Extra Field (type1)
TEST(ExtraFieldTest, UnixInfozip1) {
  // local header
  {
    const u8 data[] = {0xD4, 0x6F, 0xCE, 0x51, 0x72, 0xE3,
                       0xC7, 0x52, 0x02, 0x01, 0x04, 0x03};
    ExtraFields f;
    EXPECT_TRUE(f.Parse(FieldId::INFOZIP_UNIX_1, data));
    EXPECT_EQ(f.atime.tv_sec, 0x51CE6FD4);
    EXPECT_EQ(f.atime.tv_nsec, 0);
    EXPECT_EQ(f.mtime.tv_sec, 0x52C7E372);
    EXPECT_EQ(f.mtime.tv_nsec, 0);
    EXPECT_EQ(f.uid, 0x0102);
    EXPECT_EQ(f.gid, 0x0304);
  }

  // central header
  {
    const u8 data[] = {0x72, 0xE3, 0xC7, 0x52, 0xD4, 0x6F, 0xCE, 0x51};
    ExtraFields f;
    EXPECT_TRUE(f.Parse(FieldId::INFOZIP_UNIX_1, data));
    EXPECT_EQ(f.atime.tv_sec, 0x52C7E372);
    EXPECT_EQ(f.atime.tv_nsec, 0);
    EXPECT_EQ(f.mtime.tv_sec, 0x51CE6FD4);
    EXPECT_EQ(f.mtime.tv_nsec, 0);
    EXPECT_EQ(f.uid, -1);
    EXPECT_EQ(f.gid, -1);
  }
}

// Parse Info-ZIP Unix Extra Field (type2)
TEST(ExtraFieldTest, UnixInfozip2) {
  // local header
  {
    const u8 data[] = {0x02, 0x01, 0x04, 0x03};
    ExtraFields f;
    EXPECT_TRUE(f.Parse(FieldId::INFOZIP_UNIX_2, data));
    EXPECT_EQ(f.uid, 0x0102);
    EXPECT_EQ(f.gid, 0x0304);
  }
  // central header
  {
    const u8 data[] = {0};
    ExtraFields f;
    EXPECT_FALSE(f.Parse(FieldId::INFOZIP_UNIX_2, data));
  }
}

// Parse Info-ZIP New Unix Extra Field
TEST(ExtraFieldTest, UnixInfozipNew) {
  const u8 data1[] = {1, 1, 0x01, 1, 0xF1};
  const u8 data4[] = {1, 4, 0x04, 0x03, 0x02, 0x01, 4, 0xF8, 0xF7, 0xF6, 0xF5};
  const u8 data16_fit[] = {1,    16,   0x02, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
                           0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                           16,   0xF2, 0xF1, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                           0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
  const u8 data16_uid_overflow[] = {
      1,    16,   0x0F, 0x0E, 0x0D, 0x0C, 0x0B, 0x0A, 0x09, 0x08, 0x07, 0x06,
      0x05, 0x04, 0x03, 0x02, 0x01, 0x00, 16,   0xFF, 0xFE, 0xFD, 0xFC, 0xFB,
      0xFA, 0xF9, 0xF8, 0xF7, 0xF6, 0xF5, 0xF4, 0xF3, 0xF2, 0xF1, 0xF0};
  const u8 data16_gid_overflow[] = {
      1,    16,   0x02, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 16,   0xFF, 0xFE, 0xFD, 0xFC, 0xFB,
      0xFA, 0xF9, 0xF8, 0xF7, 0xF6, 0xF5, 0xF4, 0xF3, 0xF2, 0xF1, 0xF0};

  // 8-bit
  {
    ExtraFields f;
    EXPECT_TRUE(f.Parse(FieldId::INFOZIP_UNIX_3, data1));
    EXPECT_EQ(f.uid, 0x01);
    EXPECT_EQ(f.gid, 0xF1);
  }
  // 32-bit
  {
    ExtraFields f;
    EXPECT_TRUE(f.Parse(FieldId::INFOZIP_UNIX_3, data4));
    EXPECT_EQ(f.uid, 0x01020304);
    EXPECT_EQ(f.gid, 0xF5F6F7F8);
  }
  // 128-bit fit into uid_t and gid_t
  {
    ExtraFields f;
    EXPECT_TRUE(f.Parse(FieldId::INFOZIP_UNIX_3, data16_fit));
    EXPECT_EQ(f.uid, 0x0102);
    EXPECT_EQ(f.gid, 0xF1F2);
  }
  // 128-bit, UID doesn't fit into uid_t
  {
    ExtraFields f;
    EXPECT_FALSE(f.Parse(FieldId::INFOZIP_UNIX_3, data16_uid_overflow));
  }
  // 128-bit, GID doesn't fit into gid_t
  {
    ExtraFields f;
    EXPECT_FALSE(f.Parse(FieldId::INFOZIP_UNIX_3, data16_gid_overflow));
  }
}

// Parse NTFS Extra Field
TEST(ExtraFieldTest, NtfsExtraFieldParse) {
  const u8 data[] = {
      0x00, 0x00, 0x00, 0x00,                          // reserved
      0x01, 0x00,                                      // tag 1
      0x18, 0x00,                                      // size
      0x00, 0x80, 0x3E, 0xD5, 0xDE, 0xB1, 0x9D, 0x01,  // ctime
      0x00, 0x80, 0x3E, 0xD5, 0xDE, 0xB1, 0x9D, 0x01,  // atime
      0x00, 0x80, 0x3E, 0xD5, 0xDE, 0xB1, 0x9D, 0x01,  // btime
      0xEF, 0xDC,                                      // unknown tag
      0x03, 0x00,                                      // size
      0x01, 0x02, 0x03,                                // unhandled data
      0x01, 0x00,                                      // tag 1 (again)
      0x18, 0x00,                                      // size
      0x1B, 0xFA, 0x1F, 0x5E, 0xF3, 0x21, 0xD5, 0x01,  // ctime
      0x87, 0xCB, 0xA9, 0x32, 0x33, 0x8E, 0xC9, 0x01,  // atime
      0xFF, 0x80, 0x3E, 0xD5, 0xDE, 0xB1, 0x9D, 0x01   // btime
  };

  ExtraFields f;
  EXPECT_TRUE(f.Parse(FieldId::NTFS_TIMESTAMP, data));

  EXPECT_EQ(f.mtime.tv_sec, 1560435721);
  EXPECT_EQ(f.mtime.tv_nsec, 722114700);
  EXPECT_EQ(f.atime.tv_sec, 1234567890);
  EXPECT_EQ(f.atime.tv_nsec, 123456700);
  EXPECT_EQ(f.ctime.tv_sec, 0);
  EXPECT_EQ(f.ctime.tv_nsec, 0xFF * 100);
}

// A zero component means "not set", and should be skipped rather than
// treated as an invalid NTFS FILETIME that fails the whole field.
TEST(ExtraFieldTest, NtfsExtraFieldParseZeroAtimeCtime) {
  const u8 data[] = {
      0x00, 0x00, 0x00, 0x00,                          // reserved
      0x01, 0x00,                                      // tag 1
      0x18, 0x00,                                      // size
      0x2A, 0x46, 0xE1, 0x0C, 0x60, 0x22, 0xDA, 0x01,  // mtime
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // atime (not set)
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // ctime (not set)
  };

  ExtraFields f;
  EXPECT_TRUE(f.Parse(FieldId::NTFS_TIMESTAMP, data));

  EXPECT_EQ(f.mtime.tv_sec, 1701219888);
  EXPECT_EQ(f.mtime.tv_nsec, 914589800);
  EXPECT_EQ(f.atime.tv_sec, -1);
  EXPECT_EQ(f.atime.tv_nsec, 0);
  EXPECT_EQ(f.ctime.tv_sec, -1);
  EXPECT_EQ(f.ctime.tv_nsec, 0);
}

}  // namespace
