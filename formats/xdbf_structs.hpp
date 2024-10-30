/**
 ******************************************************************************
 * Xenia : Xbox 360 Emulator Research Project                                 *
 ******************************************************************************
 * Copyright 2016 Ben Vanik. All rights reserved.                             *
 * Released under the BSD license - see LICENSE in the root for more details. *
 ******************************************************************************
 */

#ifndef XENIA_KERNEL_XAM_XDBF_XDBF_XBOX_H_
#define XENIA_KERNEL_XAM_XDBF_XDBF_XBOX_H_

namespace xe {
namespace kernel {
namespace xam {
namespace xdbf {

/* Native XDBF structs used by 360 are in this file */

struct XdbfStringTableEntry {
  xe::be<uint16_t> id;
  xe::be<uint16_t> string_length;
};
//static_assert_size(XdbfStringTableEntry, 4);

#pragma pack(push, 1)
struct X_XDBF_HEADER {
  xe::be<uint32_t> magic;
  xe::be<uint32_t> version;
  xe::be<uint32_t> entry_count;
  xe::be<uint32_t> entry_used;
  xe::be<uint32_t> free_count;
  xe::be<uint32_t> free_used;
};
//static_assert_size(X_XDBF_HEADER, 24);

struct X_XDBF_ENTRY {
  xe::be<uint16_t> section;
  xe::be<uint64_t> id;
  xe::be<uint32_t> offset;
  xe::be<uint32_t> size;
};
//static_assert_size(X_XDBF_ENTRY, 18);

struct X_XDBF_FILELOC {
  xe::be<uint32_t> offset;
  xe::be<uint32_t> size;
};
//static_assert_size(X_XDBF_FILELOC, 8);

struct X_XDBF_SECTION_HEADER {
  xe::be<uint32_t> magic;
  xe::be<uint32_t> version;
  xe::be<uint32_t> size;
};
//static_assert_size(X_XDBF_SECTION_HEADER, 12);

struct X_XDBF_XSTC_DATA {
  X_XDBF_SECTION_HEADER header;
  xe::be<uint32_t> default_language;
};
//static_assert_size(X_XDBF_XSTC_DATA, 16);

struct X_XDBF_XTHD_DATA {
  enum TitleType : uint32_t {
    kSystem = 0,
    kFull = 1,
    kDemo = 2,
    kDownload = 3,
  };
  enum class Flags {
    kAlwaysIncludeInProfile = 1,
    kNeverIncludeInProfile = 2,
  };
  X_XDBF_SECTION_HEADER header;
  xe::be<uint32_t> title_id;
  xe::be<TitleType> title_type;
  xe::be<uint16_t> title_version_major;
  xe::be<uint16_t> title_version_minor;
  xe::be<uint16_t> title_version_build;
  xe::be<uint16_t> title_version_revision;
  xe::be<uint32_t> flags;
  xe::be<uint32_t> unk20;
  xe::be<uint32_t> unk24;
  xe::be<uint32_t> unk28;
};
//static_assert_size(X_XDBF_XTHD_DATA, 0x2C);

struct X_XDBF_TABLE_HEADER {
  X_XDBF_SECTION_HEADER header;
  xe::be<uint16_t> count;
};
//static_assert_size(X_XDBF_TABLE_HEADER, 14);

struct X_XDBF_SPA_ACHIEVEMENT {
  xe::be<uint16_t> id;
  xe::be<uint16_t> label_id;
  xe::be<uint16_t> description_id;
  xe::be<uint16_t> unachieved_id;
  xe::be<uint32_t> image_id;
  xe::be<uint16_t> gamerscore;
  xe::be<uint16_t> unkE;
  xe::be<uint32_t> flags;
  xe::be<uint32_t> unk14;
  xe::be<uint32_t> unk18;
  xe::be<uint32_t> unk1C;
  xe::be<uint32_t> unk20;
};
//static_assert_size(X_XDBF_SPA_ACHIEVEMENT, 0x24);

struct X_XDBF_GPD_ACHIEVEMENT {
  xe::be<uint32_t> magic;
  xe::be<uint32_t> id;
  xe::be<uint32_t> image_id;
  xe::be<uint32_t> gamerscore;
  xe::be<uint32_t> flags;
  xe::be<uint64_t> unlock_time;
  // wchar_t* title;
  // wchar_t* description;
  // wchar_t* unlocked_description;
};
//static_assert_size(X_XDBF_GPD_ACHIEVEMENT, 0x1C);

struct X_XDBF_AVATARAWARDS_COUNTER {
  uint8_t earned;
  uint8_t possible;
};
//static_assert_size(X_XDBF_AVATARAWARDS_COUNTER, 2);

// from https://github.com/xemio/testdev/blob/master/xkelib/xam/_xamext.h
struct X_XDBF_GPD_TITLEPLAYED {
  xe::be<uint32_t> title_id;
  xe::be<uint32_t> achievements_possible;
  xe::be<uint32_t> achievements_earned;
  xe::be<uint32_t> gamerscore_total;
  xe::be<uint32_t> gamerscore_earned;
  xe::be<uint16_t> reserved_achievement_count;

  X_XDBF_AVATARAWARDS_COUNTER all_avatar_awards;
  X_XDBF_AVATARAWARDS_COUNTER male_avatar_awards;
  X_XDBF_AVATARAWARDS_COUNTER female_avatar_awards;
  xe::be<uint32_t> reserved_flags;
  xe::be<uint64_t> last_played;

  // xe::be<wchar_t> title_name[64]; // size seems to be variable inside GPDs,
  // r/w this seperately
};
//static_assert_size(X_XDBF_GPD_TITLEPLAYED, 0x28);
#pragma pack(pop)

enum class X_XUSER_DATA_TYPE : uint8_t {
  kContext,
  kInt32,
  kInt64,
  kDouble,
  kUnicode,
  kFloat,
  kBinary,
  kDateTime,
  kNull = 0xFF
};

struct X_XUSER_DATA {
  X_XUSER_DATA() {}
  X_XUSER_DATA(const X_XUSER_DATA& data) {
    type = data.type;
    i64Data = data.i64Data;
  }

  X_XUSER_DATA_TYPE type;
  // 7 bytes padding
  union {
    xe::be<uint32_t> nData;    // X_XUSER_DATA_TYPE::kInt32
    xe::be<uint64_t> i64Data;  // X_XUSER_DATA_TYPE::kInt64
    xe::be<double> dblData;    // X_XUSER_DATA_TYPE::kDouble
    struct                     // X_XUSER_DATA_TYPE::kUnicode
    {
      xe::be<uint32_t> cbData;  // Includes null-terminator
      xe::be<uint32_t> pwszData;
    } string;
    xe::be<float> fData;  // X_XUSER_DATA_TYPE::kFloat
    struct                // X_XUSER_DATA_TYPE::kBinary
    {
      xe::be<uint32_t> cbData;
      xe::be<uint32_t> pbData;
    } binary;
    xe::be<uint64_t> ftData;  // X_XUSER_DATA_TYPE::kDateTime
  };
};
//static_assert_size(X_XUSER_DATA, 0x10);

// Create 32-bit ID from type/size/id combination
#define XPROFILEID(type, size, id) \
  ((((uint32_t)type & 0xF) << 28) | ((size & 0xFFF) << 16) | (id & 0x3FFF))

// Extract type from 32-bit ID
#define XPROFILEID_TYPE(id) ((X_XUSER_DATA_TYPE)(((uint32_t)id >> 28) & 0xF))

// Extract size from 32-bit ID
#define XPROFILEID_SIZE(id) (((uint32_t)id >> 16) & 0xFFF)

enum X_XDBF_SETTING_ID : uint32_t {
  XPROFILE_PERMISSIONS = XPROFILEID(X_XUSER_DATA_TYPE::kInt32, sizeof(uint32_t),
                                    0),  // 0x10040000,
  XPROFILE_GAMER_TYPE = XPROFILEID(X_XUSER_DATA_TYPE::kInt32, sizeof(uint32_t),
                                   1),  // 0x10040001,
  XPROFILE_GAMER_YAXIS_INVERSION = XPROFILEID(
      X_XUSER_DATA_TYPE::kInt32, sizeof(uint32_t), 2),  // 0x10040002,
  XPROFILE_OPTION_CONTROLLER_VIBRATION = XPROFILEID(
      X_XUSER_DATA_TYPE::kInt32, sizeof(uint32_t), 3),  // 0x10040003,
  XPROFILE_TITLE_SPECIFIC1 =
      XPROFILEID(X_XUSER_DATA_TYPE::kBinary, 0x3E8, 0x3FFF),  // 0x63E83FFF,
  XPROFILE_TITLE_SPECIFIC2 =
      XPROFILEID(X_XUSER_DATA_TYPE::kBinary, 0x3E8, 0x3FFE),  // 0x63E83FFE,
  XPROFILE_TITLE_SPECIFIC3 =
      XPROFILEID(X_XUSER_DATA_TYPE::kBinary, 0x3E8, 0x3FFD),  // 0x63E83FFD,
  XPROFILE_GAMERCARD_ZONE = XPROFILEID(X_XUSER_DATA_TYPE::kInt32,
                                       sizeof(uint32_t), 4),  // 0x10040004,
  XPROFILE_GAMERCARD_REGION = XPROFILEID(X_XUSER_DATA_TYPE::kInt32,
                                         sizeof(uint32_t), 5),  // 0x10040005,
  XPROFILE_GAMERCARD_CRED = XPROFILEID(X_XUSER_DATA_TYPE::kInt32,
                                       sizeof(uint32_t), 6),  // 0x10040006,
  XPROFILE_GAMER_PRESENCE_USER_STATE = XPROFILEID(
      X_XUSER_DATA_TYPE::kInt32, sizeof(uint32_t), 7),  // 0x10040007,
  XPROFILE_GAMERCARD_HAS_VISION = XPROFILEID(
      X_XUSER_DATA_TYPE::kInt32, sizeof(uint32_t), 8),  // 0x10040008,
  XPROFILE_GAMERCARD_REP =
      XPROFILEID(X_XUSER_DATA_TYPE::kFloat, sizeof(float), 0xB),  // 0x5004000B,
  XPROFILE_OPTION_VOICE_MUTED = XPROFILEID(
      X_XUSER_DATA_TYPE::kInt32, sizeof(uint32_t), 0xC),  // 0x1004000C,
  XPROFILE_OPTION_VOICE_THRU_SPEAKERS = XPROFILEID(
      X_XUSER_DATA_TYPE::kInt32, sizeof(uint32_t), 0xD),  // 0x1004000D,
  XPROFILE_OPTION_VOICE_VOLUME = XPROFILEID(
      X_XUSER_DATA_TYPE::kInt32, sizeof(uint32_t), 0xE),  // 0x1004000E,
  XPROFILE_GAMERCARD_PICTURE_KEY =
      XPROFILEID(X_XUSER_DATA_TYPE::kUnicode, 0x64, 0xF),  // 0x4064000F,
  XPROFILE_GAMERCARD_PERSONAL_PICTURE =
      XPROFILEID(X_XUSER_DATA_TYPE::kUnicode, 0x64, 0x10),  // 0x40640010,
  XPROFILE_GAMERCARD_MOTTO =
      XPROFILEID(X_XUSER_DATA_TYPE::kUnicode, 0x2C, 0x11),  // 0x402C0011,
  XPROFILE_GAMERCARD_TITLES_PLAYED = XPROFILEID(
      X_XUSER_DATA_TYPE::kInt32, sizeof(uint32_t), 0x12),  // 0x10040012,
  XPROFILE_GAMERCARD_ACHIEVEMENTS_EARNED = XPROFILEID(
      X_XUSER_DATA_TYPE::kInt32, sizeof(uint32_t), 0x13),  // 0x10040013,
  XPROFILE_GAMER_DIFFICULTY = XPROFILEID(
      X_XUSER_DATA_TYPE::kInt32, sizeof(uint32_t), 0x15),  // 0x10040015,
  XPROFILE_GAMER_CONTROL_SENSITIVITY = XPROFILEID(
      X_XUSER_DATA_TYPE::kInt32, sizeof(uint32_t), 0x18),  // 0x10040018,
  XPROFILE_GAMER_PREFERRED_COLOR_FIRST = XPROFILEID(
      X_XUSER_DATA_TYPE::kInt32, sizeof(uint32_t), 0x1D),  // 0x1004001D,
  XPROFILE_GAMER_PREFERRED_COLOR_SECOND = XPROFILEID(
      X_XUSER_DATA_TYPE::kInt32, sizeof(uint32_t), 0x1E),  // 0x1004001E,
  XPROFILE_GAMER_ACTION_AUTO_AIM = XPROFILEID(
      X_XUSER_DATA_TYPE::kInt32, sizeof(uint32_t), 0x22),  // 0x10040022,
  XPROFILE_GAMER_ACTION_AUTO_CENTER = XPROFILEID(
      X_XUSER_DATA_TYPE::kInt32, sizeof(uint32_t), 0x23),  // 0x10040023,
  XPROFILE_GAMER_ACTION_MOVEMENT_CONTROL = XPROFILEID(
      X_XUSER_DATA_TYPE::kInt32, sizeof(uint32_t), 0x24),  // 0x10040024,
  XPROFILE_GAMER_RACE_TRANSMISSION = XPROFILEID(
      X_XUSER_DATA_TYPE::kInt32, sizeof(uint32_t), 0x26),  // 0x10040026,
  XPROFILE_GAMER_RACE_CAMERA_LOCATION = XPROFILEID(
      X_XUSER_DATA_TYPE::kInt32, sizeof(uint32_t), 0x27),  // 0x10040027,
  XPROFILE_GAMER_RACE_BRAKE_CONTROL = XPROFILEID(
      X_XUSER_DATA_TYPE::kInt32, sizeof(uint32_t), 0x28),  // 0x10040028,
  XPROFILE_GAMER_RACE_ACCELERATOR_CONTROL = XPROFILEID(
      X_XUSER_DATA_TYPE::kInt32, sizeof(uint32_t), 0x29),  // 0x10040029,
  XPROFILE_GAMERCARD_TITLE_CRED_EARNED = XPROFILEID(
      X_XUSER_DATA_TYPE::kInt32, sizeof(uint32_t), 0x38),  // 0x10040038,
  XPROFILE_GAMERCARD_TITLE_ACHIEVEMENTS_EARNED = XPROFILEID(
      X_XUSER_DATA_TYPE::kInt32, sizeof(uint32_t), 0x39),  // 0x10040039,
  XPROFILE_GAMER_TIER = XPROFILEID(X_XUSER_DATA_TYPE::kInt32, sizeof(uint32_t),
                                   0x3A),  // 0x1004003A,
  XPROFILE_MESSENGER_SIGNUP_STATE = XPROFILEID(
      X_XUSER_DATA_TYPE::kInt32, sizeof(uint32_t), 0x3B),  // 0x1004003B,
  XPROFILE_MESSENGER_AUTO_SIGNIN = XPROFILEID(
      X_XUSER_DATA_TYPE::kInt32, sizeof(uint32_t), 0x3C),  // 0x1004003C,
  XPROFILE_SAVE_WINDOWS_LIVE_PASSWORD = XPROFILEID(
      X_XUSER_DATA_TYPE::kInt32, sizeof(uint32_t), 0x3D),  // 0x1004003D,
  XPROFILE_FRIENDSAPP_SHOW_BUDDIES = XPROFILEID(
      X_XUSER_DATA_TYPE::kInt32, sizeof(uint32_t), 0x3E),  // 0x1004003E,
  XPROFILE_GAMERCARD_SERVICE_TYPE_FLAGS = XPROFILEID(
      X_XUSER_DATA_TYPE::kInt32, sizeof(uint32_t), 0x3F),  // 0x1004003F,
  XPROFILE_GAMERCARD_USER_NAME =
      XPROFILEID(X_XUSER_DATA_TYPE::kUnicode, 0x104, 0x40),  // 0x41040040,
  XPROFILE_GAMERCARD_USER_LOCATION =
      XPROFILEID(X_XUSER_DATA_TYPE::kUnicode, 0x52, 0x41),  // 0x40520041,
  XPROFILE_GAMERCARD_USER_URL =
      XPROFILEID(X_XUSER_DATA_TYPE::kUnicode, 0x190, 0x42),  // 0x41900042,
  XPROFILE_GAMERCARD_USER_BIO =
      XPROFILEID(X_XUSER_DATA_TYPE::kUnicode, 0x3E8, 0x43),  // 0x43E80043,
  XPROFILE_GAMERCARD_AVATAR_INFO_1 =
      XPROFILEID(X_XUSER_DATA_TYPE::kBinary, 0x3E8, 0x44),  // 0x63E80044,
  XPROFILE_GAMERCARD_AVATAR_INFO_2 =
      XPROFILEID(X_XUSER_DATA_TYPE::kBinary, 0x3E8, 0x45),  // 0x63E80045,
  XPROFILE_GAMERCARD_PARTY_INFO =
      XPROFILEID(X_XUSER_DATA_TYPE::kBinary, 0x100, 0x46),  // 0x61000046,

  // IDs exclusive to GFWL, some seem to conflict with X360 IDs though,
  // commented out the conflicting IDs All are apparently local-only, and don't
  // get synced to the server
  // XPROFILE_GFWL_AUTOMIX =
  //  XPROFILEID(X_XUSER_DATA_TYPE::kInt32, sizeof(uint32_t), 0x47 ),
  //  //0x10040047,
  // XPROFILE_GFWL_MICBOOST =
  //  XPROFILEID(X_XUSER_DATA_TYPE::kInt32, sizeof(uint32_t), 0x48 ),
  //  //0x10040048,
  XPROFILE_GFWL_RECDEVICEDESC =
      XPROFILEID(X_XUSER_DATA_TYPE::kUnicode, 200, 0x49),  // 0x40C80049,
  XPROFILE_GFWL_PLAYDEVICE =
      XPROFILEID(X_XUSER_DATA_TYPE::kBinary, 0x10, 0x4A),  // 0x6010004A,
  XPROFILE_GFWL_PLAYDEVICEDESC =
      XPROFILEID(X_XUSER_DATA_TYPE::kUnicode, 200, 0x4B),  // 0x40C8004B,
  XPROFILE_GFWL_VOLUMELEVEL = XPROFILEID(X_XUSER_DATA_TYPE::kFloat,
                                         sizeof(float), 0x4C),  // 0x5004004C,
  XPROFILE_GFWL_RECLEVEL = XPROFILEID(X_XUSER_DATA_TYPE::kFloat, sizeof(float),
                                      0x4D),  // 0x5004004D,
  // XPROFILE_GFWL_VADHIGH =
  //  XPROFILEID(X_XUSER_DATA_TYPE::kInt32, sizeof(uint32_t), 0x4E ),
  //  //0x1004004E,
  XPROFILE_GFWL_VADNORMAL = XPROFILEID(X_XUSER_DATA_TYPE::kInt32,
                                       sizeof(uint32_t), 0x4F),  // 0x1004004F,

  XPROFILE_TENURE_LEVEL = XPROFILEID(X_XUSER_DATA_TYPE::kInt32,
                                     sizeof(uint32_t), 0x47),  // 0x10040047,
  XPROFILE_TENURE_MILESTONE = XPROFILEID(
      X_XUSER_DATA_TYPE::kInt32, sizeof(uint32_t), 0x48),  // 0x10040048,
  XPROFILE_TENURE_NEXT_MILESTONE_DATE =
      XPROFILEID(X_XUSER_DATA_TYPE::kDateTime, sizeof(uint64_t),
                 0x49),  // 0x70080049, aka ProfileDateTimeCreated?
  XPROFILE_VIDEO_METADATA =
      XPROFILEID(X_XUSER_DATA_TYPE::kBinary, 0x20, 0x4A),  // 0x6020004A,
  XPROFILE_SUBSCRIPTION_TYPE_LENGTH_IN_MONTHS = XPROFILEID(
      X_XUSER_DATA_TYPE::kInt32, sizeof(uint32_t), 0x4B),  // 0x1004004B,
  XPROFILE_SUBSCRIPTION_PAYMENT_TYPE = XPROFILEID(
      X_XUSER_DATA_TYPE::kInt32, sizeof(uint32_t), 0x4C),  // 0x1004004C,
  XPROFILE_PEC_INFO = XPROFILEID(X_XUSER_DATA_TYPE::kInt32, sizeof(uint32_t),
                                 0x4D),  // 0x1004004D,
  XPROFILE_NUI_BIOMETRIC_SIGNIN =
      XPROFILEID(X_XUSER_DATA_TYPE::kInt32, sizeof(uint32_t),
                 0x4E),  // 0x1004004E, set by XamUserNuiEnableBiometric

  // 2 unknowns requested by NXE dash
  XPROFILE_LAST_LIVE_SIGNIN =
      XPROFILEID(X_XUSER_DATA_TYPE::kDateTime, sizeof(uint64_t),
                 0x4F),  // 0x7008004F, named "LastOnLIVE" in Velocity
  XPROFILE_UNK_61180050 =
      XPROFILEID(X_XUSER_DATA_TYPE::kBinary, 280, 0x50),  // 0x61180050,

  XPROFILE_JUMP_IN_LIST =
      XPROFILEID(X_XUSER_DATA_TYPE::kBinary, 0x3E8, 0x51),  // 0x63E80051,
  XPROFILE_BEACONS_SOCIAL_NETWORK_SHARING = XPROFILEID(
      X_XUSER_DATA_TYPE::kInt32, sizeof(uint32_t), 0x52),  // 0x10040052,
  XPROFILE_USER_PREFERENCES = XPROFILEID(
      X_XUSER_DATA_TYPE::kInt32, sizeof(uint32_t), 0x53),  // 0x10040053,
  XPROFILE_GAMERCARD_PARTY_ADDR =
      XPROFILEID(X_XUSER_DATA_TYPE::kBinary, 0x62, 0x54),  // 0x60620054,

  XPROFILE_XBOXONE_GAMERSCORE =
      XPROFILEID(X_XUSER_DATA_TYPE::kInt32, sizeof(uint32_t),
                 0x57),  // 0x10040057, "XboxOneGamerscore" inside dash.xex

  WEB_EMAIL_FORMAT = XPROFILEID(X_XUSER_DATA_TYPE::kInt32, sizeof(uint32_t),
                                0x2000),  // 0x10042000,
  WEB_FLAGS = XPROFILEID(X_XUSER_DATA_TYPE::kInt32, sizeof(uint32_t),
                         0x2001),  // 0x10042001,
  WEB_SPAM = XPROFILEID(X_XUSER_DATA_TYPE::kInt32, sizeof(uint32_t),
                        0x2002),  // 0x10042002,
  WEB_FAVORITE_GENRE = XPROFILEID(X_XUSER_DATA_TYPE::kInt32, sizeof(uint32_t),
                                  0x2003),  // 0x10042003,
  WEB_FAVORITE_GAME = XPROFILEID(X_XUSER_DATA_TYPE::kInt32, sizeof(uint32_t),
                                 0x2004),  // 0x10042004,
  WEB_FAVORITE_GAME1 = XPROFILEID(X_XUSER_DATA_TYPE::kInt32, sizeof(uint32_t),
                                  0x2005),  // 0x10042005,
  WEB_FAVORITE_GAME2 = XPROFILEID(X_XUSER_DATA_TYPE::kInt32, sizeof(uint32_t),
                                  0x2006),  // 0x10042006,
  WEB_FAVORITE_GAME3 = XPROFILEID(X_XUSER_DATA_TYPE::kInt32, sizeof(uint32_t),
                                  0x2007),  // 0x10042007,
  WEB_FAVORITE_GAME4 = XPROFILEID(X_XUSER_DATA_TYPE::kInt32, sizeof(uint32_t),
                                  0x2008),  // 0x10042008,
  WEB_FAVORITE_GAME5 = XPROFILEID(X_XUSER_DATA_TYPE::kInt32, sizeof(uint32_t),
                                  0x2009),  // 0x10042009,
  WEB_PLATFORMS_OWNED = XPROFILEID(X_XUSER_DATA_TYPE::kInt32, sizeof(uint32_t),
                                   0x200A),  // 0x1004200A,
  WEB_CONNECTION_SPEED = XPROFILEID(X_XUSER_DATA_TYPE::kInt32, sizeof(uint32_t),
                                    0x200B),  // 0x1004200B,
  WEB_FLASH = XPROFILEID(X_XUSER_DATA_TYPE::kInt32, sizeof(uint32_t),
                         0x200C),  // 0x1004200C,
  WEB_VIDEO_PREFERENCE = XPROFILEID(X_XUSER_DATA_TYPE::kInt32, sizeof(uint32_t),
                                    0x200D),  // 0x1004200D,

  XPROFILE_CRUX_MEDIA_PICTURE =
      XPROFILEID(X_XUSER_DATA_TYPE::kUnicode, 0x64, 0x3E8),  // 0x406403E8,
  XPROFILE_CRUX_MEDIA_STYLE1 = XPROFILEID(
      X_XUSER_DATA_TYPE::kInt32, sizeof(uint32_t), 0x3EA),  // 0x100403EA,
  XPROFILE_CRUX_MEDIA_STYLE2 = XPROFILEID(
      X_XUSER_DATA_TYPE::kInt32, sizeof(uint32_t), 0x3EB),  // 0x100403EB,
  XPROFILE_CRUX_MEDIA_STYLE3 = XPROFILEID(
      X_XUSER_DATA_TYPE::kInt32, sizeof(uint32_t), 0x3EC),  // 0x100403EC,
  XPROFILE_CRUX_TOP_ALBUM1 = XPROFILEID(
      X_XUSER_DATA_TYPE::kInt32, sizeof(uint32_t), 0x3ED),  // 0x100403ED,
  XPROFILE_CRUX_TOP_ALBUM2 = XPROFILEID(
      X_XUSER_DATA_TYPE::kInt32, sizeof(uint32_t), 0x3EE),  // 0x100403EE,
  XPROFILE_CRUX_TOP_ALBUM3 = XPROFILEID(
      X_XUSER_DATA_TYPE::kInt32, sizeof(uint32_t), 0x3EF),  // 0x100403EF,
  XPROFILE_CRUX_TOP_ALBUM4 = XPROFILEID(
      X_XUSER_DATA_TYPE::kInt32, sizeof(uint32_t), 0x3F0),  // 0x100403F0,
  XPROFILE_CRUX_TOP_ALBUM5 = XPROFILEID(
      X_XUSER_DATA_TYPE::kInt32, sizeof(uint32_t), 0x3F1),  // 0x100403F1,
  XPROFILE_CRUX_OFFLINE_ID =
      XPROFILEID(X_XUSER_DATA_TYPE::kBinary, 0x34, 0x3F2),  // 0x603403F2,
  XPROFILE_CRUX_BKGD_IMAGE = XPROFILEID(
      X_XUSER_DATA_TYPE::kInt32, sizeof(uint32_t), 0x3F3),  // 0x100403F3,
  XPROFILE_CRUX_LAST_CHANGE_TIME = XPROFILEID(
      X_XUSER_DATA_TYPE::kDateTime, sizeof(uint64_t), 0x3F4),  // 0x700803F4,
  XPROFILE_CRUX_TOP_MUSIC =
      XPROFILEID(X_XUSER_DATA_TYPE::kBinary, 0xA8, 0x3F5),  // 0x60A803F5,
  XPROFILE_CRUX_MEDIA_MOTTO =
      XPROFILEID(X_XUSER_DATA_TYPE::kUnicode, 0x100, 0x3F6),  // 0x410003F6,
  XPROFILE_CRUX_TOP_MEDIAID1 =
      XPROFILEID(X_XUSER_DATA_TYPE::kBinary, 0x10, 0x3F7),  // 0x601003F7,
  XPROFILE_CRUX_TOP_MEDIAID2 =
      XPROFILEID(X_XUSER_DATA_TYPE::kBinary, 0x10, 0x3F8),  // 0x601003F8,
  XPROFILE_CRUX_TOP_MEDIAID3 =
      XPROFILEID(X_XUSER_DATA_TYPE::kBinary, 0x10, 0x3F9),  // 0x601003F9,
  XPROFILE_CRUX_BIO =
      XPROFILEID(X_XUSER_DATA_TYPE::kUnicode, 0x3E8, 0x3FA),  // 0x43E803FA,
  XPROFILE_CRUX_BG_SMALL_PRIVATE =
      XPROFILEID(X_XUSER_DATA_TYPE::kUnicode, 0x64, 0x3FB),  // 0x406403FB,
  XPROFILE_CRUX_BG_LARGE_PRIVATE =
      XPROFILEID(X_XUSER_DATA_TYPE::kUnicode, 0x64, 0x3FC),  // 0x406403FC,
  XPROFILE_CRUX_BG_SMALL_PUBLIC =
      XPROFILEID(X_XUSER_DATA_TYPE::kUnicode, 0x64, 0x3FD),  // 0x406403FD,
  XPROFILE_CRUX_BG_LARGE_PUBLIC =
      XPROFILEID(X_XUSER_DATA_TYPE::kUnicode, 0x64, 0x3FE),  // 0x406403FE
};

struct X_XDBF_GPD_SETTING {
  xe::be<X_XDBF_SETTING_ID> setting_id;
  // 4 bytes padding
  X_XUSER_DATA value;
  // usually followed by value.binary.cbData / value.string.pwszData bytes
};
//static_assert_size(X_XDBF_GPD_SETTING, 0x18);

// Found by dumping the kSectionStringTable sections of various games:
enum class XLanguage : uint32_t {
  kInvalid,
  kEnglish,
  kJapanese,
  kGerman,
  kFrench,
  kSpanish,
  kItalian,
  kKorean,
  kTChinese,
  kPortuguese,
  kUnknown10,  // unused?
  kPolish,
  kRussian,
  kMaxLanguages  // STFS headers can't support any more languages than these?
};

}  // namespace xdbf
}  // namespace xam
}  // namespace kernel
}  // namespace xe

#endif  // XENIA_KERNEL_XAM_XDBF_XDBF_XBOX_H_
