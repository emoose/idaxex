/**
 ******************************************************************************
 * Xenia : Xbox 360 Emulator Research Project                                 *
 ******************************************************************************
 * Copyright 2016 Ben Vanik. All rights reserved.                             *
 * Released under the BSD license - see LICENSE in the root for more details. *
 ******************************************************************************
 */

#ifndef XENIA_KERNEL_XAM_XDBF_XDBF_H_
#define XENIA_KERNEL_XAM_XDBF_XDBF_H_

#include <string>
#include <vector>

#include "xdbf_xbox.hpp"

namespace xe {
namespace kernel {
namespace xam {
namespace xdbf {

// https://github.com/oukiar/freestyledash/blob/master/Freestyle/Tools/XEX/SPA.h
// https://github.com/oukiar/freestyledash/blob/master/Freestyle/Tools/XEX/SPA.cpp

constexpr uint32_t kXdbfMagicXdbf = 0x46424458; // XDBF

enum class SpaID : uint64_t {
  Xach = 0x48434158, // XACH
  Xstr = 0x52545358, // XSTR
  Xstc = 0x43545358, // XSTC
  Xthd = 0x44485458, // XTHD
  Title = 0x8000,
};

enum class SpaSection : uint16_t {
  kMetadata = 0x1,
  kImage = 0x2,
  kStringTable = 0x3,
};

enum class GpdSection : uint16_t {
  kAchievement = 0x1,
  kImage = 0x2,
  kSetting = 0x3,
  kTitle = 0x4,
  kString = 0x5,
  kProtectedAchievement = 0x6,  // GFWL only
};

inline std::wstring ReadNullTermString(const wchar_t* ptr) {
  std::wstring retval;
  wchar_t data = xe::byte_swap(*ptr);
  while (data != 0) {
    retval += data;
    ptr++;
    data = xe::byte_swap(*ptr);
  }
  return retval;
}

struct TitlePlayed {
  uint32_t title_id = 0;
  std::wstring title_name;
  uint32_t achievements_possible = 0;
  uint32_t achievements_earned = 0;
  uint32_t gamerscore_total = 0;
  uint32_t gamerscore_earned = 0;
  uint16_t reserved_achievement_count = 0;
  X_XDBF_AVATARAWARDS_COUNTER all_avatar_awards = {};
  X_XDBF_AVATARAWARDS_COUNTER male_avatar_awards = {};
  X_XDBF_AVATARAWARDS_COUNTER female_avatar_awards = {};
  uint32_t reserved_flags = 0;
  uint64_t last_played = 0;
};

enum class AchievementType : uint32_t {
  kCompletion = 1,
  kLeveling = 2,
  kUnlock = 3,
  kEvent = 4,
  kTournament = 5,
  kCheckpoint = 6,
  kOther = 7,
};

enum class AchievementPlatform : uint32_t {
  kX360 = 0x100000,
  kPC = 0x200000,
  kMobile = 0x300000,
  kWebGames = 0x400000,
};

enum class AchievementFlags : uint32_t {
  kTypeMask = 0x7,
  kShowUnachieved = 0x8,
  kAchievedOnline = 0x10000,
  kAchieved = 0x20000,
  kNotAchievable = 0x40000,
  kWasNotAchievable = 0x80000,
  kPlatformMask = 0x700000,
  kColorizable = 0x1000000,  // avatar awards only?
};

struct Achievement {
  uint16_t id = 0;
  std::string label;
  std::string description;
  std::string unachieved_desc;
  uint32_t image_id = 0;
  uint32_t gamerscore = 0;
  uint32_t flags = 0;
  uint64_t unlock_time = 0;

  AchievementType GetType() {
    return static_cast<AchievementType>(
        flags & static_cast<uint32_t>(AchievementFlags::kTypeMask));
  }

  AchievementPlatform GetPlatform() {
    return static_cast<AchievementPlatform>(
        flags & static_cast<uint32_t>(AchievementFlags::kPlatformMask));
  }

  bool IsUnlockable() {
    return !(flags & static_cast<uint32_t>(AchievementFlags::kNotAchievable)) ||
           (flags & static_cast<uint32_t>(AchievementFlags::kWasNotAchievable));
  }

  bool IsUnlocked() {
    return flags & static_cast<uint32_t>(AchievementFlags::kAchieved);
  }

  bool IsUnlockedOnline() {
    return flags & static_cast<uint32_t>(AchievementFlags::kAchievedOnline);
  }

  void Unlock(bool online = false) {
    if (!IsUnlockable()) {
      return;
    }

    flags |= static_cast<uint32_t>(AchievementFlags::kAchieved);
    if (online) {
      flags |= static_cast<uint32_t>(AchievementFlags::kAchievedOnline);
    }
  }

  void Lock() {
    flags = flags & ~(static_cast<uint32_t>(AchievementFlags::kAchieved));
    flags = flags & ~(static_cast<uint32_t>(AchievementFlags::kAchievedOnline));
    unlock_time = 0;
  }
};

struct Entry {
  X_XDBF_ENTRY info;
  std::vector<uint8_t> data;
};

// Parses/creates an XDBF (XboxDataBaseFormat) file
// http://www.free60.org/wiki/XDBF
class XdbfFile {
 public:
  XdbfFile() {
    header_.magic = kXdbfMagicXdbf;
    header_.version = 1;
  }

  bool Read(const uint8_t* data, size_t data_size);
  bool Write(uint8_t* data, size_t* data_size);

  Entry* GetEntry(uint16_t section, uint64_t id) const;

  // Updates (or adds) an entry
  bool UpdateEntry(const Entry& entry);

 protected:
  X_XDBF_HEADER header_;
  std::vector<Entry> entries_;
  std::vector<X_XDBF_FILELOC> free_entries_;
};

class SpaFile : public XdbfFile {
 public:
  std::string GetStringTableEntry(XLanguage lang, uint16_t string_id) const;

  uint32_t GetAchievements(XLanguage lang,
                           std::vector<Achievement>* achievements) const;

  Entry* GetIcon() const;
  XLanguage GetDefaultLanguage() const;
  std::string GetTitleName() const;
  bool GetTitleData(X_XDBF_XTHD_DATA* title_data) const;
};

}  // namespace xdbf
}  // namespace xam
}  // namespace kernel
}  // namespace xe

#endif  // XENIA_KERNEL_XAM_XDBF_XDBF_H_
