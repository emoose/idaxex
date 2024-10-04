/**
 ******************************************************************************
 * Xenia : Xbox 360 Emulator Research Project                                 *
 ******************************************************************************
 * Copyright 2016 Ben Vanik. All rights reserved.                             *
 * Released under the BSD license - see LICENSE in the root for more details. *
 ******************************************************************************
 */

#include <cstring>
#include "../xex.hpp"
#include "xdbf.hpp"
#include "xdbf_xbox.hpp"

namespace xe {
namespace kernel {
namespace xam {
namespace xdbf {

constexpr uint32_t kXdbfMagicXdbf = 'XDBF';

bool XdbfFile::Read(const uint8_t* data, size_t data_size) {
  if (!data || data_size <= sizeof(X_XDBF_HEADER)) {
    return false;
  }

  auto* ptr = data;
  memcpy(&header_, ptr, sizeof(X_XDBF_HEADER));
  if (header_.magic != kXdbfMagicXdbf) {
    return false;
  }

  ptr += sizeof(X_XDBF_HEADER);

  auto* free_ptr = (const X_XDBF_FILELOC*)(ptr + (sizeof(X_XDBF_ENTRY) *
                                                  header_.entry_count));
  auto* data_ptr =
      (uint8_t*)free_ptr + (sizeof(X_XDBF_FILELOC) * header_.free_count);

  for (uint32_t i = 0; i < header_.entry_used; i++) {
    Entry entry;
    memcpy(&entry.info, ptr, sizeof(X_XDBF_ENTRY));
    entry.data.resize(entry.info.size);
    memcpy(entry.data.data(), data_ptr + entry.info.offset, entry.info.size);
    entries_.push_back(entry);

    ptr += sizeof(X_XDBF_ENTRY);
  }

  for (uint32_t i = 0; i < header_.free_used; i++) {
    free_entries_.push_back(*free_ptr);
    free_ptr++;
  }

  return true;
}

bool XdbfFile::Write(uint8_t* data, size_t* data_size) {
  *data_size = 0;

  *data_size += sizeof(X_XDBF_HEADER);
  *data_size += entries_.size() * sizeof(X_XDBF_ENTRY);
  *data_size += 1 * sizeof(X_XDBF_FILELOC);

  size_t entries_size = 0;
  for (auto ent : entries_) {
    entries_size += ent.data.size();
  }

  *data_size += entries_size;

  if (!data) {
    return true;
  }

  header_.entry_count = header_.entry_used = (uint32_t)entries_.size();
  header_.free_count = header_.free_used = 1;

  auto* ptr = data;
  memcpy(ptr, &header_, sizeof(X_XDBF_HEADER));
  ptr += sizeof(X_XDBF_HEADER);

  auto* free_ptr =
      (X_XDBF_FILELOC*)(ptr + (sizeof(X_XDBF_ENTRY) * header_.entry_count));
  auto* data_start =
      (uint8_t*)free_ptr + (sizeof(X_XDBF_FILELOC) * header_.free_count);

  auto* data_ptr = data_start;
  for (auto ent : entries_) {
    ent.info.offset = (uint32_t)(data_ptr - data_start);
    ent.info.size = (uint32_t)ent.data.size();
    memcpy(ptr, &ent.info, sizeof(X_XDBF_ENTRY));

    memcpy(data_ptr, ent.data.data(), ent.data.size());
    data_ptr += ent.data.size();
    ptr += sizeof(X_XDBF_ENTRY);
  }

  free_entries_.clear();
  X_XDBF_FILELOC free_ent;
  free_ent.offset = (uint32_t)*data_size - sizeof(X_XDBF_HEADER) -
                    (sizeof(X_XDBF_ENTRY) * header_.entry_count) -
                    (sizeof(X_XDBF_FILELOC) * header_.free_count);

  free_ent.size = 0 - free_ent.offset;
  free_entries_.push_back(free_ent);

  for (auto ent : free_entries_) {
    memcpy(free_ptr, &ent, sizeof(X_XDBF_FILELOC));
    free_ptr++;
  }

  return true;
}

Entry* XdbfFile::GetEntry(uint16_t section, uint64_t id) const {
  for (size_t i = 0; i < entries_.size(); i++) {
    auto* entry = (Entry*)&entries_[i];
    if (entry->info.section != section || entry->info.id != id) {
      continue;
    }

    return entry;
  }

  return nullptr;
}

bool XdbfFile::UpdateEntry(const Entry& entry) {
  for (size_t i = 0; i < entries_.size(); i++) {
    auto* ent = (Entry*)&entries_[i];
    if (ent->info.section != entry.info.section ||
        ent->info.id != entry.info.id) {
      continue;
    }

    ent->data = entry.data;
    ent->info.size = (uint32_t)entry.data.size();
    return true;
  }

  Entry new_entry;
  new_entry.info.section = entry.info.section;
  new_entry.info.id = entry.info.id;
  new_entry.info.size = (uint32_t)entry.data.size();
  new_entry.data = entry.data;

  entries_.push_back(new_entry);
  return true;
}

std::string GetStringTableEntry_(const uint8_t* table_start, uint16_t string_id,
                                 uint16_t count) {
  auto* ptr = table_start;
  for (uint16_t i = 0; i < count; ++i) {
    auto entry = reinterpret_cast<const XdbfStringTableEntry*>(ptr);
    ptr += sizeof(XdbfStringTableEntry);
    if (entry->id == string_id) {
      return std::string(reinterpret_cast<const char*>(ptr),
                         entry->string_length);
    }
    ptr += entry->string_length;
  }
  return "";
}

std::string SpaFile::GetStringTableEntry(XLanguage language,
                                         uint16_t string_id) const {
  auto xstr_table = GetEntry(static_cast<uint16_t>(SpaSection::kStringTable),
                             static_cast<uint64_t>(language));
  if (!xstr_table) {
    return "";
  }

  auto xstr_head =
      reinterpret_cast<const X_XDBF_TABLE_HEADER*>(xstr_table->data.data());
  //assert_truexstr_head->header.magic == static_cast<uint32_t>(SpaID::Xstr));
  //assert_truexstr_head->header.version == 1);

  const uint8_t* ptr = xstr_table->data.data() + sizeof(X_XDBF_TABLE_HEADER);

  return GetStringTableEntry_(ptr, string_id, xstr_head->count);
}

uint32_t SpaFile::GetAchievements(
    XLanguage lang, std::vector<Achievement>* achievements) const {
  auto xach_table = GetEntry(static_cast<uint16_t>(SpaSection::kMetadata),
                             static_cast<uint64_t>(SpaID::Xach));
  if (!xach_table) {
    return 0;
  }

  auto xach_head =
      reinterpret_cast<const X_XDBF_TABLE_HEADER*>(xach_table->data.data());
  //assert_truexach_head->header.magic == static_cast<uint32_t>(SpaID::Xach));
  //assert_truexach_head->header.version == 1);

  auto xstr_table = GetEntry(static_cast<uint16_t>(SpaSection::kStringTable),
                             static_cast<uint64_t>(lang));
  if (!xstr_table) {
    return 0;
  }

  auto xstr_head =
      reinterpret_cast<const X_XDBF_TABLE_HEADER*>(xstr_table->data.data());
  //assert_truexstr_head->header.magic == static_cast<uint32_t>(SpaID::Xstr));
  //assert_truexstr_head->header.version == 1);

  const uint8_t* xstr_ptr =
      xstr_table->data.data() + sizeof(X_XDBF_TABLE_HEADER);

  if (achievements) {
    auto* ach_data =
        reinterpret_cast<const X_XDBF_SPA_ACHIEVEMENT*>(xach_head + 1);
    for (uint32_t i = 0; i < xach_head->count; i++) {
      Achievement ach;
      ach.id = ach_data->id;
      ach.image_id = ach_data->image_id;
      ach.gamerscore = ach_data->gamerscore;
      ach.flags = ach_data->flags;
      ach.flags |= static_cast<uint32_t>(AchievementPlatform::kX360);

      ach.label = GetStringTableEntry_(xstr_ptr, ach_data->label_id, xstr_head->count);

      ach.description = GetStringTableEntry_(
          xstr_ptr, ach_data->description_id, xstr_head->count);

      ach.unachieved_desc = GetStringTableEntry_(
          xstr_ptr, ach_data->unachieved_id, xstr_head->count);

      achievements->push_back(ach);
      ach_data++;
    }
  }

  return xach_head->count;
}

Entry* SpaFile::GetIcon() const {
  return GetEntry(static_cast<uint16_t>(SpaSection::kImage),
                  static_cast<uint64_t>(SpaID::Title));
}

XLanguage SpaFile::GetDefaultLanguage() const {
  auto block = GetEntry(static_cast<uint16_t>(SpaSection::kMetadata),
                        static_cast<uint64_t>(SpaID::Xstc));
  if (!block) {
    return XLanguage::kEnglish;
  }

  auto xstc = reinterpret_cast<const X_XDBF_XSTC_DATA*>(block->data.data());
  //assert_truexstc->header.magic == static_cast<uint32_t>(SpaID::Xstc));

  return static_cast<XLanguage>(static_cast<uint32_t>(xstc->default_language));
}

std::string SpaFile::GetTitleName() const {
  return GetStringTableEntry(GetDefaultLanguage(),
                             static_cast<uint16_t>(SpaID::Title));
}

bool SpaFile::GetTitleData(X_XDBF_XTHD_DATA* title_data) const {
  auto block = GetEntry(static_cast<uint16_t>(SpaSection::kMetadata),
                        static_cast<uint64_t>(SpaID::Xthd));
  if (!block) {
    return false;
  }

  auto xthd = reinterpret_cast<const X_XDBF_XTHD_DATA*>(block->data.data());
  //assert_truexthd->header.magic == static_cast<uint32_t>(SpaID::Xthd));

  if (title_data) {
    *title_data = *xthd;
  }
  return true;
}

}  // namespace xdbf
}  // namespace xam
}  // namespace kernel
}  // namespace xe
