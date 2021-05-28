#pragma once
#include <cstdint>
#include <vector>
#include <algorithm>
#include <map>
#include <string>

#include "xex_optheaders.hpp"
#include "pe_structs.hpp"

// XEX header magic values
#define MAGIC_XEX0 0x58455830  // 'XEX0'
#define MAGIC_XEX3F 0x5845583F // 'XEX?'
#define MAGIC_XEX2D 0x5845582D // 'XEX-'
#define MAGIC_XEX25 0x58455825 // 'XEX%'
#define MAGIC_XEX1 0x58455831  // 'XEX1'
#define MAGIC_XEX2 0x58455832  // 'XEX2'

// Basefile magic values
#define MAGIC_XUIZ 0x5A495558  // 'ZIUX'

// Function pointer types, these let us support both IDA's IO functions & regular C's IO
typedef size_t(*read_fn)(void* buffer, size_t element_size, size_t element_count, void* file);
typedef int(*seek_fn)(void* file, long long offset, int origin);
typedef long long(*tell_fn)(void* file);
typedef int(*dbgmsg_fn)(const char* format, ...);
int stdio_msg(const char* format, ...); // xex2.cpp

struct XEXFunction
{
  uint32_t ThunkAddr = 0;
  uint32_t FuncAddr = 0;
};

class XEXFile
{
  // IO function pointers
  read_fn read = nullptr;
  seek_fn seek = nullptr;
  tell_fn tell = nullptr;
  dbgmsg_fn dbgmsg = nullptr;

  uint32_t data_length_ = 0; // length of file data (filesize - headersize)

  xex::XexHeader xex_header_ = {};
  std::map<uint32_t, uint32_t> directory_entries_;
  xex2::SecurityInfo security_info_ = {};
  std::vector<xex::HvPageInfo> page_descriptors_;

  bool has_secinfo_ = false;

  int signkey_index_ = -1;
  bool valid_signature_ = false;
  bool valid_header_hash_ = false;
  bool valid_image_hash_ = false;
  bool valid_imports_hash_ = false;

  int key_index_ = -1;
  uint8_t session_key_[0x10];

  std::vector<uint8_t> xex_headers_;
  std::vector<uint8_t> pe_data_;

  // Values of various optional headers
  xe::be<uint32_t> opt_base_address_ = 0;
  xe::be<uint32_t> entry_point_ = 0;
  xex_opt::XexFileDataDescriptor* data_descriptor_ = nullptr;
  xex_opt::XexPrivileges privileges_ = {};
  xex_opt::XexPrivileges32 privileges32_ = {};
  xex_opt::XexExecutionId* execution_id_ = nullptr;
  xex_opt::XexVitalStats* vital_stats_ = nullptr;
  xex_opt::XexTlsData* tls_data_ = nullptr;
  std::vector<xex_opt::XexImageLibraryVersion> libraries_; // Versions of libraries this was linked against
  std::string pe_module_name_ = "";

  // Imports & Exports
  std::map<std::string, std::map<uint32_t, XEXFunction>> imports_;
  std::map<uint32_t, XEXFunction> exports_;
  std::map<std::string, xex_opt::XexImportTable> import_tables_;
  std::string exports_libname_ = "";

  // Sections from XEX headers
  std::vector<IMAGE_SECTION_HEADER> xex_sections_;

  // Sections from PE headers (includes XEX sections above)
  std::vector<IMAGE_SECTION_HEADER> sections_;

  // Note: "void* file" below is a pointer to a FILE object, not to raw file data!
  bool read_imports(void* file);
  bool read_exports(void* file);

  bool read_secinfo(void* file);
  uint32_t verify_secinfo(void* file);

  bool read_basefile(void* file, int key_index);
  bool read_basefile_raw(void* file, bool encrypted);
  bool read_basefile_uncompressed(void* file, bool encrypted);
  bool read_basefile_compressed(void* file, bool encrypted);

  bool basefile_verify();

  bool pe_load(const uint8_t* data);
  bool pe_load_imports(const uint8_t* data);
  bool pe_load_exports(const uint8_t* data);

public:
  XEXFile() { 
#ifndef IDALDR
    read = (read_fn)fread; seek = (seek_fn)_fseeki64; tell = (tell_fn)_ftelli64; dbgmsg = stdio_msg;
#endif
  }

  // Sets our IO function pointers to use IDA's IO functions
  void use_ida_io();

  // Loads in the XEX - note that "file" should be a FILE object, not a pointer to raw data!
  bool load(void* file);

  const xex::XexHeader& header() { return xex_header_; }
  const xex2::SecurityInfo& security_info() { return security_info_; }
  const std::vector<xex::HvPageInfo>& page_descriptors() { return page_descriptors_; }

  const uint8_t* xex_headers() { return xex_headers_.data(); }
  const uint8_t* pe_data() { return pe_data_.data(); }

  uint32_t pe_rva_to_offset(uint32_t rva);

  uint32_t xex_va_to_offset(uint32_t va);
  uint32_t xex_offset_to_va(uint32_t offset);

  // Length of the pe_data member, not the same as image_size!
  size_t pe_data_length() { return pe_data_.size(); }

  bool basefile_is_pe() {
    return pe_data_length() > 4 && *(uint16_t*)pe_data() == EXE_MZ_SIGNATURE;
  }

  bool basefile_is_xuiz() {
    return pe_data_length() > 4 && *(uint32_t*)pe_data() == MAGIC_XUIZ;
  }

  bool basefile_is_valid() {
    return basefile_is_pe() || basefile_is_xuiz();
  }

  const std::vector<IMAGE_SECTION_HEADER>& sections() { return sections_; }
  const std::vector<IMAGE_SECTION_HEADER>& xex_sections() { return xex_sections_; }

  const std::map<std::string, std::map<uint32_t, XEXFunction>>& imports() { return imports_; }
  const std::map<uint32_t, XEXFunction>& exports() { return exports_; }

  const std::map<std::string, xex_opt::XexImportTable>& import_tables() { return import_tables_; }
  const std::string& exports_libname() { return exports_libname_; }

  bool has_header(uint32_t id);

  // Returns value of an optional header, if exists
  uint32_t opt_header(uint32_t id);

  // Returns pointer to an optional headers value, if exists
  void* opt_header_ptr(uint32_t id);

  template<typename T>
  T* opt_header_ptr(uint32_t id) {
    return (T*)opt_header_ptr(id);
  }

  const char* sign_key_name();
  uint32_t sign_key_index() { return signkey_index_; }
  bool valid_signature() { return valid_signature_; }
  bool valid_header_hash() { return valid_header_hash_; }
  bool valid_image_hash() { return valid_image_hash_; }
  bool valid_imports_hash() { return valid_imports_hash_; }

  uint32_t encryption_key_index() { return key_index_; }
  uint8_t* session_key() { return session_key_; }

  // Optional headers
  uint32_t image_size() {
    return std::max(data_length_, (uint32_t)security_info_.ImageSize);
  }

  uint32_t base_address() { return opt_base_address_ ? opt_base_address_ : security_info_.ImageInfo.LoadAddress; }
  uint32_t opt_base_address() { return opt_base_address_; }
  uint32_t entry_point() { return entry_point_; }

  const std::string& pe_module_name() { return pe_module_name_; }
  const xex_opt::XexVitalStats* vital_stats() { return vital_stats_; }
  const xex_opt::XexFileDataDescriptor* data_descriptor() { return data_descriptor_; }

  uint32_t min_kernel_version() {
    switch (xex_header_.Magic) {
      case MAGIC_XEX0:  return 1332;
      case MAGIC_XEX3F: return 1529;
      case MAGIC_XEX2D: return 1640;
      case MAGIC_XEX25: return 1746;
      case MAGIC_XEX1:  return 1838;
      case MAGIC_XEX2:  return 1861;
    }
    return 0;
  }
};
