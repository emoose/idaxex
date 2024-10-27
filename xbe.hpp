#pragma once
#include <cstdint>
#include <vector>
#include <algorithm>
#include <map>
#include <string>

#include "xbe_structs.hpp"
#include "xex.hpp" // stdio crap

#define MAGIC_XBEH 0x48454258
#define MAGIC_XBEH_BE 0x58424548

// Keys are derived by kernel via: 
//   uint32_t* key_base = (uint32_t*)&XePublicKeyData[0x80]
//   KernelThunkKey = key_base[1] ^ key_base[2];
//   EntryPointKey = key_base[0] ^ key_base[4];
// Where XePublicKeyData is export 355 from kernel, beginning with RSA1 header
#define XBE_XOR_KT_RETAIL 0x5B6D40B6
#define XBE_XOR_EP_RETAIL 0xA8FC57AB
#define XBE_XOR_KT_DEBUG 0xEFB1F152
#define XBE_XOR_EP_DEBUG 0x94859D4B
#define XBE_XOR_KT_XBL_BETA 0x46437DCD
#define XBE_XOR_EP_XBL_BETA 0xE682F45B
#define XBE_XOR_KT_CHIHIRO 0x2290059D
#define XBE_XOR_EP_CHIHIRO 0x40B5C16E

struct XBESection
{
  std::string Name;
  xbe::XbeSection Info;
  std::vector<uint8_t> Data;
};

enum class XBELoadError
{
  Success,
  Unfinished,
  InvalidMagic,
  UnknownXORKey,
  Count
};

class XBEFile
{
  // IO function pointers
  read_fn read = nullptr;
  seek_fn seek = nullptr;
  tell_fn tell = nullptr;
  dbgmsg_fn dbgmsg = nullptr;

  size_t image_length_ = 0; // length of xbe file

  xbe::XbeHeader xbe_header_ = {};
  std::vector<uint8_t> xbe_data_;
  std::vector<uint8_t> header_data_;

  std::vector<XBESection> sections_;
  std::map<uint32_t, uint32_t> kernel_imports_;
  std::vector<std::vector<uint8_t>> codeview_data_;
  uint32_t tls_directory_va_ = 0;
  IMAGE_TLS_DIRECTORY32 tls_directory_{};
  std::vector<uint32_t> tls_callbacks_;

  std::vector<xbe::XbeLibraryVersion> libraries_; // Versions of libraries this was linked against
  std::string pe_module_name_ = "";

  int load_error_ = 0;

  int xorkey_index_ = -1;

  std::string read_null_terminated(void* file, std::size_t maxlen);

public:
  XBEFile() {
#ifndef IDALDR
#ifdef _MSC_VER
    read = (read_fn)fread; seek = (seek_fn)_fseeki64; tell = (tell_fn)_ftelli64; dbgmsg = stdio_msg;
#else
    read = (read_fn)fread; seek = (seek_fn)fseeko64; tell = (tell_fn)ftello64; dbgmsg = stdio_msg;
#endif
#endif
  }

  static const char* key_name(int xor_key_idx);

  uint32_t base_address() { return xbe_header_.BaseAddress; }
  uint32_t entry_point() { return xbe_header_.AddressOfEntryPoint; }
  uint32_t image_size() { return xbe_header_.SizeOfImage; }
  int xorkey_index() { return xorkey_index_; }
  bool is_xorkey_beta();

  const std::string& pe_module_name() { return pe_module_name_; }

  uint32_t tls_directory_va() { return tls_directory_va_; }
  IMAGE_TLS_DIRECTORY32 tls_directory() { return tls_directory_; }
  const std::vector<uint32_t>& tls_callbacks() { return tls_callbacks_; }

  const std::vector<uint8_t>& xbe_data() { return xbe_data_; }
  const std::vector<uint8_t>& header_data() { return header_data_; }
  const std::vector<XBESection>& sections() { return sections_; }
  const std::map<uint32_t, uint32_t>& kernel_imports() { return kernel_imports_; }
  const uint8_t* codeview_data(int idx, size_t* size = nullptr) {
    if (codeview_data_.size() > idx)
    {
      if (size)
        *size = codeview_data_[idx].size();
      return codeview_data_[idx].data();
    }
    return nullptr;
  }
  const std::vector<xbe::XbeLibraryVersion>& libraries() { return libraries_; }

  uint32_t xbe_va_to_offset(uint32_t va);

  int load_error() { return load_error_; }

  // Sets our IO function pointers to use IDA's IO functions
  void use_ida_io();

  // Loads in the file - note that "file" should be a FILE object, not a pointer to raw data!
  bool load(void* file);

  const xbe::XbeHeader& header() { return xbe_header_; }
};
