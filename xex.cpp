#include "../idaldr.h"
#include "xex.hpp"
#include "xex_headerids.hpp"
#include <cstdio>
#include <algorithm>

#include "aes.hpp"
#include "lzx/lzx.hpp"
#include "sha1.hpp"

// Various encryption keys used to decrypt XEX image key
// There's no indication inside the XEX which key is used though :(
// Only way to know is to try decrypting and check if the resulting data is valid
const uint8_t retail_key[16] = {
  0x20, 0xB1, 0x85, 0xA5, 0x9D, 0x28, 0xFD, 0xC3,
  0x40, 0x58, 0x3F, 0xBB, 0x08, 0x96, 0xBF, 0x91
};
const uint8_t devkit_key[16] = {
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

// unsure if any of the xex1 keys get used, we'll still try them as last resort anyway
const uint8_t retail_key_xex1[16] = {
  0xA2, 0x6C, 0x10, 0xF7, 0x1F, 0xD9, 0x35, 0xE9,
  0x8B, 0x99, 0x92, 0x2C, 0xE9, 0x32, 0x15, 0x72
};
const uint8_t devkit_key_xex1[16] = {
  0xA8, 0xB0, 0x05, 0x12, 0xED, 0xE3, 0x63, 0x8D,
  0xC6, 0x58, 0xB3, 0x10, 0x1F, 0x9F, 0x50, 0xD1
};

const uint8_t* key_bytes[4] = {
  retail_key,
  devkit_key,
  retail_key_xex1,
  devkit_key_xex1
};
const char* key_names[4] = {
  "retail",
  "devkit",
  "retail-XEX1",
  "devkit-XEX1"
};

bool XEXFile::VerifyBaseFileHeader(const uint8_t* data)
{
  // validate the basefiles magic, should either be a PE (with MZ signature)
  // or an XUIZ resource file

  // TODO: find out whether there's any other basefile formats?
  return *(uint16_t*)data == EXE_MZ_SIGNATURE || *(uint32_t*)data == MAGIC_XUIZ;
}

bool XEXFile::load(void* file)
{
  seek(file, 0, SEEK_END);
  auto fsize = tell(file);
  seek(file, 0, 0);

  read(&xex_header_, sizeof(xex::XexHeader), 1, file);
  *(uint32_t*)&xex_header_.ModuleFlags =
    swap32(*(uint32_t*)&xex_header_.ModuleFlags);

  if (xex_header_.Magic != MAGIC_XEX2 && xex_header_.Magic != MAGIC_XEX1 && 
    xex_header_.Magic != MAGIC_XEX25 && xex_header_.Magic != MAGIC_XEX2D && 
    xex_header_.Magic != MAGIC_XEX3F)
    return false;

  // Read in XEX header section
  xex_headers_.resize(xex_header_.SizeOfHeaders);
  seek(file, 0, 0);
  read(xex_headers_.data(), 1, xex_header_.SizeOfHeaders, file);

  data_length_ = (uint32_t)(fsize - xex_header_.SizeOfHeaders);

  seek(file, sizeof(xex::XexHeader), 0);

  if (xex_header_.Magic == MAGIC_XEX3F)
  {
    // XEX3F has some unknown data (imagesize?) in place of the directory entry count
    // directory count comes after that data, so read it into that datas place
    image_size_ = xex_header_.HeaderDirectoryEntryCount;
    read(&xex_header_.HeaderDirectoryEntryCount, sizeof(uint32_t), 1, file);

    // XEX3F has base address here instead of securityinfo offset
    base_address_ = xex_header_.SecurityInfo;
  }

  // Read in directory entry / optional header keyvalues
  for (int i = 0; i < xex_header_.HeaderDirectoryEntryCount; i++)
  {
    xex::XexDirectoryEntry header;
    read(&header, sizeof(xex::XexDirectoryEntry), 1, file);

    directory_entries_[header.Key] = header.Value;

    // XEX25 (and probably XEX2D) use a different imports key
    // some part of them isn't loading properly though, so disable loading imports for those for now
    /*if (header.Key == XEX_BETAHEADER_IMPORTS)
      directory_entries_[XEX_HEADER_IMPORTS] = header.Value;*/
  }

  // Read security info
  bool has_secinfo = read_secinfo(file);

  // Read various optional headers
  if (directory_entries_.count(XEX_HEADER_PE_BASE))
    base_address_ = directory_entries_[XEX_HEADER_PE_BASE];

  if (directory_entries_.count(XEX_HEADER_ENTRY_POINT))
    entry_point_ = directory_entries_[XEX_HEADER_ENTRY_POINT];

  *(uint32_t*)&privileges_ = opt_header(XEX_HEADER_PRIVILEGES);
  *(uint32_t*)&privileges32_ = opt_header(XEX_HEADER_PRIVILEGES_32);

  execution_id_ = reinterpret_cast<xex_opt::XexExecutionId*>(opt_header_ptr(XEX_HEADER_EXECUTION_ID));
  if (execution_id_)
  {
    *(uint32_t*)&execution_id_->BaseVersion = swap32(*(uint32_t*)&execution_id_->BaseVersion);
    *(uint32_t*)&execution_id_->Version = swap32(*(uint32_t*)&execution_id_->Version);
  }

  vital_stats_ = reinterpret_cast<xex_opt::XexVitalStats*>(opt_header_ptr(XEX_HEADER_VITAL_STATS));
  tls_data_ = reinterpret_cast<xex_opt::XexTlsData*>(opt_header_ptr(XEX_HEADER_TLS_DATA));

  data_descriptor_ = reinterpret_cast<xex_opt::XexFileDataDescriptor*>(opt_header_ptr(XEX_FILE_DATA_DESCRIPTOR_HEADER));

  auto libs = reinterpret_cast<xex_opt::XexImageLibraryVersions*>(opt_header_ptr(XEX_HEADER_BUILD_VERSIONS));
  if (libs)
  {
    auto count = (libs->Size - 4) / sizeof(xex_opt::XexImageLibraryVersion);
    for (uint32_t i = 0; i < count; i++)
      libraries_.push_back(libs->Libraries[i]);
  }

  if (directory_entries_.count(XEX_HEADER_PE_MODULE_NAME))
  {
    auto* header = (xex_opt::XexStringHeader*)opt_header_ptr(XEX_HEADER_PE_MODULE_NAME);
    if (header)
    {
      // Copy string and null terminate it ourselves, just in case
      auto str = new char[header->Size + 1];
      memcpy(str, header->Data, header->Size);
      str[header->Size] = '\0';

      pe_module_name_ = str;

      delete[] str;
    }
  }

  // Try decrypting/decompressing the basefile
  if (!read_basefile(file, 0) && !read_basefile(file, 1) && !read_basefile(file, 2) && !read_basefile(file, 3))
    return false;

  // Basefile seems to have read fine, try reading the PE headers
  if (!pe_load(pe_data_.data()))
    return false;

  // Let's map in the XEX sections too, seeing as there's no tools for pre-XEX2 to view these with
  auto sects = reinterpret_cast<xex_opt::XexSectionHeaders*>(opt_header_ptr(XEX_HEADER_SECTION_TABLE));
  if (sects)
  {
    auto count = (sects->Size - 4) / sizeof(xex_opt::XexSectionHeader);
    for (uint32_t i = 0; i < count; i++)
    {
      auto& section = sects->Sections[i];

      IMAGE_SECTION_HEADER pe_sec;
      pe_sec.Characteristics = IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ;
      pe_sec.VirtualAddress = section.VirtualAddress - base_address_;
      pe_sec.VirtualSize = section.VirtualSize;
      pe_sec.SizeOfRawData = section.VirtualSize;
      memcpy(pe_sec.Name, section.SectionName, 8);

      xex_sections_.push_back(pe_sec);
    }
  }

  // Try reading imports & exports
  read_imports(file);
  read_exports(file);

  return true;
}

// Reads import libraries & function info from XEX import table
bool XEXFile::read_imports(void* file)
{
  if (!directory_entries_.count(XEX_HEADER_IMPORTS))
    return false;

  if (!directory_entries_[XEX_HEADER_IMPORTS])
    return false;

  seek(file, directory_entries_[XEX_HEADER_IMPORTS], 0);

  xex_opt::XexImportDescriptor import_desc;
  read(&import_desc, sizeof(xex_opt::XexImportDescriptor), 1, file);

  // Seperate the library names in the name table
  std::vector<std::string> import_libs;
  std::string cur_lib = "";
  for (int i = 0; i < import_desc.NameTableSize; i++)
  {
    if (!cur_lib.length())
    {
      // align to 4 bytes
      if ((i % 4) != 0)
      {
        int align = 4 - (i % 4);
        align = std::min(align, (int)import_desc.NameTableSize - i); // don't let us align past end of nametable
        i += align - 1; // minus 1 since for loop will add 1 to it too
        seek(file, align, SEEK_CUR);

        continue;
      }
    }

    char name_char;
    read(&name_char, 1, 1, file);

    if (name_char == '\0' || name_char == '\xCD')
    {
      if (cur_lib.length())
      {
        import_libs.push_back(cur_lib);
        cur_lib = "";
      }
    }
    else
      cur_lib += name_char;
  }

  // Read in each import library
  for (uint32_t i = 0; i < import_desc.ModuleCount; i++)
  {
    auto table_addr = tell(file);

    // Read in import table header
    xex_opt::XexImportTable table_header;
    read(&table_header, sizeof(xex_opt::XexImportTable), 1, file);
    *(uint32_t*)&table_header.Version = swap32(*(uint32_t*)&table_header.Version);
    *(uint32_t*)&table_header.VersionMin = swap32(*(uint32_t*)&table_header.VersionMin);

    auto& libname = import_libs.at(table_header.ModuleIndex);

    if (!imports_.count(libname))
      imports_[libname] = std::map<uint32_t, XEXFunction>();

    if (!import_tables_.count(libname))
      import_tables_[libname] = table_header;

    for (uint32_t j = 0; j < table_header.ImportCount; j++)
    {
      xe::be<uint32_t> record_addr;
      read(&record_addr, sizeof(uint32_t), 1, file);
      if (!record_addr)
        continue;

      // Read import data from basefile
      auto record_offset = pe_rva_to_offset(record_addr);

      auto record_value = *(uint32_t*)(pe_data() + record_offset);
      record_value = swap32(record_value);

      auto record_type = (record_value & 0xFF000000) >> 24;
      auto ordinal = record_value & 0xFFFF;

      XEXFunction imp;
      if (imports_[libname].count(ordinal))
        imp = imports_[libname][ordinal];

      if (record_type == 0)
      {
        // variable
        imp.ThunkAddr = record_addr;
      }
      else if (record_type == 1)
      {
        // function
        imp.FuncAddr = record_addr;

        // have to rewrite code to set r3 & r4 like xorlosers loader does
        // r3 = module index afaik
        // r4 = ordinal
        // important to note that basefiles extracted via xextool have this rewrite done already, but raw basefile from XEX doesn't!
        // todo: find out how to add to imports window like xorloser loader...
        *(uint32_t*)(pe_data() + record_offset + 0) = swap32(0x38600000 | table_header.ModuleIndex);
        *(uint32_t*)(pe_data() + record_offset + 4) = swap32(0x38800000 | ordinal);
      }
      else // todo: fix this
        dbgmsg("[+] %s import %d (@ 0x%X) unknown type %d!\n", libname.c_str(), ordinal, record_addr, record_type);

      imports_[libname][ordinal] = imp;
    }

    // Seek to end of this import table
    seek(file, table_addr + table_header.TableSize, 0);
  }

  // Handle callcap imports
  if (directory_entries_.count(XEX_HEADER_CALLCAP_IMPORTS))
  {
    xex_opt::XexCallcapImports callcap;
    seek(file, directory_entries_[XEX_HEADER_CALLCAP_IMPORTS], 0);
    read(&callcap, sizeof(xex_opt::XexCallcapImports), 1, file);

    if (!callcap.BeginFunctionThunkAddress || !callcap.EndFunctionThunkAddress)
      return true;

    dbgmsg("[+] Naming callcap imports... (0x%X - 0x%X)\n", callcap.BeginFunctionThunkAddress, callcap.EndFunctionThunkAddress);
    for (uint32_t i = callcap.BeginFunctionThunkAddress; i < callcap.EndFunctionThunkAddress + 0x10; i += 0x10)
    {
      uint32_t import_offset = pe_rva_to_offset(i);

      uint32_t info_1 = *(uint32_t*)(pe_data() + import_offset);
      uint32_t info_2 = *(uint32_t*)(pe_data() + import_offset + 4);
      info_1 = swap32(info_1);
      info_2 = swap32(info_2);

      auto ordinal_1 = info_1 & 0xFFFF;
      auto ordinal_2 = info_2 & 0xFFFF;
      auto moduleidx_1 = (info_1 & 0xFF0000) >> 16;
      auto moduleidx_2 = (info_2 & 0xFF0000) >> 16;

      // Sanity check the callcap info, values from first dword should match values in second
      if (ordinal_1 != ordinal_2 || moduleidx_1 != moduleidx_2)
      {
        dbgmsg("[!] Invalid callcap at 0x%X ?", i);
        continue;
      }

      // Not sure if it should always be xbdm or not...
      std::string libname = "xbdm.xex";
      if (import_libs.size() > moduleidx_1)
        libname = import_libs.at(moduleidx_1);

      if (!imports_.count(libname))
        imports_[libname] = std::map<uint32_t, XEXFunction>();

      XEXFunction imp;
      if (imports_[libname].count(ordinal_1))
        imp = imports_[libname][ordinal_1];

      imp.ThunkAddr = i;
      imp.FuncAddr = i;

      *(uint32_t*)(pe_data() + import_offset + 0) = swap32(0x38600000 | moduleidx_1);
      *(uint32_t*)(pe_data() + import_offset + 4) = swap32(0x38800000 | ordinal_1);

      imports_[libname][ordinal_1] = imp;
    }
  }

  return true;
}

// Reads function info defined inside XEX export table
bool XEXFile::read_exports(void* file)
{
  if (!export_table_va_)
    return false;

  auto export_table_offset = pe_rva_to_offset(export_table_va_);
  xex_opt::HvImageExportTable export_table;
  memcpy(&export_table, pe_data() + export_table_offset, sizeof(xex_opt::HvImageExportTable));

  if (export_table.Magic[0] != XEX_EXPORT_MAGIC_0 ||
    export_table.Magic[1] != XEX_EXPORT_MAGIC_1 ||
    export_table.Magic[2] != XEX_EXPORT_MAGIC_2)
  {
    dbgmsg("[+] Export table magic is invalid! (0x%X 0x%X 0x%X)\n", export_table.Magic[0], export_table.Magic[1], export_table.Magic[2]);
    return false;
  }

  dbgmsg("[+] Loading module exports...\n");
  char module_name[256];
  get_root_filename(module_name, 256);

  auto ordinal_addrs_va = export_table_va_ + sizeof(xex_opt::HvImageExportTable);
  auto ordinal_addrs_offset = export_table_offset + sizeof(xex_opt::HvImageExportTable);
  for (int i = 0; i < export_table.Count; i++)
  {
    auto ordinal = export_table.Base + i;

    XEXFunction exp;
    if (exports_.count(ordinal))
      exp = exports_[ordinal];

    exp.ThunkAddr = ordinal_addrs_va + (i * 4);
    exp.FuncAddr = *(uint32_t*)(pe_data() + ordinal_addrs_offset + (i * 4));
    exp.FuncAddr = swap32(exp.FuncAddr);
    if (!exp.FuncAddr)
      continue;

    exp.FuncAddr += (export_table.ImageBaseAddress << 16);

    exports_[ordinal] = exp;
  }

  return true;
}

// Reads in fields we care about from the various SecurityInfo versions
bool XEXFile::read_secinfo(void* file)
{
  if (xex_header_.Magic == MAGIC_XEX3F)
    return false; // XEX3F doesn't have securityinfo header!

  // ImageSize - always at SecurityInfo[0x4]
  seek(file, xex_header_.SecurityInfo + 4, 0);
  read(&image_size_, sizeof(uint32_t), 1, file);

  // ImageKey
  if (xex_header_.Magic != MAGIC_XEX2D)
  {
    std::map<uint32_t, size_t> offs_ImageKey = {
      {MAGIC_XEX2, offsetof(xex2::SecurityInfo, ImageInfo.ImageKey)},
      {MAGIC_XEX1, offsetof(xex1::SecurityInfo, ImageInfo.ImageKey)},
      {MAGIC_XEX25, offsetof(xex25::SecurityInfo, ImageInfo.ImageKey)}
    };

    seek(file, xex_header_.SecurityInfo + offs_ImageKey[xex_header_.Magic], 0);
    read(image_key_, 1, 0x10, file);
  }

  // LoadAddress
  std::map<uint32_t, size_t> offs_LoadAddress = {
    {MAGIC_XEX2, offsetof(xex2::SecurityInfo, ImageInfo.LoadAddress)},
    {MAGIC_XEX1, offsetof(xex1::SecurityInfo, ImageInfo.LoadAddress)},
    {MAGIC_XEX25, offsetof(xex25::SecurityInfo, ImageInfo.LoadAddress)},
    {MAGIC_XEX2D, offsetof(xex2d::SecurityInfo, ImageInfo.LoadAddress)}
  };

  seek(file, xex_header_.SecurityInfo + offs_LoadAddress[xex_header_.Magic], 0);
  read(&base_address_, sizeof(uint32_t), 1, file);

  // ExportTableAddress
  std::map<uint32_t, size_t> offs_ExportTableAddress = {
    {MAGIC_XEX2, offsetof(xex2::SecurityInfo, ImageInfo.ExportTableAddress)},
    {MAGIC_XEX1, offsetof(xex1::SecurityInfo, ImageInfo.ExportTableAddress)},
    {MAGIC_XEX25, offsetof(xex25::SecurityInfo, ImageInfo.ExportTableAddress)},
    {MAGIC_XEX2D, offsetof(xex2d::SecurityInfo, ImageInfo.ExportTableAddress)}
  };

  seek(file, xex_header_.SecurityInfo + offs_ExportTableAddress[xex_header_.Magic], 0);
  read(&export_table_va_, sizeof(uint32_t), 1, file);

  // ImageFlags
  std::map<uint32_t, size_t> offs_ImageFlags = {
    {MAGIC_XEX2, offsetof(xex2::SecurityInfo, ImageInfo.ImageFlags)},
    {MAGIC_XEX1, offsetof(xex1::SecurityInfo, ImageInfo.ImageFlags)},
    {MAGIC_XEX25, offsetof(xex25::SecurityInfo, ImageInfo.ImageFlags)},
    {MAGIC_XEX2D, offsetof(xex2d::SecurityInfo, ImageInfo.ImageFlags)}
  };

  seek(file, xex_header_.SecurityInfo + offs_ImageFlags[xex_header_.Magic], 0);
  read(&image_flags_, sizeof(uint32_t), 1, file);
  *(uint32_t*)&image_flags_ = swap32(*(uint32_t*)&image_flags_);

  // GameRegion
  std::map<uint32_t, size_t> offs_GameRegion = {
    {MAGIC_XEX2, offsetof(xex2::SecurityInfo, ImageInfo.GameRegion)},
    {MAGIC_XEX1, offsetof(xex1::SecurityInfo, ImageInfo.GameRegion)},
    {MAGIC_XEX25, 0},
    {MAGIC_XEX2D, 0}
  };

  uint32_t tmp = 0;
  if (offs_GameRegion[xex_header_.Magic])
  {
    seek(file, xex_header_.SecurityInfo + offs_GameRegion[xex_header_.Magic], 0);
    read(&tmp, sizeof(uint32_t), 1, file);
    tmp = swap32(tmp);
  }
  *(uint32_t*)&game_regions_ = tmp;

  // AllowedMediaTypes
  std::map<uint32_t, size_t> offs_AllowedMediaTypes = {
    {MAGIC_XEX2, offsetof(xex2::SecurityInfo, AllowedMediaTypes)},
    {MAGIC_XEX1, offsetof(xex1::SecurityInfo, AllowedMediaTypes)},
    {MAGIC_XEX25, offsetof(xex25::SecurityInfo, AllowedMediaTypes)},
    {MAGIC_XEX2D, offsetof(xex2d::SecurityInfo, AllowedMediaTypes)}
  };

  seek(file, xex_header_.SecurityInfo + offs_AllowedMediaTypes[xex_header_.Magic], 0);
  read(&media_types_, sizeof(uint32_t), 1, file);
  *(uint32_t*)&media_types_ = swap32(*(uint32_t*)&media_types_);

  return true;
}

// Reads (and optionally decrypts) the basefile from the XEX in "raw" format
bool XEXFile::read_basefile_raw(void* file, bool encrypted)
{
  pe_data_.resize(std::max(data_length_, swap32(image_size_.value)));

  seek(file, xex_header_.SizeOfHeaders, 0);
  read(pe_data_.data(), 1, data_length_, file);

  if (encrypted)
  {
    AES_ctx aes;
    uint8_t iv[] = {
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };

    AES_init_ctx_iv(&aes, session_key_, iv);
    AES_CBC_decrypt_buffer(&aes, pe_data_.data(), data_length_);
  }

  return true;
}

// Reads (and optionally decrypts) the basefile from the XEX in uncompressed format
bool XEXFile::read_basefile_uncompressed(void* file, bool encrypted)
{
  if (!data_descriptor_)
    return false;

  int num_blocks = (data_descriptor_->Size - 8) / 8;
  auto* xex_blocks = new xex_opt::XexRawDataDescriptor[num_blocks];

  seek(file, directory_entries_[XEX_FILE_DATA_DESCRIPTOR_HEADER] + 8, 0);
  read(xex_blocks, sizeof(xex_opt::XexRawDataDescriptor), num_blocks, file);

  AES_ctx aes;
  uint8_t iv[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
  };

  if (encrypted)
    AES_init_ctx_iv(&aes, session_key_, iv);

  pe_data_.resize(image_size_);
  uint32_t position = 0;
  seek(file, xex_header_.SizeOfHeaders, 0);
  for (int i = 0; i < num_blocks; i++)
  {
    // if it's the first block & encrypted, we'll test-decrypt the first 16 bytes
    // so we can test if it decrypted properly with this key, without needing to process the entire block
    if (i == 0 && encrypted)
    {
      // Read first 16 bytes of block and decrypt
      auto pos = tell(file);
      read(pe_data_.data(), 1, 0x10, file);
      AES_ECB_decrypt(&aes, pe_data_.data());

      // Check basefile header
      if (!VerifyBaseFileHeader(pe_data_.data()))
      {
        pe_data_.clear();
        delete[] xex_blocks;
        return false;
      }

      // Reinit AES & seek back to start of block
      AES_init_ctx_iv(&aes, session_key_, iv);
      seek(file, pos, 0);
    }

    read(pe_data_.data() + position, 1, xex_blocks[i].DataSize, file);

    if (encrypted)
      AES_CBC_decrypt_buffer(&aes, pe_data_.data() + position, xex_blocks[i].DataSize);

    position += xex_blocks[i].DataSize;
    memset(pe_data_.data() + position, 0, xex_blocks[i].ZeroSize);
    position += xex_blocks[i].ZeroSize;
  }
  // todo: verify block size sum == ImageSize ?

  delete[] xex_blocks;

  return true;
}

// Reads (and optionally decrypts) the basefile from the XEX in LZX-compressed format
bool XEXFile::read_basefile_compressed(void* file, bool encrypted)
{
  AES_ctx aes;
  if (encrypted)
  {
    uint8_t iv[] = {
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };
    AES_init_ctx_iv(&aes, session_key_, iv);
  }

  // read windowsize & first block from file_data_descriptor header
  xex_opt::XexCompressedDataDescriptor compression_info;
  seek(file, directory_entries_[XEX_FILE_DATA_DESCRIPTOR_HEADER] + 8, 0);
  read(&compression_info, sizeof(xex_opt::XexCompressedDataDescriptor), 1, file);

  auto* cur_block = &compression_info.FirstDescriptor;

  // Alloc memory for the PE
  pe_data_.resize(image_size_);

  // LZX init...
  LZXinit(compression_info.WindowSize);
  uint8_t* comp_buffer = (uint8_t*)malloc(0x9800); // 0x9800 = max comp. block size (0x8000) + MAX_GROWTH (0x1800)
  if (!comp_buffer)
  {
    dbgmsg("[!] Error: failed to allocate decompression buffer!?\n");
    return false;
  }

  uint32_t size_left = image_size_;
  uint32_t size_done = 0;
  int retcode = 0;

  // Start decompressing
  SHA1Context sha_state;
  seek(file, xex_header_.SizeOfHeaders, 0);
  xex_opt::XexDataDescriptor next_block;
  uint8_t* block_data = 0;
  while (cur_block->Size)
  {
    block_data = (uint8_t*)malloc(cur_block->Size);
    read(block_data, 1, cur_block->Size, file);

    if (encrypted)
      AES_CBC_decrypt_buffer(&aes, block_data, cur_block->Size);

    // Check hash of the block - don't want to attempt decompressing invalid data!
    uint8_t sha_hash[0x14];
    SHA1Reset(&sha_state);
    SHA1Input(&sha_state, block_data, cur_block->Size);
    SHA1Result(&sha_state, sha_hash);

    if (memcmp(sha_hash, cur_block->DataDigest, 0x14) != 0)
    {
      retcode = 2;
      goto end;
    }

    memcpy(&next_block, block_data, sizeof(xex_opt::XexDataDescriptor));
    uint8_t* p = block_data + sizeof(xex_opt::XexDataDescriptor);
    while (true)
    {
      uint16_t comp_size = *(uint16_t*)p;
      p += 2;
      if (!comp_size)
        break;

      comp_size = swap16(comp_size);
      if (comp_size > 0x9800) // sanity check: shouldn't be above 0x9800
      {
        retcode = 1;
        goto end;
      }
      // Read in LZX buffer
      memcpy(comp_buffer, p, comp_size);
      p += comp_size;
      if (comp_size < 0x9800) // if comp. size is below buffer size 0x9800, zero out the remainder of the buffer
        memset(comp_buffer + comp_size, 0, 0x9800 - comp_size);

      // Decompress!
      auto dec_size = size_left < 0x8000 ? size_left : 0x8000;
      retcode = LZXdecompress(comp_buffer, pe_data_.data() + size_done, comp_size, dec_size);
      if (retcode != 0)
        goto end;

      size_done += dec_size;
      size_left -= dec_size;
    }
    memcpy(cur_block, &next_block, sizeof(xex_opt::XexDataDescriptor));

    free(block_data);
    block_data = 0;
  }

end:
  if (block_data)
    free(block_data);

  free(comp_buffer);

  if (retcode != 0)
    dbgmsg("[!] read_basefile_decompressed error code = %d!\n", retcode);

  return retcode == 0;
}

// Reads import libraries & function info from PE headers
bool XEXFile::pe_load_imports(const uint8_t* data)
{
  IMAGE_DOS_HEADER* dos_header = (IMAGE_DOS_HEADER*)data;
  if (dos_header->MZSignature != EXE_MZ_SIGNATURE)
    return false;

  IMAGE_NT_HEADERS* nt_header = (IMAGE_NT_HEADERS*)(data + dos_header->AddressOfNewExeHeader);
  if (nt_header->Signature != EXE_NT_SIGNATURE)
    return false;

  auto imports_addr = pe_rva_to_offset(nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
  if (!imports_addr)
    return false;

  // Loop through import descriptors...
  auto* import_desc = (IMAGE_IMPORT_DESCRIPTOR*)(data + imports_addr);
  while (import_desc->FirstThunk)
  {
    auto module_name_addr = pe_rva_to_offset(import_desc->Name);
    if (!module_name_addr)
      continue;

    char* libname = (char*)(data + module_name_addr);

    imports_addr = pe_rva_to_offset(import_desc->FirstThunk);
    if (!imports_addr)
      continue;

    if (!imports_.count(libname))
      imports_[libname] = std::map<uint32_t, XEXFunction>();

    // Loop through imports...
    uint32_t import_offset = 0;
    auto* import_data = (uint32_t*)(data + imports_addr);
    while (*import_data)
    {
      auto ordinal = *import_data & 0xFFFF;

      XEXFunction imp;
      if (imports_[libname].count(ordinal))
        imp = imports_[libname][ordinal];

      imp.ThunkAddr = base_address_ + import_desc->FirstThunk + import_offset;

      imports_[libname][ordinal] = imp;
      import_offset += 4;

      // todo: search code for references to ThunkAddr
    }

    import_desc++;
  }

  return true;
}

// Reads function info defined inside PE headers
bool XEXFile::pe_load_exports(const uint8_t* data)
{
  IMAGE_DOS_HEADER* dos_header = (IMAGE_DOS_HEADER*)data;
  if (dos_header->MZSignature != EXE_MZ_SIGNATURE)
    return false;

  IMAGE_NT_HEADERS* nt_header = (IMAGE_NT_HEADERS*)(data + dos_header->AddressOfNewExeHeader);
  if (nt_header->Signature != EXE_NT_SIGNATURE)
    return false;

  auto exports_addr = pe_rva_to_offset(nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
  if (!exports_addr)
    return false;

  auto* exports_desc = (IMAGE_EXPORT_DIRECTORY*)(data + exports_addr);

  auto module_name_addr = pe_rva_to_offset(exports_desc->Name);
  if (!module_name_addr)
    return false;

  exports_libname_ = (char*)(data + module_name_addr);
  auto exports_ptr_addr = pe_rva_to_offset(exports_desc->AddressOfFunctions);
  for (int i = 0; i < exports_desc->NumberOfFunctions; i++)
  {
    auto ordinal = exports_desc->Base + i;
    XEXFunction exp;
    if (exports_.count(ordinal))
      exp = exports_[ordinal];

    exp.ThunkAddr = base_address_ + exports_desc->AddressOfFunctions + (i * 4);
    exp.FuncAddr = *(uint32*)(data + exports_ptr_addr + (i * 4));
    if (!exp.FuncAddr)
      continue;

    exp.FuncAddr += base_address_;

    exports_[ordinal] = exp;
  }

  return true;
}

// Reads information from PE headers (section info, entrypoint, base addr...)
bool XEXFile::pe_load(const uint8_t* data)
{
  IMAGE_DOS_HEADER* dos_header = (IMAGE_DOS_HEADER*)data;
  if (dos_header->MZSignature != EXE_MZ_SIGNATURE)
    return false;

  IMAGE_NT_HEADERS* nt_header = (IMAGE_NT_HEADERS*)(data + dos_header->AddressOfNewExeHeader);
  if (nt_header->Signature != EXE_NT_SIGNATURE)
    return false;

  // Get base address/entrypoint from optionalheader if we don't already have them
  if (!base_address_)
    base_address_ = nt_header->OptionalHeader.ImageBase;

  if (!entry_point_)
    entry_point_ = base_address_ + nt_header->OptionalHeader.AddressOfEntryPoint;

  // Read in PE sections
  IMAGE_SECTION_HEADER* sects = (IMAGE_SECTION_HEADER*)(data +
    dos_header->AddressOfNewExeHeader +
    sizeof(IMAGE_NT_HEADERS));

  for (int i = 0; i < nt_header->FileHeader.NumberOfSections; i++)
    sections_.push_back(sects[i]);

  if (xex_header_.Magic == MAGIC_XEX3F)
  {
    if (nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size)
      pe_load_imports(data);

    if (nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size)
      pe_load_exports(data);
  }

  return true;
}

// Converts an RVA into a file offset
uint32_t XEXFile::pe_rva_to_offset(uint32_t rva)
{
  if (rva > base_address_)
    rva -= base_address_;
  if (xex_header_.Magic != MAGIC_XEX3F)
    return rva; // all formats besides XEX3F seem to keep raw data lined up with in-memory PE?

  for (auto section : sections_)
  {
    if (rva >= section.VirtualAddress && rva < section.VirtualAddress + section.VirtualSize)
      return rva - section.VirtualAddress + section.PointerToRawData;
  }

  return 0;
}

uint32_t XEXFile::opt_header(uint32_t id)
{
  if (!directory_entries_.count(id))
    return 0;
  
  return directory_entries_[id];
}

void* XEXFile::opt_header_ptr(uint32_t id)
{
  auto val = opt_header(id);
  if (!val)
    return 0;

  // TODO: check if the value is stored in the directory_entries_ section
  // and return pointer to it if so?

  return xex_headers_.data() + val;
}

// Reads in, decrypts, decompresses & verifies the basefile from the XEX image
bool XEXFile::read_basefile(void* file, int key_index)
{
  xex_opt::XexDataFormat comp_format = xex_opt::XexDataFormat::None;
  uint16_t enc_flag = 0;

  // Read compression/encryption info from data descriptor header if we have one
  if (data_descriptor_)
  {
    comp_format = (xex_opt::XexDataFormat)(uint16_t)data_descriptor_->Format;
    enc_flag = data_descriptor_->Flags;
  }

  key_index_ = key_index;
  if (key_index == 0) // only print this on first invocation of read_basefile
  {
    char* format = "Raw";
    if (comp_format == xex_opt::XexDataFormat::Compressed)
      format = "Compressed";
    else if (comp_format == xex_opt::XexDataFormat::DeltaCompressed)
      format = "Delta Compressed";
    else if (comp_format == xex_opt::XexDataFormat::Raw)
      format = "Not Compressed";

    dbgmsg("[+] %s\n", format);
    dbgmsg("[+] %s\n", (enc_flag != 0) ? "Encrypted" : "Not Encrypted");
  }

  // Setup session key
  if (enc_flag)
  {
    dbgmsg("[+] Attempting decrypt with %s key...\n", key_names[key_index]);
    memcpy(session_key_, image_key_, 0x10);
    AES_ctx key_ctx;
    AES_init_ctx(&key_ctx, key_bytes[key_index]);
    AES_ECB_decrypt(&key_ctx, session_key_);
  }

  bool result = false;
  if (comp_format == xex_opt::XexDataFormat::None)
    result = read_basefile_raw(file, enc_flag);
  else if (comp_format == xex_opt::XexDataFormat::Raw)
    result = read_basefile_uncompressed(file, enc_flag);
  else if (comp_format == xex_opt::XexDataFormat::Compressed)
    result = read_basefile_compressed(file, enc_flag);
  else
  {
    dbgmsg("[!] Error: XEX uses invalid compression format %hd!\n", (uint16_t)comp_format);
    result = false;
  }

  // if reading was "successful", validate the basefiles magic
  if (result)
    return VerifyBaseFileHeader(pe_data_.data());

  return result;
}

// Shim function to allow using IDA's qlread function
size_t idaread(void* buffer, size_t element_size, size_t element_count, void* file)
{
  return qlread((linput_t*)file, buffer, element_size * element_count);
}

// Shim function to allow using vprintf cstdio function
int stdio_msg(const char* format, ...)
{
  va_list argp;
  va_start(argp, format);

  int retval = vprintf(format, argp);

  va_end(argp);

  return retval;
}

void XEXFile::use_ida_io()
{
#if fread == dont_use_fread
  read = idaread;
  seek = (seek_fn)qlseek;
  tell = (tell_fn)qltell;
  dbgmsg = msg;
#endif
}