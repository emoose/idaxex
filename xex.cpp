// TODO:
// - XEX1 and older
// - improve speed of file load
// - label __savegprlr_* and __restgprlr_*
// - add more checks to things
// - find reason why IDA refuses to analyze entire chunks of code (temp fix atm by marking code manually inside pe_add_section, seems xorloser loader doesn't need to do this though...)
// - find why data references aren't being XREF'd (eg instead of "lis r11, unk_83BA5600@h" we get "lis r11, -0x7C46"...)
// - test!

#include "../idaldr.h"
#include "xex.hpp"
#include <typeinf.hpp>
#include <bytes.hpp>
#include <algorithm>
#include <vector>
#include <algorithm>
#include "lzx/lzx.hpp"
#include "aes.hpp"
#include "sha1.hpp"

#define FF_WORD     0x10000000 // why doesn't this get included from ida headers?

std::string DoNameGen(const std::string& libName, int id); // namegen.cpp

const uint8 retail_key[16] = {
  0x20, 0xB1, 0x85, 0xA5, 0x9D, 0x28, 0xFD, 0xC3,
  0x40, 0x58, 0x3F, 0xBB, 0x08, 0x96, 0xBF, 0x91
};
const uint8 devkit_key[16] = {
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};
// unsure if any of the xex1 keys get used, we'll still try them as last resort anyway
const uint8 retail_key_xex1[16] = {
  0xA2, 0x6C, 0x10, 0xF7, 0x1F, 0xD9, 0x35, 0xE9,
  0x8B, 0x99, 0x92, 0x2C, 0xE9, 0x32, 0x15, 0x72
};
const uint8 devkit_key_xex1[16] = {
  0xA8, 0xB0, 0x05, 0x12, 0xED, 0xE3, 0x63, 0x8D,
  0xC6, 0x58, 0xB3, 0x10, 0x1F, 0x9F, 0x50, 0xD1
};

const uint8* key_bytes[4] = {
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

IMAGE_XEX_HEADER xex_header;
XEX2_SECURITY_INFO security_info;
std::map<uint32, uint32> directory_entries;
XEX_FILE_DATA_DESCRIPTOR data_descriptor;

int64 data_length = 0;
uint32 base_address = 0;
uint32 entry_point = 0;
uint32 export_table_va = 0;

uint8 session_key[16];

void pe_add_section(const IMAGE_SECTION_HEADER& section)
{
  uint32 seg_perms = 0;
  if (section.Characteristics & IMAGE_SCN_MEM_EXECUTE)
    seg_perms |= SEGPERM_EXEC;
  if (section.Characteristics & IMAGE_SCN_MEM_READ)
    seg_perms |= SEGPERM_READ;
  if (section.Characteristics & IMAGE_SCN_MEM_WRITE)
    seg_perms |= SEGPERM_WRITE;

  bool has_code = (section.Characteristics & IMAGE_SCN_CNT_CODE);
  bool has_data = (section.Characteristics & IMAGE_SCN_CNT_INITIALIZED_DATA) || (section.Characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA);

  char* seg_class = has_code ? "CODE" : "DATA";
  uint32 seg_addr = base_address + section.VirtualAddress;

  // Create buffer for section name so we can terminate it properly
  char name[9];
  memset(name, 0, 9);
  memcpy(name, section.Name, 8);

  segment_t segm;
  segm.start_ea = seg_addr;
  segm.end_ea = seg_addr + section.VirtualSize;
  segm.align = saRelPara;
  segm.perm = seg_perms;
  add_segm_ex(&segm, name, seg_class, 0);

  // some reason IDA is refusing to analyze entire chunks of code
  // so we'll mark the whole segment as code if we're sure there's no data
  // drastic times call for drastic measures...
  if (has_code && !has_data)
    for (ea_t i = segm.start_ea; i < segm.end_ea; i += 4)
      auto_make_code(i);
}

bool pe_load(uint8* data)
{
  IMAGE_DOS_HEADER* dos_header = (IMAGE_DOS_HEADER*)data;
  if (dos_header->MZSignature != EXE_MZ_SIGNATURE)
    return false;

  IMAGE_NT_HEADERS* nt_header = (IMAGE_NT_HEADERS*)(data + dos_header->AddressOfNewExeHeader);
  if (nt_header->Signature != EXE_NT_SIGNATURE)
    return false;

  // Get base address/entrypoint from optionalheader if we don't already have them
  if (!base_address)
    base_address = nt_header->OptionalHeader.ImageBase;

  if (!entry_point)
    entry_point = base_address + nt_header->OptionalHeader.AddressOfEntryPoint;

  IMAGE_SECTION_HEADER* sections = (IMAGE_SECTION_HEADER*)(data + 
                                                           dos_header->AddressOfNewExeHeader + 
                                                           sizeof(IMAGE_NT_HEADERS) + 
                                                           (nt_header->OptionalHeader.NumberOfRvaAndSizes * 8)); // skip past data directories (for now? will we ever need them?)

  // Read in PE sections & copy section data into IDA
  for (int i = 0; i < nt_header->FileHeader.NumberOfSections; i++)
  {
    auto& section = sections[i];

    uint32 sec_addr = section.VirtualAddress; // if xex_magic != _MAGIC_XEX3F else section.PointerToRawData
    int sec_size = std::min(section.VirtualSize, section.SizeOfRawData);

    if (sec_addr + sec_size > security_info.ImageSize)
      sec_size = security_info.ImageSize - sec_addr;

    // Add section as IDA segment
    pe_add_section(section);

    if (sec_size <= 0)
      continue;

    // Load data into IDA
    mem2base(data + sec_addr, base_address + section.VirtualAddress, base_address + section.VirtualAddress + sec_size, -1);
  }

  if (entry_point)
    add_entry(0, entry_point, "start", 1);

  return true;
}

bool xex_read_uncompressed(linput_t* li, bool encrypted)
{
  int num_blocks = (data_descriptor.Size - 8) / 8;
  auto* xex_blocks = (XEX_RAW_DATA_DESCRIPTOR*)calloc(num_blocks, sizeof(XEX_RAW_DATA_DESCRIPTOR));
  qlseek(li, directory_entries[XEX_FILE_DATA_DESCRIPTOR_HEADER] + 8);
  qlread(li, xex_blocks, num_blocks * sizeof(XEX_RAW_DATA_DESCRIPTOR));

  AES_ctx aes;
  uint8 iv[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
  };

  if (encrypted)
    AES_init_ctx_iv(&aes, session_key, iv);

  uint8* pe_data = (uint8*)malloc(security_info.ImageSize);
  uint32_t position = 0;
  qlseek(li, xex_header.SizeOfHeaders);
  for (int i = 0; i < num_blocks; i++)
  {
    xex_blocks[i].DataSize = swap32(xex_blocks[i].DataSize);
    xex_blocks[i].ZeroSize = swap32(xex_blocks[i].ZeroSize);

    // if it's the first block & encrypted, we'll test-decrypt the first 16 bytes
    // so we can test if it decrypted properly with this key, without needing to process the entire block
    if (i == 0 && encrypted)
    {
      // Read first 16 bytes of block and decrypt
      auto pos = qltell(li);
      qlread(li, pe_data, 0x10);
      AES_ECB_decrypt(&aes, pe_data);

      // Check MZ signature
      uint16 pe_sig = *(uint16*)pe_data;
      if (pe_sig != EXE_MZ_SIGNATURE)
      {
        free(pe_data);
        return false;
      }

      // Reinit AES & seek back to start of block
      AES_init_ctx_iv(&aes, session_key, iv);
      qlseek(li, pos);
    }

    qlread(li, pe_data + position, xex_blocks[i].DataSize);

    if (encrypted)
      AES_CBC_decrypt_buffer(&aes, pe_data + position, xex_blocks[i].DataSize);

    position += xex_blocks[i].DataSize;
    memset(pe_data + position, 0, xex_blocks[i].ZeroSize);
    position += xex_blocks[i].ZeroSize;
  }
  // todo: verify block size sum == ImageSize ?

  auto result = pe_load(pe_data);
  free(pe_data);

  return result;
}

bool xex_read_compressed(linput_t* li, bool encrypted)
{
  AES_ctx aes;
  if (encrypted)
  {
    uint8 iv[] = {
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };
    AES_init_ctx_iv(&aes, session_key, iv);
  }

  // read windowsize & first block from file_data_descriptor header
  auto* compression_info = (XEX_COMPRESSED_DATA_DESCRIPTOR*)malloc(sizeof(XEX_COMPRESSED_DATA_DESCRIPTOR));
  qlseek(li, directory_entries[XEX_FILE_DATA_DESCRIPTOR_HEADER] + 8);
  qlread(li, compression_info, sizeof(XEX_COMPRESSED_DATA_DESCRIPTOR));
  compression_info->WindowSize = swap32(compression_info->WindowSize);

  auto* cur_block = &compression_info->FirstDescriptor;
  cur_block->Size = swap32(cur_block->Size);

  // Alloc memory for the PE
  uint8* pe_data = (uint8*)malloc(security_info.ImageSize);

  // LZX init...
  LZXinit(compression_info->WindowSize);
  uint8* comp_buffer = (uint8*)malloc(0x9800); // 0x9800 = max comp. block size (0x8000) + MAX_GROWTH (0x1800)

  uint32 size_left = security_info.ImageSize;
  uint32 size_done = 0;
  int retcode = 0;

  // Start decompressing
  SHA1Context sha_state;
  qlseek(li, xex_header.SizeOfHeaders);
  XEX_DATA_DESCRIPTOR next_block;
  uint8* block_data = 0;
  while (cur_block->Size)
  {
    block_data = (uint8*)malloc(cur_block->Size);
    qlread(li, block_data, cur_block->Size);

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

    memcpy(&next_block, block_data, sizeof(XEX_DATA_DESCRIPTOR));
    next_block.Size = swap32(next_block.Size);
    uint8* p = block_data + sizeof(XEX_DATA_DESCRIPTOR);
    while (true)
    {
      uint16 comp_size = *(uint16*)p;
      p += 2;
      if (!comp_size)
        break;

      comp_size = swap16(comp_size);
      if (comp_size > 0x8000) // sanity check: shouldn't be above 0x8000
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
      uint32 dec_size = size_left < 0x8000 ? size_left : 0x8000;
      retcode = LZXdecompress(comp_buffer, pe_data + size_done, comp_size, dec_size);
      if (retcode != 0)
        goto end;

      size_done += dec_size;
      size_left -= dec_size;
    }
    memcpy(cur_block, &next_block, sizeof(XEX_DATA_DESCRIPTOR));

    free(block_data);
    block_data = 0;
  }

end:
  if (block_data)
    free(block_data);

  free(compression_info);
  free(comp_buffer);

  bool result = false;
  if (retcode == 0)
    result = pe_load(pe_data);

  free(pe_data);
  return result;
}

bool xex_read_image(linput_t* li, int key_index)
{
  int comp_format = 0;
  int enc_flag = 0;

  // Read compression/encryption info from data descriptor header if we have one
  if (directory_entries.count(XEX_FILE_DATA_DESCRIPTOR_HEADER))
  {
    qlseek(li, directory_entries[XEX_FILE_DATA_DESCRIPTOR_HEADER]);
    qlread(li, &data_descriptor, sizeof(XEX_FILE_DATA_DESCRIPTOR));

    data_descriptor.Size = swap32(data_descriptor.Size);
    comp_format = data_descriptor.Format = swap16(data_descriptor.Format);
    enc_flag = data_descriptor.Flags = swap16(data_descriptor.Flags);
  }

  // Setup session key
  if (enc_flag)
  {
    memcpy(session_key, security_info.ImageInfo.ImageKey, 0x10);
    AES_ctx key_ctx;
    AES_init_ctx(&key_ctx, key_bytes[key_index]);
    AES_ECB_decrypt(&key_ctx, session_key);
  }

  bool result = false;
  if (comp_format == 1)
    result = xex_read_uncompressed(li, enc_flag);
  else if (comp_format == 2)
    result = xex_read_compressed(li, enc_flag);
  else
    warning("xex_read_image: Unhandled XEX compression format %d!", comp_format);

  if(result && enc_flag)
    msg("[+] Decrypted successfully using %s key!\n", key_names[key_index]);

  return result;
}

void xex_load_imports(linput_t* li)
{
  if (!directory_entries.count(XEX_HEADER_IMPORTS))
    return;

  if (!directory_entries[XEX_HEADER_IMPORTS])
    return;

  XEX_IMPORT_DESCRIPTOR import_desc;
  qlseek(li, directory_entries[XEX_HEADER_IMPORTS]);
  qlread(li, &import_desc, sizeof(XEX_IMPORT_DESCRIPTOR));
  import_desc.ModuleCount = swap32(import_desc.ModuleCount);
  import_desc.NameTableSize = swap32(import_desc.NameTableSize);
  import_desc.Size = swap32(import_desc.Size);

  // Seperate the library names in the name table
  std::vector<std::string> import_libs;
  std::string cur_lib = "";
  for (int i = 0; i < import_desc.NameTableSize; i++)
  {
    if(!cur_lib.length())
    {
      // align to 4 bytes
      if ((i % 4) != 0)
      {
        int align = 4 - (i % 4);
        align = std::min(align, (int)import_desc.NameTableSize - i); // don't let us align past end of nametable
        i += align - 1; // minus 1 since for loop will add 1 to it too
        qlseek(li, align, SEEK_CUR);

        continue;
      }
    }

    char name_char;
    qlread(li, &name_char, 1);

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

  msg("[+] Loading module imports... (%d import modules)\n", import_desc.ModuleCount);

  // Read in each import library
  for (int i = 0; i < import_desc.ModuleCount; i++)
  {
    // Create netcode for this module, used for populating imports window
    netnode module_node;
    module_node.create();

    // Read in import table header
    auto table_addr = qltell(li);
    XEX_IMPORT_TABLE table_header;
    qlread(li, &table_header, sizeof(XEX_IMPORT_TABLE));
    table_header.TableSize = swap32(table_header.TableSize);
    table_header.ImportCount = swap16(table_header.ImportCount);

    auto& libname = import_libs.at(table_header.ModuleIndex);

    // track variable imports so we can rename them later
    // (all imports have a "variable" type, but only functions have a "thunk" type)
    // (so we add the import to variable list when variable type is loaded, but then remove it if a thunk for that import gets loaded)
    std::map<int, ea_t> variables;
    std::map<int, ea_t> import_ea;

    // Loop through table entries
    for (int j = 0; j < table_header.ImportCount; j++)
    {
      uint32 record_addr;
      qlread(li, &record_addr, sizeof(uint32));
      record_addr = swap32(record_addr);

      auto record_value = get_dword(record_addr);
      auto record_type = (record_value & 0xFF000000) >> 24;
      auto ordinal = record_value & 0xFFFF;

      auto import_name = DoNameGen(libname, ordinal);
      if (record_type == 0)
      {
        // variable
        create_data(record_addr, FF_WORD, 2 * 2, BADADDR);
        set_name(record_addr, ("__imp__" + import_name).c_str());
        variables[ordinal] = record_addr;
        import_ea[ordinal] = record_addr;
      }
      else if (record_type == 1)
      {
        // thunk
        // have to rewrite code to set r3 & r4 like xorlosers loader does
        // r3 = module index afaik
        // r4 = ordinal
        // important to note that basefiles extracted via xextool have this rewrite done already, but raw basefile from XEX doesn't!
        // todo: find out how to add to imports window like xorloser loader...

        put_dword(record_addr + 0, 0x38600000 | table_header.ModuleIndex);
        put_dword(record_addr + 4, 0x38800000 | ordinal);
        set_name(record_addr, import_name.c_str());

        // add comment to thunk like xorloser's loader
        set_cmt(record_addr + 4, qstring().sprnt("%s :: %s", libname.c_str(), import_name.c_str()).c_str(), 1);

        // force IDA to recognize addr as code, so we can add it as a library function
        auto_make_code(record_addr);
        auto_recreate_insn(record_addr);
        func_t func(record_addr, record_addr + 0x10, FUNC_LIB);
        add_func_ex(&func);

        // thunk means this isn't a variable, remove from our variables map
        if (variables.count(ordinal))
          variables.erase(ordinal);

        import_ea[ordinal] = record_addr;
      }
      else
        msg("[+] %s import %d (%s) (@ 0x%X) unknown type %d!\n", libname.c_str(), ordinal, import_name, record_addr, record_type);
    }

    // Imports window setup
    for (auto kvp : import_ea)
    {
      // Set import name
      auto import_name = DoNameGen(libname, kvp.first);
      module_node.supset_ea(kvp.second, import_name.c_str());

      // Set import ordinal
      nodeidx_t ndx = ea2node(kvp.second);
      module_node.altset(kvp.first, ndx);
    }

    // Add module to imports window
    import_module(libname.c_str(), NULL, module_node, NULL, "x360");

    // Remove "__imp__" part from variable import names
    for (auto kvp : variables)
    {
      auto import_name = DoNameGen(libname, kvp.first);
      set_name(kvp.second, import_name.c_str());
    }

    // Seek to end of this import table
    qlseek(li, table_addr + table_header.TableSize);
  }
}

void xex_load_exports()
{
  if (!export_table_va)
    return;

  HV_IMAGE_EXPORT_TABLE export_table;
  get_bytes(&export_table, sizeof(HV_IMAGE_EXPORT_TABLE), export_table_va);
  export_table.Magic[0] = swap32(export_table.Magic[0]);
  export_table.Magic[1] = swap32(export_table.Magic[1]);
  export_table.Magic[2] = swap32(export_table.Magic[2]);
  export_table.Count = swap32(export_table.Count);
  export_table.Base = swap32(export_table.Base);
  export_table.ImageBaseAddress = swap32(export_table.ImageBaseAddress);

  if (export_table.Magic[0] != XEX_EXPORT_MAGIC_0 ||
    export_table.Magic[1] != XEX_EXPORT_MAGIC_1 ||
    export_table.Magic[2] != XEX_EXPORT_MAGIC_2)
  {
    msg("[+] Export table magic is invalid! (0x%X 0x%X 0x%X)\n", export_table.Magic[0], export_table.Magic[1], export_table.Magic[2]);
    return;
  }

  msg("[+] Loading module exports...\n");
  char module_name[256];
  get_root_filename(module_name, 256);

  auto ordinal_addrs_va = export_table_va + sizeof(HV_IMAGE_EXPORT_TABLE);
  for (int i = 0; i < export_table.Count; i++)
  {
    auto func_ord = export_table.Base + i;
    auto func_va = get_dword(ordinal_addrs_va + (i * 4));
    if (!func_va)
      continue;

    func_va += (export_table.ImageBaseAddress << 16);
    auto func_name = DoNameGen(module_name, func_ord);

    // Add to exports list & mark as func if inside a code section
    qstring func_segmclass;
    get_segm_class(&func_segmclass, getseg(func_va));

    bool func_iscode = func_segmclass == "CODE";
    add_entry(func_ord, func_va, func_name.c_str(), func_iscode);
    if (func_iscode)
      add_func(func_va); // make doubly sure it gets marked as code
  }
}

//------------------------------------------------------------------------------
void idaapi load_file(linput_t *li, ushort /*_neflags*/, const char * /*fileformatname*/)
{
  set_processor_type("ppc", SETPROC_LOADER);
  set_compiler_id(COMP_MS);

  inf.baseaddr = 0;
  ea_t start = to_ea(inf.baseaddr, 0);
  ea_t end = start;

  int64 fsize = qlsize(li);
  qlseek(li, 0);

  auto read = qlread(li, &xex_header, sizeof(IMAGE_XEX_HEADER));

  // byteswap xex_header
  xex_header.Magic = swap32(xex_header.Magic);
  xex_header.ModuleFlags = swap32(xex_header.ModuleFlags);
  xex_header.SizeOfHeaders = swap32(xex_header.SizeOfHeaders);
  xex_header.SizeOfDiscardableHeaders = swap32(xex_header.SizeOfDiscardableHeaders);
  xex_header.SecurityInfo = swap32(xex_header.SecurityInfo);
  xex_header.HeaderDirectoryEntryCount = swap32(xex_header.HeaderDirectoryEntryCount);

  data_length = fsize - xex_header.SizeOfHeaders;

  // Read in directory entry / optional header keyvalues
  for (int i = 0; i < xex_header.HeaderDirectoryEntryCount; i++)
  {
    IMAGE_XEX_DIRECTORY_ENTRY header;
    read = qlread(li, &header, sizeof(IMAGE_XEX_DIRECTORY_ENTRY));
    header.Key = swap32(header.Key);
    header.Value = swap32(header.Value);

    directory_entries[header.Key] = header.Value;
  }

  // Read in SecurityInfo
  qlseek(li, xex_header.SecurityInfo);
  read = qlread(li, &security_info, sizeof(XEX2_SECURITY_INFO));
  security_info.ImageSize = swap32(security_info.ImageSize);

  base_address = security_info.ImageInfo.LoadAddress = swap32(security_info.ImageInfo.LoadAddress);
  export_table_va = security_info.ImageInfo.ExportTableAddress = swap32(security_info.ImageInfo.ExportTableAddress);

  // todo: should we actually be using the PE_BASE header?
  if (directory_entries.count(XEX_HEADER_PE_BASE))
    base_address = directory_entries[XEX_HEADER_PE_BASE];

  if (directory_entries.count(XEX_HEADER_ENTRY_POINT))
    entry_point = directory_entries[XEX_HEADER_ENTRY_POINT];

  // Try decrypting with all 4 keys
  if (!xex_read_image(li, 0) && !xex_read_image(li, 1) && !xex_read_image(li, 2) && !xex_read_image(li, 3))
  {
    msg("[+] Failed to load PE image from XEX :(\n");
    return;
  }

  // basefile loaded!

  // Setup imports & exports if we have them
  if (directory_entries.count(XEX_HEADER_IMPORTS))
    xex_load_imports(li);

  if (export_table_va)
    xex_load_exports();

  // Done :)
  msg("[+] XEX loaded, voila!\n");
  return;
}

//--------------------------------------------------------------------------
static int idaapi accept_file(
        qstring *fileformatname,
        qstring *processor,
        linput_t *li,
        const char *)
{
  qlseek(li, 0);
  uint32 type;
  if ( qlread(li, &type, sizeof(uint32)) == sizeof(uint32)
    && type == XEX2_MAGIC )
  {
    *fileformatname = "Xbox360 XEX File";
    *processor      = "PPC";
    return 1;
  }
  return 0;
}

//--------------------------------------------------------------------------
loader_t LDSC =
{
  IDP_INTERFACE_VERSION,
  0,                            // loader flags
//
//      check input file format. if recognized, then return 1
//      and fill 'fileformatname'.
//      otherwise return 0
//
  accept_file,
//
//      load file into the database.
//
  load_file,
//
//      create output file from the database.
//      this function may be absent.
//
  NULL,
//      take care of a moved segment (fix up relocations, for example)
  NULL,
  NULL,
};
