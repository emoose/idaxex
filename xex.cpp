// TODO:
// - encryption support
// - add imports to imports window
// - test export labelling
// - create generic names for imports/exports we can't find (eg whateverLibrary_0001)
// - test!

#include "../idaldr.h"
#include "xex.hpp"
#include <typeinf.hpp>
#include <bytes.hpp>
#include <algorithm>
#include <vector>

extern "C" { 
#include "lzx/lzx.h"
}

#define FF_WORD     0x10000000 // why doesn't this get included from ida headers?

const char* DoNameGen(const char* libName, int id); // namegen.cpp

const uint8 retail_key[16] = {
  0x20, 0xB1, 0x85, 0xA5, 0x9D, 0x28, 0xFD, 0xC3,
  0x40, 0x58, 0x3F, 0xBB, 0x08, 0x96, 0xBF, 0x91
};
const uint8 devkit_key[16] = {
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};
const uint8 unused_key[16] = { // aka "XEX1 key", never seen it used, we'll try using it as last resort though
  0xA2, 0x6C, 0x10, 0xF7, 0x1F, 0xD9, 0x35, 0xE9,
  0x8B, 0x99, 0x92, 0x2C, 0xE9, 0x32, 0x15, 0x72
};

const uint8* key_bytes[3] = {
  retail_key,
  devkit_key,
  unused_key
};
const char* key_names[3] = {
  "retail",
  "devkit",
  "XEX1"
};

IMAGE_XEX_HEADER xex_header;
XEX2_SECURITY_INFO security_info;
std::map<uint32, uint32> directory_entries;
XEX_FILE_DATA_DESCRIPTOR data_descriptor;

int64 data_length = 0;
uint32 base_address = 0;
uint32 entry_point = 0;
uint32 export_table_va = 0;

void pe_add_section(const IMAGE_SECTION_HEADER& section)
{
  uint32 seg_perms = 0;
  if (section.Characteristics & IMAGE_SCN_MEM_EXECUTE)
    seg_perms |= SEGPERM_EXEC;
  if (section.Characteristics & IMAGE_SCN_MEM_READ)
    seg_perms |= SEGPERM_READ;
  if (section.Characteristics & IMAGE_SCN_MEM_WRITE)
    seg_perms |= SEGPERM_WRITE;

  char* seg_class = (section.Characteristics & IMAGE_SCN_CNT_CODE) ? "CODE" : "DATA";
  uint32 seg_addr = base_address + section.VirtualAddress;

  add_segm(0, seg_addr, seg_addr + section.VirtualSize, section.Name, seg_class);
  //idc.set_segm_alignment(seg_addr, idc.saRelPara)
  //idc.set_segm_attr(seg_addr, idc.SEGATTR_PERM, seg_perms)
  //idc.set_default_sreg_value(seg_addr, "DS", 0) # how is DS meant to be set ? prolly don't matter but still
  //idc.set_default_sreg_value(seg_addr, "VLE", 0)
}

bool pe_load(uint8* data)
{
  IMAGE_DOS_HEADER* dos_header = (IMAGE_DOS_HEADER*)data;
  if (dos_header->MZSignature != 0x5A4D)
    return false;

  IMAGE_NT_HEADERS* nt_header = (IMAGE_NT_HEADERS*)(data + dos_header->AddressOfNewExeHeader);
  if (nt_header->Signature != 0x4550)
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

  for (int i = 0; i < nt_header->FileHeader.NumberOfSections; i++)
  {
    auto& section = sections[i];

    uint32 sec_addr = section.VirtualAddress; // if xex_magic != _MAGIC_XEX3F else section.PointerToRawData
    int sec_size = std::min(section.VirtualSize, section.SizeOfRawData);

    if (sec_addr + sec_size > security_info.ImageSize)
      sec_size = security_info.ImageSize - sec_addr;

    if (sec_size <= 0)
      continue;

    // Add section as IDA segment
    pe_add_section(section);

    // Load data into IDA
    mem2base(data + sec_addr, base_address + section.VirtualAddress, base_address + section.VirtualAddress + section.VirtualSize, -1);
  }

  if (entry_point)
    add_entry(0, entry_point, "start", 1);

  return true;
}

bool xex_read_uncompressed(linput_t* li)
{
  int num_blocks = (data_descriptor.Size - 8) / 8;
  auto* xex_blocks = (XEX_RAW_DATA_DESCRIPTOR*)calloc(num_blocks, sizeof(XEX_RAW_DATA_DESCRIPTOR));
  qlseek(li, directory_entries[XEX_FILE_DATA_DESCRIPTOR_HEADER] + 8);
  qlread(li, xex_blocks, num_blocks * sizeof(XEX_RAW_DATA_DESCRIPTOR));

  qlseek(li, xex_header.SizeOfHeaders);

  uint8* pe_data = (uint8*)malloc(security_info.ImageSize);
  uint32_t position = 0;
  for (int i = 0; i < num_blocks; i++)
  {
    xex_blocks[i].DataSize = swap32(xex_blocks[i].DataSize);
    xex_blocks[i].ZeroSize = swap32(xex_blocks[i].ZeroSize);

    qlread(li, pe_data + position, xex_blocks[i].DataSize);
    position += xex_blocks[i].DataSize;
    memset(pe_data + position, 0, xex_blocks[i].ZeroSize);
    position += xex_blocks[i].ZeroSize;
  }
  // todo: verify block size sum == ImageSize ?

  auto result = pe_load(pe_data);
  free(pe_data);

  return result;
}

bool xex_read_compressed(linput_t* li)
{
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
  qlseek(li, xex_header.SizeOfHeaders);
  XEX_DATA_DESCRIPTOR next_block;
  while (cur_block->Size)
  {
    auto cur_addr = qltell(li);
    qlread(li, &next_block, sizeof(XEX_DATA_DESCRIPTOR));
    next_block.Size = swap32(next_block.Size);
    while (true)
    {
      uint16 comp_size;
      qlread(li, &comp_size, sizeof(uint16));

      if (!comp_size)
        break;

      comp_size = swap16(comp_size);
      if (comp_size > 0x8000) // sanity check: shouldn't be above 0x8000
      {
        retcode = 1;
        goto end;
      }
      
      // Read in LZX buffer
      qlread(li, comp_buffer, comp_size);
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
    qlseek(li, cur_addr + cur_block->Size);
    memcpy(cur_block, &next_block, sizeof(XEX_DATA_DESCRIPTOR));
  }

end:
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
  if (directory_entries.count(XEX_FILE_DATA_DESCRIPTOR_HEADER))
  {
    qlseek(li, directory_entries[XEX_FILE_DATA_DESCRIPTOR_HEADER]);
    qlread(li, &data_descriptor, sizeof(XEX_FILE_DATA_DESCRIPTOR));

    data_descriptor.Size = swap32(data_descriptor.Size);
    comp_format = data_descriptor.Format = swap16(data_descriptor.Format);
    enc_flag = data_descriptor.Flags = swap16(data_descriptor.Flags);
  }

  // todo: setup session_key here

  if (comp_format == 1)
    return xex_read_uncompressed(li);
  else if (comp_format == 2)
    return xex_read_compressed(li);

  return false;
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

  // seperate the library names in the name table
  std::vector<std::string> import_libs;
  std::string cur_lib = "";
  for (int i = 0; i < import_desc.NameTableSize; i++)
  {
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

  printf("[+] Loading module imports... (%d import modules)\n", import_desc.ModuleCount);

  // read in each import library
  for (int i = 0; i < import_desc.ModuleCount; i++)
  {
    auto table_addr = qltell(li);
    XEX_IMPORT_TABLE table_header;
    qlread(li, &table_header, sizeof(XEX_IMPORT_TABLE));
    table_header.TableSize = swap32(table_header.TableSize);
    table_header.ImportCount = swap16(table_header.ImportCount);

    auto& libname = import_libs.at(table_header.ModuleIndex);

    // track variable imports so we can rename them later
    // (all imports have a "variable" type, but only functions have a "thunk" type)
    // (so we add the import to variable list when variable type is loaded, but then remove it if a thunk for that import gets loaded)
    std::map<int, int> variables;
    for (int j = 0; j < table_header.ImportCount; j++)
    {
      uint32 record_addr;
      qlread(li, &record_addr, sizeof(uint32));
      record_addr = swap32(record_addr);

      auto record_value = get_dword(record_addr);
      auto record_type = (record_value & 0xFF000000) >> 24;
      auto ordinal = record_value & 0xFFFF;

      auto import_name = DoNameGen(libname.c_str(), ordinal);
      if (record_type == 0)
      {
        // variable
        create_data(record_addr, FF_WORD, 2, BADADDR);
        create_data(record_addr + 2, FF_WORD, 2, BADADDR);
        //idc.make_array(record_addr, 2)
        set_name(record_addr, (std::string("__imp__") + import_name).c_str());
        variables[ordinal] = record_addr;
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
        add_func(record_addr, record_addr + 0x10);
        set_name(record_addr, import_name);

        // add comment to thunk like xorloser's loader
        // idc.set_cmt(record_addr + 4, "%s :: %s" % (libname.rsplit('.', 1)[0], import_name), 1)

        // this should mark the func as a library function, but it doesn't do anything for some reason
        // tried a bunch of things like idaapi.autoWait() before running it, just crashes IDA with internal errors...
        // idc.set_func_flags(record_addr, idc.get_func_flags(record_addr) | idc.FUNC_LIB)

        // thunk means this isn't a variable, remove from our variables map
        if (variables.count(ordinal))
          variables.erase(ordinal);
      }
      else
        printf("[+] %s import %d (%s) (@ 0x%X) unknown type %d!\n", libname.c_str(), ordinal, import_name, record_addr, record_type);
    }

    // remove "__imp__" part from variable import names
    for (auto kvp : variables)
    {
      auto import_name = DoNameGen(libname.c_str(), kvp.first);
      set_name(kvp.second, import_name);
    }

    // Seek to end of this import table
    qlseek(li, table_addr + table_header.TableSize);
  }

  // todo: add imports to imports window!!!
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
    printf("[+] Export table magic is invalid! (0x%X 0x%X 0x%X)\n", export_table.Magic[0], export_table.Magic[1], export_table.Magic[2]);
    return;
  }

  printf("[+] Loading module exports...\n");
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
    
    bool func_iscode = !strcmp(func_segmclass.c_str(), "CODE");
    add_entry(func_ord, func_va, func_name, func_iscode);
    if (func_iscode)
      add_func(func_va); // make doubly sure it gets marked as code
  }
}

//------------------------------------------------------------------------------
void idaapi load_file(linput_t *li, ushort /*_neflags*/, const char * /*fileformatname*/)
{
  printf("[+] IDAXEX load_file!\n");

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

  for (int i = 0; i < xex_header.HeaderDirectoryEntryCount; i++)
  {
    IMAGE_XEX_DIRECTORY_ENTRY header;
    read = qlread(li, &header, sizeof(IMAGE_XEX_DIRECTORY_ENTRY));
    header.Key = swap32(header.Key);
    header.Value = swap32(header.Value);

    directory_entries[header.Key] = header.Value;
  }

  qlseek(li, xex_header.SecurityInfo);
  read = qlread(li, &security_info, sizeof(XEX2_SECURITY_INFO));
  security_info.ImageSize = swap32(security_info.ImageSize);

  base_address = security_info.ImageInfo.LoadAddress = swap32(security_info.ImageInfo.LoadAddress);
  export_table_va = security_info.ImageInfo.ExportTableAddress = swap32(security_info.ImageInfo.ExportTableAddress);

  if (directory_entries.count(XEX_HEADER_PE_BASE))
    base_address = directory_entries[XEX_HEADER_PE_BASE];

  if (directory_entries.count(XEX_HEADER_ENTRY_POINT))
    entry_point = directory_entries[XEX_HEADER_ENTRY_POINT];

  if (!xex_read_image(li, 0) && !xex_read_image(li, 1) && !xex_read_image(li, 2))
  {
    printf("[+] Failed to load PE image from XEX :(\n");
    return;
  }

  // basefile loaded!

  // Setup imports & exports if we have them
  if (directory_entries.count(XEX_HEADER_IMPORTS))
    xex_load_imports(li);

  if (export_table_va)
    xex_load_exports();

  // Done :)
  printf("[+] XEX loaded, voila!\n");
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
