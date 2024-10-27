#include <ida.hpp>
#include <idp.hpp>
#include <loader.hpp>
#include <auto.hpp>
#include <diskio.hpp>
#include <entry.hpp>
#include <typeinf.hpp>
#include <bytes.hpp>
#include <segregs.hpp>

struct exehdr {}; // needed for pe.h
#include <pe.h>
#include <common.h>

#include <filesystem>
#include <list>
#include <array>

#include <libXbSymbolDatabase.h>

#include "xbe.hpp"

#ifdef _WIN32
#define strncasecmp _strnicmp
#endif

std::string DoNameGen(const std::string& libName, int id, int version); // namegen.cpp
std::string DoXTLIDNameGen(uint32_t id); // namegen_xtlid.cpp

std::array<std::string, 11> kDataSectionNames = {
  ".rdata",
  ".data",
  ".data1",
  "DOLBY",
  "XON_RD",
  "WMADEC",
  ".XBLD",
  "D3D_RW",
  "D3DX_RW",
  "XGRPH_RW",
  "XTIMAGE",
};

void xbe_add_sections(XBEFile& file)
{
  auto& xbe_header = file.header_data();

  // TODO: adding a HEADER segment is likely needed for PDB loading
  // though PDBs currently can't load properly due to other segment issues (see note at end of xbe_setup_netnode)
  // so we'll skip adding this for now
  /*
  segment_t xbe_segm;
  xbe_segm.start_ea = 0x10000;
  xbe_segm.end_ea = 0x10000 + xbe_header.size();
  xbe_segm.align = saRelDble;
  xbe_segm.bitness = 1;
  xbe_segm.perm = SEGPERM_READ | SEGPERM_WRITE;
  add_segm_ex(&xbe_segm, "HEADER", "DATA", 0);
  mem2base(xbe_header.data(), xbe_segm.start_ea, xbe_segm.end_ea, -1);*/

  sel_t ds = BADADDR;

  for (const auto& section : file.sections())
  {
    // Add section as IDA segment
    uint32 seg_perms = 0;
    seg_perms |= SEGPERM_READ;
    if (section.Info.SectionFlags.Executable)
      seg_perms |= SEGPERM_EXEC;
    if (section.Info.SectionFlags.Writable)
      seg_perms |= SEGPERM_WRITE;

    bool has_code = (section.Info.SectionFlags.Executable);

    // Unfortunately flags aren't always reliable to tell if section has code or not
    // Check against some known data-section names and remove flag if matches
    if (has_code)
      for (auto& name : kDataSectionNames)
      {
        if (name == section.Name) {
          has_code = false;
          break;
        }
      }

    const char* seg_class = has_code ? "CODE" : "DATA";

    uint32 seg_addr = section.Info.VirtualAddress;
    size_t seg_size = section.Data.size();

    segment_t segm;
    segm.start_ea = seg_addr;
    segm.end_ea = seg_addr + section.Info.VirtualSize;
    segm.align = saRelByte;
    segm.bitness = 1;
    segm.perm = seg_perms;
    segm.sel = allocate_selector(0);
    for (int i = 0; i < SREG_NUM; i++)
      segm.defsr[i] = BADADDR;

    if (section.Name == ".data")
      ds = segm.sel;

    add_segm_ex(&segm, section.Name.c_str(), seg_class, 0);

    // Load data into IDA
    if (seg_size > 0)
      mem2base(section.Data.data(), seg_addr, seg_addr + seg_size, -1);
  }

  if (ds != BADADDR)
    set_default_dataseg(ds);
}

void xbe_setup_netnode(XBEFile& file)
{
  netnode penode;
  penode.create(PE_NODE);

  // Set PE header node data
  // Make a copy of PE header and update with correct values first, since IDA/eh_parse reads some info from this
  
  auto& xbe_header = file.header();
  
  IMAGE_NT_HEADERS nt_header{ 0 };
  nt_header.Signature = 0x4550;
  nt_header.FileHeader.Machine = 0x14C;
  nt_header.FileHeader.NumberOfSections = file.sections().size();
  nt_header.FileHeader.TimeDateStamp = xbe_header.NtTimeDateStamp;
  nt_header.FileHeader.SizeOfOptionalHeader = sizeof(IMAGE_OPTIONAL_HEADER32);

  auto& opt = nt_header.OptionalHeader;
  opt.Magic = 0x10B;
  opt.MajorLinkerVersion = 8;
  opt.AddressOfEntryPoint = xbe_header.AddressOfEntryPoint;
  opt.ImageBase = xbe_header.BaseAddress;
  opt.SectionAlignment = 0x1000;
  opt.FileAlignment = 0x400;
  opt.MajorOperatingSystemVersion = 4;
  opt.MajorSubsystemVersion = 4;
  opt.SizeOfImage = xbe_header.NtSizeOfImage;
  opt.SizeOfHeaders = xbe_header.SizeOfHeaders;
  opt.Subsystem = 2;
  opt.SizeOfStackCommit = xbe_header.SizeOfStackCommit;
  opt.SizeOfHeapReserve = xbe_header.SizeOfHeapReserve;
  opt.SizeOfHeapCommit = xbe_header.SizeOfHeapCommit;
  opt.NumberOfRvaAndSizes = 16;

  penode.set(&nt_header, sizeof(IMAGE_NT_HEADERS));

  // Update imagebase
  penode.altset(PE_ALT_IMAGEBASE, file.base_address());

  // Update IDA with any codeview data
  size_t cv_length = 0;
  auto* cv_data = file.codeview_data(0, &cv_length);
  if (cv_data)
  {
    // Set PDB filename to whatever cv_data[0] says
    const char* pdb_path = (const char*)(cv_data + sizeof(CV_INFO_PDB70));

    // Try using filename instead of full path, else it may fail to load in
    const char* pdb_name = strrchr(pdb_path, '\\');
    if (pdb_name)
      pdb_path = pdb_name + 1; // get name past the backslash

    penode.supset(PE_SUPSTR_PDBNM, pdb_path);

    // Copy cv_data into RSDS tag
    penode.setblob(cv_data, cv_length, 0, RSDS_TAG);

    // TODO: pdb loading doesn't currently work for xbe files
    // Even though cvdump shows that the symbols are relative to each segment
    // It looks like DIA (and PDBIDA) both lookup the segment address from something inside the PDB, rather than from the IDB
    // PDB segments are based on the original EXE layout, not the XBE version, so this causes it to use wrong address for symbols
    // 
    // (guess there must be some way for DIA to adjust segment addrs since XboxSDK allows XBE+PDB debugging
    // but IDA probably isn't setup to make use of that, or if it is I haven't seen a way for us to change it...)
#if 0
    // Prompt for PDB load
    msg("Prompting for PDB load...\n(full X360 type loading may require pdb.cfg PDB_PROVIDER = PDB_PROVIDER_MSDIA !)\n");
    auto* plugin = find_plugin("pdb", true);
    run_plugin(plugin, 1LL);
#endif
  }
}

static int num_dbsymbols = 0;

static void reg_cb(const char* library_str,
  uint32_t library_flag,
  uint32_t xref_index,
  const char* symbol_str,
  xbaddr address,
  uint32_t build_version,
  uint32_t symbol_type,
  uint32_t call_type,
  uint32_t param_count,
  const XbSDBSymbolParam* param_list)
{
  num_dbsymbols++;
  const char* symbol_name = XbSymbolDatabase_SymbolReferenceToString(xref_index);
  set_name(address, symbol_name);

  if (symbol_type == symbol_function)
  {
    // workaround IDA insisting on creating mainXapiStartup as dword
    show_auto(address);
    del_items(address);
    auto_make_proc(address);

    func_t* existing = get_func(address);
    if (existing)
    {
      existing->flags |= FUNC_LIB;
      update_func(existing);
    }
    else
    {
      func_t func(address, BADADDR, FUNC_LIB);
      add_func_ex(&func);
    }
  }
}

bool xbe_scan_symboldb(XBEFile& file)
{
  msg("[XbSymbolDatabase] Scanning for library symbols, database version %x\n", XbSymbolDatabase_LibraryVersion());
  num_dbsymbols = 0;

  // Make copy of xbe_data so we can apply transformations before passing to XbSymbolDatabase
  std::vector<uint8_t> xbe_data = file.xbe_data();
  xbe::XbeHeader* xbe_header = (xbe::XbeHeader*)xbe_data.data();

  if (file.is_xorkey_beta())
  {
    // Recrypt beta keys to retail, to workaround XbSymbolDatabase lacking beta keys
    xbe_header->XboxKernelThunkDataOffset =
      file.header().XboxKernelThunkDataOffset /* decrypted */
      ^ XBE_XOR_KT_RETAIL; /* retail thunk key (TODO: if any beta games use debug libs we should switch to debug key here?) */

    xbe_header->AddressOfEntryPoint =
      file.header().AddressOfEntryPoint /* decrypted */
      ^ XBE_XOR_EP_RETAIL;
  }

  XbSDBLibraryHeader lib_header = {
      .count = XbSymbolDatabase_GenerateLibraryFilter(xbe_header, NULL),
      .filters = (XbSDBLibrary*)malloc(lib_header.count * sizeof(XbSDBLibrary))
  };
  if (!lib_header.filters) {
    return false;
  }
  XbSymbolDatabase_GenerateLibraryFilter(xbe_header, &lib_header);

  XbSDBSectionHeader sect_header = {
      .count = XbSymbolDatabase_GenerateSectionFilter(xbe_header, NULL, 1),
      .filters = (XbSDBSection*)malloc(sect_header.count * sizeof(XbSDBSection))
  };
  if (!sect_header.filters) {
    free(lib_header.filters);
    return false;
  }
  XbSymbolDatabase_GenerateSectionFilter(xbe_header, &sect_header, 1);

  XbSymbolContextHandle ctx;
  bool status = XbSymbolDatabase_CreateXbSymbolContext(&ctx, reg_cb, lib_header, sect_header, XbSymbolDatabase_GetKernelThunkAddress(xbe_header));
  if (status)
  {
    XbSymbolContext_ScanManual(ctx);
    XbSymbolContext_ScanAllLibraryFilter(ctx);
    XbSymbolContext_RegisterXRefs(ctx);
    msg("[XbSymbolDatabase] Scan complete, %d symbols named\n", num_dbsymbols);
  }
  else
  {
    msg("[XbSymbolDatabase] CreateXbSymbolContext failed...\n");
  }

  XbSymbolContext_Release(ctx);

  free(sect_header.filters);
  free(lib_header.filters);

  return true;
}

void xbe_parse_xtlid(XBEFile& file)
{
  for (const auto& section : file.sections())
  {
    if (section.Name != ".XTLID")
      continue;

    uint32_t* xtlid = (uint32_t*)section.Data.data();

    // xtlid header
    uint32_t unk0 = *(xtlid++);
    uint32_t lib_version = *(xtlid++);

    uint32_t num_fns = (section.Data.size() - 8) / 8;

    if (unk0 != 0 || (lib_version == 0 || lib_version > 5933))
    {
      msg("[XTLID] Failed to parse XTLID, unexpected header values: %x %x\n", unk0, lib_version);
      return;
    }

    add_extra_line(section.Info.VirtualAddress, true, "XTLID function count: %d\nXTLID library version: %d", int(num_fns), int(lib_version));

    // create dword for version field
    create_dword(section.Info.VirtualAddress + 4, 4, true);
    set_op_type(section.Info.VirtualAddress + 4, dec_flag(), 0);
    set_cmt(section.Info.VirtualAddress + 4, qstring().sprnt("XTLID library version: %d", int(lib_version)).c_str(), false);

    msg("[XTLID] Library version from XTLID: %d\n", int(lib_version));
    msg("[XTLID] Naming %d library functions from XTLID data...\n", int(num_fns));
    int named_fns = 0;
    for (uint32_t i = 0; i < num_fns; i++)
    {
      uint32_t xtlid_ea = section.Info.VirtualAddress + 8 + (i * 8);
      create_dword(xtlid_ea, 4, true);
      set_op_type(xtlid_ea, hex_flag(), 0); // force the ID to be hex number without creating random xrefs
      create_dword(xtlid_ea + 4, 4, true);

      uint32_t fn_id = *(xtlid++);
      uint32_t fn_addr = *(xtlid++);

      auto fn_name = DoXTLIDNameGen(fn_id);
      if (fn_name.empty())
      {
        msg("[XTLID] Name for XTLID 0x%x not found\n", fn_id);
      }
      else
      {
        set_name(fn_addr, fn_name.c_str(), SN_FORCE);
        named_fns++;

        // Check if we should create func for this XTLID
        // List of some known non-function XTLIDs
        static std::vector<uint32_t> kDataXTLIDs = {
          0xb002d, // DirectSoundRequiredMixBins_3D
          0xb002e, // DirectSoundRequiredMixBins_5Channel3D
          0xb0033, // g_dwDirectSoundDebugBreakLevel
          0xb0034, // g_dwDirectSoundDebugLevel
          0xb0035, // g_pfnDirectSoundDebugCallback
          0x60001, // XDEVICE_TYPE_KEYBOARD_TABLE
          0x1007b, // XDEVICE_TYPE_DEBUG_MOUSE_TABLE
          0x1007c, // XDEVICE_TYPE_GAMEPAD_TABLE
          0x1007d, // XDEVICE_TYPE_IR_REMOTE_TABLE
          0x1007e, // XDEVICE_TYPE_MEMORY_UNIT_TABLE
          0x1007b, // XDEVICE_TYPE_DEBUG_MOUSE_TABLE
          0x50001, // XDEVICE_TYPE_DEBUG_KEYBOARD_TABLE
          0x80001, // D3D__Device
          0x80002, // D3D__NullHardware
          0x80003, // D3D__pDevice
          0x80004, // D3D__SingleStepPusher
          0x70001, // XDEVICE_TYPE_HIGHFIDELITY_MICROPHONE_TABLE
          0x70002, // XDEVICE_TYPE_VOICE_HEADPHONE_TABLE
          0x70003, // XDEVICE_TYPE_VOICE_MICROPHONE_TABLE
        };

        bool isDSoundData =
          (fn_id >= 0xb0005 && fn_id <= 0xb000e) ||
          (fn_id >= 0xb0012 && fn_id <= 0xb002b);

        if (isDSoundData || std::find(kDataXTLIDs.begin(), kDataXTLIDs.end(), fn_id) != kDataXTLIDs.end())
          continue;

        // Make sure func is inside a code segment
        auto* seg = getseg(fn_addr);
        qstring name;
        get_segm_class(&name, seg);
        if (name != "CODE")
          continue;

        // workaround IDA insisting on creating mainXapiStartup as dword
        show_auto(fn_addr);
        del_items(fn_addr);
        auto_make_proc(fn_addr);
        func_t* existing = get_func(fn_addr);
        if (existing)
        {
          existing->flags |= FUNC_LIB;
          update_func(existing);
        }
        else
        {
          func_t func(fn_addr, BADADDR, FUNC_LIB);
          add_func_ex(&func);
        }
      }
    }
    msg("[XTLID] XTLID naming finished, %d names added\n", named_fns);

    break;
  }
}

bool load_application_xbe(linput_t* li)
{
  qlseek(li, 0);

  XBEFile file;
  file.use_ida_io();
  if (!file.load(li))
  {
    msg("[+] XBE file load failed with XBELoadError code %d\n", file.load_error());
    return false;
  }
  msg("[+] XBE encryption key: %s\n", XBEFile::key_name(file.xorkey_index()));

  inf_set_filetype(f_PE);
  inf_set_baseaddr(file.base_address() >> 4);
  set_imagebase(file.base_address());

  xbe_add_sections(file);

  if (file.entry_point())
  {
    add_func(file.entry_point());
    add_entry(0, file.entry_point(), "start", 1);
    inf_set_main(file.entry_point());
    inf_set_start_ip(file.entry_point());

    sel_t cs = 0;
    segment_t* cs_seg = getseg(file.entry_point());
    if (cs_seg)
      cs = cs_seg->sel;

    inf_set_start_cs(cs);
  }

  auto& header = file.header();

  auto& pe_module_name = file.pe_module_name();
  if (!pe_module_name.empty())
    add_pgm_cmt("PE module name: %s", pe_module_name.c_str());

  add_pgm_cmt("PE checksum: %x", (uint32_t)header.NtCheckSum);

  time_t pe_timestamp = header.NtTimeDateStamp;
  char* pe_timestamp_string = asctime(localtime(&pe_timestamp));
  if (pe_timestamp_string)
  {
    pe_timestamp_string[strlen(pe_timestamp_string) - 1] = 0; // remove newline from timestamp_string
    add_pgm_cmt("PE timestamp: %s", pe_timestamp_string);
  }

  time_t xbe_timestamp = header.TimeDateStamp;
  char* xbe_timestamp_string = asctime(localtime(&xbe_timestamp));
  if (xbe_timestamp_string)
  {
    xbe_timestamp_string[strlen(xbe_timestamp_string) - 1] = 0; // remove newline from timestamp_string
    add_pgm_cmt("XBE timestamp: %s", xbe_timestamp_string);
  }

  const xbe::XbeLibraryVersion* kernel_lib = nullptr;
  add_pgm_cmt("\nXTL versions:");
  for (auto& library : file.libraries())
  {
    if (!strncasecmp("XBOXKRNL", library.LibraryName, 8))
      kernel_lib = &library;

    char name[9];
    std::copy_n(library.LibraryName, 8, name);
    name[8] = '\0';

    add_pgm_cmt(" %s v%d.%d.%d.%d", name, library.MajorVersion, library.MinorVersion, library.BuildVersion, library.QFEVersion);
  }

  auto tls_directory_va = file.tls_directory_va();
  if (tls_directory_va)
  {
    auto tls_directory = file.tls_directory();
    auto& tls_callbacks = file.tls_callbacks();

    if (tls_directory.StartAddressOfRawData)
      set_name(tls_directory.StartAddressOfRawData, "_tls_start");
    if (tls_directory.EndAddressOfRawData)
      set_name(tls_directory.EndAddressOfRawData, "_tls_end");
    if (tls_directory.AddressOfIndex)
      set_name(tls_directory.AddressOfIndex, "_tls_index");
    if (tls_directory.AddressOfCallBacks)
    {
      set_name(tls_directory.AddressOfCallBacks, "_tls_callbacks"); // not actual name, usually something useless like __xl_b
      if (tls_callbacks.size())
        create_dword(tls_directory.AddressOfCallBacks, tls_callbacks.size() * 4);
    }

    for (size_t i = 0; i < tls_callbacks.size(); i++)
      set_name(tls_callbacks[i], qstring().sprnt("TlsCallback_%d", int(i)).c_str());

    // Create IMAGE_TLS_DIRECTORY32 and set directory name/type
    static const char IMAGE_TLS_DIRECTORY32_type[] =
      R"(typedef struct _IMAGE_TLS_DIRECTORY32
{
  void *StartAddressOfRawData;
  void *EndAddressOfRawData;
  void *AddressOfIndex;
  void *AddressOfCallBacks;
  unsigned int SizeOfZeroFill;
  unsigned int Characteristics;
} IMAGE_TLS_DIRECTORY32;
)";

    h2ti(nullptr, nullptr, IMAGE_TLS_DIRECTORY32_type, HTI_DCL, nullptr, nullptr, msg);
    set_name(tls_directory_va, "_tls_used");
    apply_cdecl(nullptr, tls_directory_va, "IMAGE_TLS_DIRECTORY32 _tls_used;");
  }

  // TODO: how are exports handled?

  netnode kernel_node;
  kernel_node.create();

  // Track lowest record addr so we can add import module comment to it later
  ea_t lowest_addr = BADADDR;

  for (auto imp : file.kernel_imports())
  {
    auto imp_name = DoNameGen("xbox1krnl", imp.second, 0);
    auto imp_addr = imp.first;

    if (imp_addr)
    {
      set_name(imp_addr, imp_name.c_str(), SN_FORCE);
      set_cmt(imp_addr, qstring().sprnt("%s :: %s", "xboxkrnl", imp_name.c_str()).c_str(), 1);
      create_dword(imp_addr, 4, true);

      set_import_name(kernel_node, imp_addr, imp_name.c_str());
      set_import_ordinal(kernel_node, imp_addr, imp.second);

      if (lowest_addr == BADADDR || lowest_addr > imp_addr)
        lowest_addr = imp_addr;
    }
  }

  if (lowest_addr != BADADDR)
  {
    if (kernel_lib)
    {
      add_extra_line(lowest_addr, true, "\n\nImports from %s v%d.%d.%d.%d\n", "xboxkrnl",
        kernel_lib->MajorVersion, kernel_lib->MinorVersion, kernel_lib->BuildVersion, kernel_lib->QFEVersion);
    }
  }

  import_module("xboxkrnl", NULL, kernel_node, NULL, "xbox");

  xbe_setup_netnode(file);

  xbe_scan_symboldb(file);
  xbe_parse_xtlid(file);

  return true;
}

//------------------------------------------------------------------------------
void idaapi load_file_xbe(linput_t* li, ushort _neflags, const char* fileformatname)
{
  bool reloading = (_neflags & NEF_RELOAD) == NEF_RELOAD;

  if (!reloading)
  {
    set_processor_type("metapc", SETPROC_LOADER);
    inf_set_specsegs(4);
  }

  // load in the xbe
  if (load_application_xbe(li))
  {
    if (!reloading)
    {
      // set as 32-bit for hexrays support
      EAH.setup(false);   // file format does not support 64-bit data
      inf_set_app_bitness(32);

      add_til("mssdk_win7", ADDTIL_SILENT);
    }
  }
}
