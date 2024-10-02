// TODO:
// - fix export loading so that a segment isn't required (read from linput_t instead of reading thru IDA?)
// - improve speed of file load & analysis?
// - add more checks to things
// - find fix for XEX25/Crackdown alpha build (need to re-extract OS files for XEX25...)
// - test XEX2D / XEX3F
// - fix XEX1 exports
// - test!

#include "../idaldr.h"
#include "xex.hpp"
#include "xex_headerids.hpp"
#include <typeinf.hpp>
#include <bytes.hpp>
#include <filesystem>

netnode ignore_micro;

#define FF_WORD     0x10000000 // why doesn't this get included from ida headers?
#define FF_DWORD    0x20000000

bool exclude_unneeded_sections = true;

std::string DoNameGen(const std::string& libName, int id, int version); // namegen.cpp

void label_regsaveloads(ea_t start, ea_t end)
{
  // "std %r14, -0x98(%sp)" followed by "std %r15, -0x90(%sp)"
  uint8 save_pattern[] = {
    0xF9, 0xC1, 0xFF, 0x68, 0xF9, 0xE1, 0xFF, 0x70
  };
  // "ld %r14, -0x98(%sp)" followed by "ld %r15, -0x90(%sp)"
  uint8 load_pattern[] = {
    0xE9, 0xC1, 0xFF, 0x68, 0xE9, 0xE1, 0xFF, 0x70
  };
  // "stfd %f14, -0x90(%r12)" followed by "stfd %f15, -0x88(%r12)"
  uint8 savef_pattern[] = {
    0xD9, 0xCC, 0xFF, 0x70, 0xD9, 0xEC, 0xFF, 0x78
  };
  // "lfd %f14, -0x90(%r12)" followed by "lfd %f15, -0x88(%r12)"
  uint8 loadf_pattern[] = {
    0xC9, 0xCC, 0xFF, 0x70, 0xC9, 0xEC, 0xFF, 0x78
  };


  uint8* patterns[] = {
    save_pattern,
    load_pattern,
    savef_pattern,
    loadf_pattern
  };
  const char* pattern_labels[] = {
    "__savegprlr_%d",
    "__restgprlr_%d",
    "__savefpr_%d",
    "__restfpr_%d"
  };

  init_ignore_micro();

  for (int pat_idx = 0; pat_idx < 4; pat_idx++)
  {
    ea_t addr = start;

    while (addr != BADADDR)
    {
      addr = bin_search(addr, end, patterns[pat_idx], NULL, 8, BIN_SEARCH_CASE | BIN_SEARCH_FORWARD);
      if (addr == BADADDR)
        break;

      for (int i = 14; i < 32; i++)
      {
        int size = 4;

        // final one is 0xC bytes when saving, 0x10 when loading
        // (final fpr pattern is 0x8 when saving/loading)
        if (i == 31)
        {
            size = (pat_idx == 0) ? 0xC : 0x10;
            if (pat_idx > 1) size = 8;
        }

        // reset addr
        del_items(addr, 0, 8);
        create_insn(addr);

        set_name(addr, qstring().sprnt(pattern_labels[pat_idx], i).c_str(), SN_FORCE);

        func_t fn(addr, addr + size);
        fn.flags |= FUNC_OUTLINE | FUNC_HIDDEN;
        add_func_ex(&fn);

        // Mark save/rest functions as prolog/epilog to hide them from decompiler
        int hide_size = size;
        if (i == 31)
            hide_size -= 4; // don't hide last blr
        for (int insn = 0; insn < hide_size; insn += 4)
        {
            if (pat_idx == 0 || pat_idx == 2)
            {
                mark_prolog_insn(addr + insn);
            }
            else
            {
                mark_epilog_insn(addr + insn);
            }
        }

        addr += size;
      }
    }
  }
}

void pe_add_sections(XEXFile& file)
{
  for (const auto& section : file.sections())
  {
    // New buffer for section name so we can null-terminate it
    char name[9];
    std::copy_n(section.Name, 8, name);
    name[8] = '\0';

    // Exclude some sections from being added - don't know the reason, but xorlosers loader seems to
    // they don't seem important anyway, so i guess it's a good idea?
    // TODO: actually this probably wasn't a good idea, will need to figure out a better way of excluding sections
    if (exclude_unneeded_sections)
    {
      if (!strcmp(name, ".edata"))
        continue;
      if (!strcmp(name, ".XBLD"))
        continue;
      if (!strcmp(name, ".reloc"))
        continue;
    }

    uint32 sec_addr = section.VirtualAddress;
    uint32 sec_size = section.VirtualSize;

    if (file.header().Magic == MAGIC_XEX3F || file.header().Magic == MAGIC_XEX0)
    {
      sec_addr = section.PointerToRawData;
      sec_size = section.SizeOfRawData; // TODO: verify this?
    }

    // Size could be beyond file bounds, if so fix the size to what we can fit
    if (sec_addr + sec_size > file.image_size())
      sec_size = file.image_size() - sec_addr;

    // Add section as IDA segment
    uint32 seg_perms = 0;
    if (section.Characteristics & IMAGE_SCN_MEM_EXECUTE)
      seg_perms |= SEGPERM_EXEC;
    if (section.Characteristics & IMAGE_SCN_MEM_READ)
      seg_perms |= SEGPERM_READ;
    if (section.Characteristics & IMAGE_SCN_MEM_WRITE)
      seg_perms |= SEGPERM_WRITE;

    bool has_code = (section.Characteristics & IMAGE_SCN_CNT_CODE);
    bool has_data = (section.Characteristics & IMAGE_SCN_CNT_INITIALIZED_DATA) || (section.Characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA);

    const char* seg_class = has_code ? "CODE" : "DATA";
    ea_t seg_addr = (ea_t)file.base_address() + (ea_t)section.VirtualAddress;

    segment_t segm;
    segm.start_ea = seg_addr;
    segm.end_ea = seg_addr + section.VirtualSize;
    segm.align = saRelDble;
    segm.bitness = 1;
    segm.perm = seg_perms;
    add_segm_ex(&segm, name, seg_class, 0);

    if (sec_size <= 0)
      continue;

    // Load data into IDA
    mem2base(file.pe_data() + sec_addr, seg_addr, seg_addr + sec_size, -1);

    if (has_code)
      label_regsaveloads(seg_addr, seg_addr + section.VirtualSize);
  }

  // Try reading & marking functions from .pdata section
  for (const auto& section : file.sections())
  {
    // New buffer for section name so we can null-terminate it
    char name[9];
    std::copy_n(section.Name, 8, name);
    name[8] = '\0';

    if (strcmp(name, ".pdata"))
      continue;

    uint32 sec_addr = section.VirtualAddress;
    uint32 sec_size = section.VirtualSize;

    if (file.header().Magic == MAGIC_XEX3F || file.header().Magic == MAGIC_XEX0)
    {
      sec_addr = section.PointerToRawData;
      sec_size = section.SizeOfRawData; // TODO: verify this?
    }

    ea_t seg_addr = (ea_t)file.base_address() + (ea_t)section.VirtualAddress;

    // Size could be beyond file bounds, if so fix the size to what we can fit
    if (sec_addr + sec_size > file.image_size())
      sec_size = file.image_size() - sec_addr;

    // Store function addrs from .pdata inside a std::vector, so we can iterate over them in reverse
    std::vector<uint32_t> funcs;
    int offset = 0;
    while (offset < sec_size)
    {
      create_data(seg_addr + offset, dword_flag(), 4, BADNODE);
      create_data(seg_addr + offset + 4, dword_flag(), 4, BADNODE);

      auto* fn_ptr = reinterpret_cast<const xe::be<uint32_t>*>(file.pe_data() + sec_addr + offset);
      ea_t fn = *fn_ptr;

      funcs.push_back(fn);

      // Delete useless .pdata -> fn xref
      del_dref(seg_addr + offset, fn);

      offset += 8;
    }

    msg("Parsing .pdata and creating %lld functions...\n", funcs.size());

    // display messagebox prompt to user, since pdata labelling can take a little while
    // ida printf formatter tends to crash, too bad, use sprintf to rewrite just the number portion
    char msg_text[256] = "Marking functions from .pdata... (";
    int num_pos = strlen(msg_text);
    char* msg_text_write = &msg_text[num_pos];
    sprintf_s(msg_text_write, 256 - num_pos, "0/%lld)", funcs.size());

    show_wait_box(msg_text);

    // Iterate over functions in reverse, so hopefully they'll be marked with correct lengths
    size_t num = 0;
    for (std::vector<uint32_t>::reverse_iterator i = funcs.rbegin(); i != funcs.rend(); ++i)
    {
      create_insn(*i);
      add_func(*i);
      if (user_cancelled())
        break;

      // update every few funcs
      if (++num % 50 == 0)
      {
        sprintf_s(msg_text_write, 256 - num_pos, "%lld/%lld)", num, funcs.size());
        replace_wait_box(msg_text);
      }
    }

    hide_wait_box();
  }
}

#define PE_NODE "$ PE header" // netnode name for PE header
// value()        -> peheader_t
// altval(segnum) -> s->start_ea
#define PE_ALT_DBG_FPOS   nodeidx_t(-1)  // altval() -> translated fpos of debuginfo
#define PE_ALT_IMAGEBASE  nodeidx_t(-2)  // altval() -> loading address (usually pe.imagebase)
#define PE_ALT_PEHDR_OFF  nodeidx_t(-3)  // altval() -> offset of PE header
#define PE_ALT_NEFLAGS    nodeidx_t(-4)  // altval() -> neflags
#define PE_ALT_TDS_LOADED nodeidx_t(-5)  // altval() -> tds already loaded(1) or invalid(-1)
#define PE_ALT_PSXDLL     nodeidx_t(-6)  // altval() -> if POSIX(x86) imports from PSXDLL netnode
#define PE_ALT_OVRVA      nodeidx_t(-7)  // altval() -> overlay rva (if present)
#define PE_ALT_OVRSZ      nodeidx_t(-8)  // altval() -> overlay size (if present)
#define PE_SUPSTR_PDBNM   nodeidx_t(-9)  // supstr() -> pdb file name
                              // supval(segnum) -> pesection_t
                              // blob(0, PE_NODE_RELOC)  -> relocation info
                              // blob(0, RSDS_TAG)  -> rsds_t structure
                              // blob(0, NB10_TAG)  -> cv_info_pdb20_t structure
#define PE_ALT_NTAPI      nodeidx_t(-10) // altval() -> uses Native API
#define PE_EMBED_PDB_OFF  nodeidx_t(-11) // altval() -> offset of embedded PDB file
#define PE_NODE_RELOC 'r'
#define RSDS_TAG 's'
#define NB10_TAG 'n'
#define UTDS_TAG 't'

void pe_setup_netnode(XEXFile& file)
{
  netnode penode;
  penode.create(PE_NODE);

  penode.altset(PE_ALT_IMAGEBASE, file.base_address());

  size_t cv_length = 0;
  auto* cv_data = file.codeview_data(0, &cv_length);
  if (cv_data)
  {
    // Set PDB filename to whatever cv_data[0] says
    // (only use filename instead of full path, else it may fail to load it)
    char* pdb_path_ptr = (char*)(cv_data + sizeof(CV_INFO_PDB70));
    std::filesystem::path pdb_path = pdb_path_ptr;
    penode.supset(PE_SUPSTR_PDBNM, pdb_path.filename().string().c_str());

    // Copy cv_data into RSDS tag
    penode.setblob(cv_data, cv_length, 0, RSDS_TAG);

    // Prompt for PDB load
    msg("Prompting for PDB load...\n(full X360 type loading may require pdb.cfg PDB_PROVIDER = PDB_PROVIDER_MSDIA !)\n");
    auto* plugin = find_plugin("pdb", 1LL);
    run_plugin(plugin, 1LL);
  }
}

bool load_application(linput_t* li)
{
  qlseek(li, 0);

  XEXFile file;
  file.use_ida_io();
  if (!file.load(li))
    return false;

  inf_set_filetype(f_PE);
  inf_set_baseaddr(file.base_address() >> 4);
  set_imagebase(file.base_address());

  // If this is XEX2 try loading in x360.til, in case we have one
  if (file.header().Magic == MAGIC_XEX2)
      add_til("x360.til", ADDTIL_INCOMP);

  pe_add_sections(file);

  if (file.entry_point())
    add_entry(0, file.entry_point(), "start", 1);

  auto pe_module_name = file.pe_module_name();
  if (!pe_module_name.empty())
    add_pgm_cmt("PE module name: %s", pe_module_name.c_str());

  auto vital_stats = file.vital_stats();
  if (vital_stats)
  {
    time_t timestamp = vital_stats->Timestamp;
    char* timestamp_string = asctime(localtime(&timestamp));
    if (timestamp_string)
    {
      timestamp_string[strlen(timestamp_string) - 1] = 0; // remove newline from timestamp_string
      add_pgm_cmt("XEX timestamp: %s", timestamp_string);
    }

    add_pgm_cmt("XEX checksum: %x", vital_stats->Checksum);
  }

  auto exports_libname = file.exports_libname();
  if (exports_libname.empty())
  {
    exports_libname = pe_module_name;
    if (exports_libname.empty())
    {
      char module_name[256];
      memset(module_name, 0, 256);

      get_root_filename(module_name, 256);
      exports_libname = module_name;
    }
  }

  auto exports_version = file.min_kernel_version();
  if (file.header().Magic != MAGIC_XEX2D)
  {
    auto* exec_info = file.opt_header_ptr<xex_opt::XexExecutionId>(XEX_HEADER_EXECUTION_ID);
    if (exec_info)
    {
      exports_version = exec_info->Version.Build;
    }
  }
  else
  {
    auto* exec_info = file.opt_header_ptr<xex_opt::xex2d::XexExecutionId>(XEX_HEADER_EXECUTION_ID);
    if (exec_info)
    {
      exports_version = exec_info->Version.Build;
    }
  }

  auto* exec_info25 = file.opt_header_ptr<xex_opt::xex25::XexExecutionId>(XEX_HEADER_EXECUTION_ID_BETA);
  if (exec_info25)
  {
    exports_version = exec_info25->Version.Build;
  }

  auto* exec_info3f = file.opt_header_ptr<xex_opt::xex3f::XexExecutionId>(XEX_HEADER_EXECUTION_ID_BETA3F);
  if (exec_info3f)
  {
    exports_version = exec_info3f->Version.Build;
  }

  for (auto& exp : file.exports())
  {
    auto exp_name = DoNameGen(exports_libname, exp.first, exports_version);
    auto exp_addr = exp.second.FuncAddr;

    // Mark as func export if inside a code section
    qstring func_segmclass;
    get_segm_class(&func_segmclass, getseg(exp_addr));

    bool func_iscode = func_segmclass == "CODE";
    add_entry(exp.first, exp_addr, exp_name.c_str(), func_iscode);

    if (func_iscode)
      add_func(exp_addr); // make doubly sure it gets marked as code
  }

  for (auto lib : file.imports())
  {
    auto& libname = lib.first;

    netnode module_node;
    module_node.create();

    // Track lowest record addr so we can add import module comment to it later
    ea_t lowest_addr = BADADDR;

    int lib_version = file.min_kernel_version();

    auto& tables = file.import_tables();
    if (tables.count(libname))
    {
      lib_version = tables.at(libname).Version.Build;
    }

    for (auto& imp : lib.second)
    {
      auto imp_name = DoNameGen(libname, imp.first, lib_version);
      auto imp_addr = imp.second.ThunkAddr;

      if (imp.second.ThunkAddr && imp.second.ThunkAddr != imp.second.FuncAddr)
      {
        auto thunk_name = "__imp_" + imp_name;
        if (!imp.second.FuncAddr)
          thunk_name = imp_name;

        set_name(imp.second.ThunkAddr, thunk_name.c_str(), SN_FORCE);
        create_data(imp.second.ThunkAddr, FF_WORD, 2 * 2, BADADDR);

        if (lowest_addr == BADADDR || lowest_addr > imp.second.ThunkAddr)
          lowest_addr = imp.second.ThunkAddr;
      }

      if (imp.second.FuncAddr)
      {
        imp_addr = imp.second.FuncAddr;
        set_name(imp_addr, imp_name.c_str(), SN_FORCE);

        // add comment to thunk like xorloser's loader
        set_cmt(imp_addr + 4, qstring().sprnt("%s :: %s", libname.c_str(), imp_name.c_str()).c_str(), 1);

        // force IDA to recognize addr as code, so we can add it as a library function
        auto_make_code(imp_addr);
        auto_recreate_insn(imp_addr);
        func_t func(imp_addr, imp_addr + 0x10, FUNC_LIB);
        add_func_ex(&func);
      }

      // Set imports window name
      module_node.supset_ea(imp_addr, imp_name.c_str());

      // Set imports window ordinal
      module_node.altset(imp.first, ea2node(imp_addr));
    }

    if (lowest_addr != BADADDR)
    {
      if (tables.count(libname))
      {
        auto& table_header = tables.at(libname);

        add_extra_line(lowest_addr, true, "\n\nImports from %s v%d.%d.%d.%d (minimum v%d.%d.%d.%d)\n", libname.c_str(),
          table_header.Version.Major, table_header.Version.Minor, table_header.Version.Build, table_header.Version.QFE,
          table_header.VersionMin.Major, table_header.VersionMin.Minor, table_header.VersionMin.Build, table_header.VersionMin.QFE);
      }
    }

    if (lib.second.size())
    {
      // Add module to imports window
      import_module(libname.c_str(), NULL, module_node, NULL, "x360");
    }
  }

  pe_setup_netnode(file);

  return true;
}

//------------------------------------------------------------------------------
void idaapi load_file(linput_t *li, ushort /*_neflags*/, const char * /*fileformatname*/)
{
  // Set processor to PPC
  set_processor_type("ppc:vmx128", SETPROC_LOADER);

  // Set PPC_LISOFF to true
  // should help analyzer convert "lis r11, -0x7C46" to "lis r11, unk_83BA5600@h"
  uint32 val = 1;
  PH.set_idp_options("PPC_LISOFF", IDPOPT_BIT, &val);

  // Set compiler info
  compiler_info_t comp;
  comp.id = COMP_MS;
  comp.cm = CM_N32_F48 | CM_CC_FASTCALL;
  comp.size_i = 4;
  comp.size_b = 1;
  comp.size_e = 4;
  comp.defalign = 0;
  comp.size_s = 2;
  comp.size_l = 4;
  comp.size_ll = 8;
  comp.size_ldbl = 0;
  set_compiler(comp, SETCOMP_OVERRIDE);

  // load in the xex
  load_application(li);

  // set as 32-bit for hexrays support
  EAH.setup(false);   // file format does not support 64-bit data
  inf_set_app_bitness(32);
}

//--------------------------------------------------------------------------
static int idaapi accept_file(
        qstring *fileformatname,
        qstring *processor,
        linput_t *li,
        const char *)
{
  qlseek(li, 0);
  xe::be<uint32> magic;
  if (qlread(li, &magic, sizeof(uint32)) != sizeof(uint32))
    return 0;

  int valid = 0;
  if (magic == MAGIC_XEX2)
  {
    valid = 1;
    *fileformatname = "Xbox360 XEX2 File";
  }
  else if (magic == MAGIC_XEX1)
  {
    valid = 1;
    *fileformatname = "Xbox360 XEX1 File (>=1838)";
  }
  else if(magic == MAGIC_XEX25)
  {
    valid = 1;
    *fileformatname = "Xbox360 XEX%/XEX25 File (>=1746)";
  }
  else if(magic == MAGIC_XEX2D)
  {
    valid = 1;
    *fileformatname = "Xbox360 XEX-/XEX2D File (>=1640)";
  }
  else if (magic == MAGIC_XEX3F)
  {
    valid = 1;
    *fileformatname = "Xbox360 XEX?/XEX3F File (>=1434)";
  }
  else if (magic == MAGIC_XEX0)
  {
    valid = 1;
    *fileformatname = "Xbox360 XEX0 File (>=1332)";
  }

  if (valid)
    *processor = "PPC";

  return valid;
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
