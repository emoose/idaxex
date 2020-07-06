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
#include <typeinf.hpp>
#include <bytes.hpp>

#define FF_WORD     0x10000000 // why doesn't this get included from ida headers?
#define FF_DWORD    0x20000000

bool exclude_unneeded_sections = true;

std::string DoNameGen(const std::string& libName, int id); // namegen.cpp

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

  uint8* patterns[] = {
    save_pattern,
    load_pattern
  };
  char* pattern_labels[] = {
    "__savegprlr_%d",
    "__restgprlr_%d"
  };

  for (int pat_idx = 0; pat_idx < 2; pat_idx++)
  {
    ea_t addr = start;

    while (addr != BADADDR)
    {
      addr = bin_search2(addr, end, patterns[pat_idx], NULL, 8, BIN_SEARCH_CASE | BIN_SEARCH_FORWARD);
      if (addr == BADADDR)
        break;

      for (int i = 14; i < 32; i++)
      {
        int size = 4;

        // final one is 0xC bytes when saving, 0x10 when loading
        if (i == 31)
          size = (pat_idx == 0) ? 0xC : 0x10;

        // reset addr
        del_items(addr, 0, 8);
        create_insn(addr);

        set_name(addr, qstring().sprnt(pattern_labels[pat_idx], i).c_str());
        add_func(addr, addr + size);

        addr += size;
      }
    }
  }
}

void pe_add_sections(XEXFile& file)
{
  for (auto section : file.sections())
  {
    // New buffer for section name so we can null-terminate it
    char name[9];
    memset(name, 0, 9);
    memcpy(name, section.Name, 8);

    // Exclude some sections from being added - don't know the reason, but xorlosers loader seems to
    // they don't seem important anyway, so i guess it's a good idea?
    if (exclude_unneeded_sections)
    {
      if (!strcmp(name, ".edata"))
        return;
      if (!strcmp(name, ".idata"))
        return;
      if (!strcmp(name, ".XBLD"))
        return;
      if (!strcmp(name, ".reloc"))
        return;
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

    char* seg_class = has_code ? "CODE" : "DATA";
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
}

//------------------------------------------------------------------------------
void idaapi load_file(linput_t *li, ushort /*_neflags*/, const char * /*fileformatname*/)
{
  // Set processor to PPC
  set_processor_type("ppc", SETPROC_LOADER);

  // Set PPC_LISOFF to true
  // should help analyzer convert "lis r11, -0x7C46" to "lis r11, unk_83BA5600@h"
  uint32 val = 1;
  ph.set_idp_options("PPC_LISOFF", IDPOPT_BIT, &val);

  // Set compiler info
  compiler_info_t comp;
  comp.id = COMP_MS;
  comp.defalign = 0;
  comp.size_i = 4;
  comp.size_b = 4;
  comp.size_e = 4;
  comp.size_s = 2;
  comp.size_l = 4;
  comp.size_ll = 8;
  comp.cm = CM_N32_F48;
  set_compiler(comp, 0, "xbox");

  inf.baseaddr = 0;

  qlseek(li, 0);

  XEXFile file;
  file.use_ida_io();
  bool result = file.load(li);
  if (result)
  {
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

    for (auto exp : file.exports())
    {
      auto exp_name = DoNameGen(exports_libname, exp.first);
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

      for (auto imp : lib.second)
      {
        auto imp_name = DoNameGen(libname, imp.first);
        auto imp_addr = imp.second.ThunkAddr;

        if (imp.second.ThunkAddr && imp.second.ThunkAddr != imp.second.FuncAddr)
        {
          auto thunk_name = "__imp_" + imp_name;
          if (!imp.second.FuncAddr)
            thunk_name = imp_name;

          set_name(imp.second.ThunkAddr, thunk_name.c_str());
          create_data(imp.second.ThunkAddr, FF_WORD, 2 * 2, BADADDR);

          if (lowest_addr == BADADDR || lowest_addr > imp.second.ThunkAddr)
            lowest_addr = imp.second.ThunkAddr;
        }

        if (imp.second.FuncAddr)
        {
          imp_addr = imp.second.FuncAddr;
          set_name(imp_addr, imp_name.c_str());

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
        auto& tables = file.import_tables();
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
  }
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
