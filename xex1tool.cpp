// xex1tool.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include <cstdio>
#include <filesystem>

#include "3rdparty/cxxopts.hpp"
#include "3rdparty/date.hpp"

#include "xex.hpp"
#include "xex_headerids.hpp"

#include "xdbf/xdbf.hpp"

extern const char* key_names[4];
extern bool xex_log_verbose;

std::string time2str(uint32_t time)
{
  date::sys_seconds tp{ std::chrono::seconds{time} };
  return date::format("%a %b %d %I:%M:%S %Y", tp);
}

std::string titleid2str(uint32_t tid, bool id_only = false)
{
  char str[64];
  if (id_only || (((tid >> 24) & 0xFF) - 0x21 > 0x59) || (((tid >> 16) & 0xFF) - 0x21 > 0x59))
    sprintf_s(str, "%08X", tid);
  else
    sprintf_s(str, "%08X (%c%c-%d)", tid, ((tid >> 24) & 0xFF), ((tid >> 16) & 0xFF), (tid & 0xFFFF));

  return str;
}

bool LoadSpa(XEXFile& xex, xe::kernel::xam::xdbf::SpaFile& spa)
{
  uint32_t title_id = 0;
  auto* exec_info = xex.opt_header_ptr<xex_opt::XexExecutionId>(XEX_HEADER_EXECUTION_ID);
  if (exec_info)
    title_id = exec_info->TitleID;
  else
  {
    auto* exec_info25 = xex.opt_header_ptr<xex_opt::xex25::XexExecutionId>(XEX_HEADER_EXECUTION_ID_BETA);
    if (exec_info25)
      title_id = exec_info25->TitleID;
  }

  auto tid = titleid2str(title_id, true);

  auto& sects = xex.xex_sections();
  for (auto section : sects)
  {
    char name[9];
    std::copy_n(section.Name, 8, name);
    name[8] = '\0';

    if (std::string(name) != tid)
      continue;

    auto* data = xex.pe_data();
    data += xex.pe_rva_to_offset(section.VirtualAddress);
    auto size = std::min(section.SizeOfRawData, section.VirtualSize);

    return spa.Read(data, size);
  }

  return false;
}

std::string DoNameGen(const std::string& libName, int id, int version);

void PrintImports(XEXFile& xex) {
  printf("\nXEX Imports:\n");

  auto& tables = xex.import_tables();

  for (auto& lib : xex.imports()) {
    auto& libname = lib.first;

    int version = xex.min_kernel_version();

    if (tables.count(libname))
    {
      auto& table_header = tables.at(libname);

      printf("# %s v%d.%d.%d.%d\n# (min v%d.%d.%d.%d, %llu imports)\n", libname.c_str(),
        table_header.Version.Major, table_header.Version.Minor, table_header.Version.Build, table_header.Version.QFE,
        table_header.VersionMin.Major, table_header.VersionMin.Minor, table_header.VersionMin.Build, table_header.VersionMin.QFE, lib.second.size());

      version = table_header.Version.Build;
    }

    for (auto& imp : lib.second)
    {
      auto imp_name = DoNameGen(libname, imp.first, version);
      auto imp_addr = imp.second.ThunkAddr;

      printf("  %3d) %s\n", imp.first, imp_name.c_str());
    }
    printf("\n");
  }
}

void PrintInfo(XEXFile& xex, bool print_mem_pages)
{
  printf("\nXEX Info\n");

  auto& header = xex.header();
  const char* exe_type = nullptr;
  const char* exe_versions = nullptr;
  switch (header.Magic) {
  case MAGIC_XEX2:
    exe_type = "XEX2";
    exe_versions = ">=1861";
    break;
  case MAGIC_XEX1:
    exe_type = "XEX1";
    exe_versions = ">=1838";
    break;
  case MAGIC_XEX25:
    exe_type = "XEX25 ('XEX%')";
    exe_versions = ">=1746";
    break;
  case MAGIC_XEX2D:
    exe_type = "XEX2D ('XEX-')";
    exe_versions = ">=1640";
    break;
  case MAGIC_XEX3F:
    exe_type = "XEX3F ('XEX?')";
    exe_versions = ">=1434";
    break;
  case MAGIC_XEX0:
    exe_type = "XEX0";
    exe_versions = ">=1332";
    break;
  }

  if (!exe_type)
    return; // wtf

  printf("  %s %s (%s)\n", exe_type, xex.basefile_is_pe() ? "Executable" : "Image", exe_versions);

  // We only have pub keys / verify method for XEX2 atm
  // No point printing any misleading info...
  if (header.Magic == MAGIC_XEX2)
  {
    if (xex.valid_signature() && xex.sign_key_index() != -1)
      printf("  Valid RSA signature (signed with '%s' key)\n", xex.sign_key_name());
    else
      printf("  Invalid RSA signature!\n");

    if (!xex.valid_header_hash())
      printf("  Invalid header hash!\n");

    if (!xex.valid_imports_hash())
      printf("  Invalid import table hash!\n");
  }

  if (!xex.valid_image_hash())
    printf("  Invalid image hash!\n");

  bool encrypted = false;
  if (xex.data_descriptor())
  {
    auto* desc = xex.data_descriptor();
    encrypted = desc->Flags != 0;
    if (encrypted && xex.encryption_key_index() != -1)
      printf("  Encrypted using '%s' key\n", key_names[xex.encryption_key_index()]);
    else if (!encrypted)
      printf("  Not Encrypted\n");

    switch (desc->Format)
    {
    case xex_opt::XexDataFormat::None:
    case xex_opt::XexDataFormat::Raw:
      printf("  Not Compressed\n");
      break;
    case xex_opt::XexDataFormat::Compressed:
      printf("  Compressed\n");
      break;
    case xex_opt::XexDataFormat::DeltaCompressed:
      printf("  Delta Compressed\n");
      break;
    }
  }

  if (header.ModuleFlags.TitleProcess)
    printf("  Title Module\n");
  if (header.ModuleFlags.TitleImports)
    printf("  Title Exports\n");
  if (header.ModuleFlags.Debugger)
    printf("  System Debugger\n");
  if (header.ModuleFlags.Dll)
    printf("  DLL Module\n");
  if (header.ModuleFlags.PatchFull)
    printf("  Full Patch\n");
  if (header.ModuleFlags.PatchDelta)
    printf("  Delta Patch\n");
  if (header.ModuleFlags.UserMode)
    printf("  User Mode\n");

  auto& sec_info = xex.security_info();
  // Flags aren't correct for XEX2D afaik...
  if (header.Magic != MAGIC_XEX2D)
  {
    if (sec_info.ImageInfo.ImageFlags.Unknown1)
      printf("  Has Unknown1 flag\n");
    if (sec_info.ImageInfo.ImageFlags.ManufacturingUtility)
      printf("  Manufacturing Utility\n");
    if (sec_info.ImageInfo.ImageFlags.ManufacturingSupportTool)
      printf("  Manufacturing Support Tool\n");
    if (sec_info.ImageInfo.ImageFlags.Xgd2MediaOnly)
      printf("  XGD2 Media Only\n");
    if (sec_info.ImageInfo.ImageFlags.DataCenterRequired)
      printf("  DataCenter Required\n");
    if (sec_info.ImageInfo.ImageFlags.DataCenterAware)
      printf("  DataCenter Aware\n");
    if (sec_info.ImageInfo.ImageFlags.CardeaKey)
      printf("  Cardea Key\n");
    if (sec_info.ImageInfo.ImageFlags.XeikaKey)
      printf("  Xeika Key\n");
    if (sec_info.ImageInfo.ImageFlags.TitleUserMode)
      printf("  Title UserMode\n");
    if (sec_info.ImageInfo.ImageFlags.SystemUserMode)
      printf("  System UserMode\n");
    if (sec_info.ImageInfo.ImageFlags.Orange0)
      printf("  Orange0\n");
    if (sec_info.ImageInfo.ImageFlags.Orange1)
      printf("  Orange1\n");
    if (sec_info.ImageInfo.ImageFlags.Orange2)
      printf("  Orange2\n");
    if (sec_info.ImageInfo.ImageFlags.SignedKeyVaultRequired)
      printf("  Signed KeyVault Required\n");
    if (sec_info.ImageInfo.ImageFlags.IptvSignupApplication)
      printf("  Iptv Signup Application\n");
    if (sec_info.ImageInfo.ImageFlags.IptvTitleApplication)
      printf("  Iptv Title Application\n");
    if (sec_info.ImageInfo.ImageFlags.NccpKeys)
      printf("  NCCP Keys\n");
    if (sec_info.ImageInfo.ImageFlags.KeyVaultPrivilegesRequired)
      printf("  KeyVault Privileges Required\n");
    if (sec_info.ImageInfo.ImageFlags.OnlineActivationRequired)
      printf("  Online Activation Required\n");
    if (sec_info.ImageInfo.ImageFlags.PageSize4Kb)
      printf("  Page Size 4Kb\n");
    if (sec_info.ImageInfo.ImageFlags.NoGameRegion)
      printf("  No Game Region\n");
    if (sec_info.ImageInfo.ImageFlags.RevocationCheckOptional)
      printf("  Revocation Check Optional\n");
    if (sec_info.ImageInfo.ImageFlags.RevocationCheckRequired)
      printf("  Revocation Check Required\n");
  }

  auto mslogo = xex.has_header(XEX_HEADER_MSLOGO);
  if (mslogo)
    printf("  Xbox360 Logo Data Present\n");

  if (xex.has_header(XEX_HEADER_PE_IMPORTS))
    printf("  Imports By Name\n");

  if (xex.has_header(XEX_HEADER_PE_EXPORTS))
    printf("  Exports By Name\n");

  auto* callcap = xex.opt_header_ptr<xex_opt::XexCallcapImports>(XEX_HEADER_CALLCAP_IMPORTS);
  if (callcap)
    printf("  Has Call Cap Data   (%08X %08X)\n", (uint32_t)callcap->BeginFunctionThunkAddress, (uint32_t)callcap->EndFunctionThunkAddress);

  auto fastcap = xex.has_header(XEX_HEADER_FASTCAP_ENABLED);
  if (fastcap)
    printf("  Has Fast Cap Data   (%08X)\n", fastcap);

  auto addt_mem = xex.opt_header(XEX_HEADER_ADDITIONAL_TITLE_MEM);
  if (addt_mem)
    printf("  Requires %dMB Extra Debug Memory\n", addt_mem);

  printf("\nBasefile Info\n");
  auto& pe_name = xex.pe_module_name();
  if (pe_name.length())
    printf("  Original PE Name:   %s\n", pe_name.c_str());

  printf("  Base Address:       %08X\n", xex.base_address());
  printf("  Entry Point:        %08X\n", xex.entry_point());
  printf("  Image Size:         %8X\n", xex.image_size());
  auto page_size = xex.base_address() < 0x90000000 ? 64 * 1024 : 4 * 1024;
  printf("  Page Size:          %8X\n", page_size);
  auto* stats = xex.vital_stats();
  if (stats)
  {
    printf("  Checksum:           %08X\n", (uint32_t)stats->Checksum);

    // TODO: should this be the VA from inside PE headers?
    auto* exp_table = xex.opt_header_ptr<IMAGE_DATA_DIRECTORY>(XEX_HEADER_PE_EXPORTS);
    if (exp_table)
      printf("  Export Table:       %08X\n", exp_table->VirtualAddress);

    auto s = time2str(stats->Timestamp);
    printf("  Filetime:           %08X - %s\n", (uint32_t)stats->Timestamp, s.c_str());
  }
  auto size = xex.opt_header(XEX_HEADER_STACK_SIZE);
  if (size)
    printf("  Stack Size:         %8X\n", size);

  size = xex.opt_header(XEX_HEADER_XAPI_HEAP_SIZE);
  if (size)
    printf("  Heap Size:          %8X\n", size);

  auto* page_heap = xex.opt_header_ptr<xex_opt::XexPageHeapOptions>(XEX_HEADER_PAGE_HEAP_SIZE_FLAGS);
  if (page_heap)
  {
    printf("  Page Heap Size:     %8X\n", (uint32_t)page_heap->Size);
    printf("  Page Heap Flags:    %8X\n", (uint32_t)page_heap->Flags);
  }

  size = xex.opt_header(XEX_HEADER_WORKSPACE_SIZE);
  if (size)
    printf("  Workspace Size:     %8X\n", size);

  size = xex.opt_header(XEX_HEADER_FSCACHE_SIZE);
  if (size)
    printf("  Filesystem Cache Size:  %8X\n", size);

  // Write out region info (XEX1/XEX2 only)
  if (header.Magic == MAGIC_XEX1 || header.Magic == MAGIC_XEX2)
  {
    printf("\nRegions\n");
    if (sec_info.ImageInfo.ImageFlags.NoGameRegion || (sec_info.ImageInfo.GameRegion & xex::Region_All))
      printf("  All Regions\n");
    else
    {
      if (sec_info.ImageInfo.GameRegion & xex::Region_NorthAmerica)
        printf("  North America\n");
      if (sec_info.ImageInfo.GameRegion & xex::Region_Japan)
        printf("  Japan\n");
      if (sec_info.ImageInfo.GameRegion & xex::Region_China)
        printf("  China\n");
      if (sec_info.ImageInfo.GameRegion & xex::Region_RestOfAsia)
        printf("  Rest of Asia\n");
      if (sec_info.ImageInfo.GameRegion & xex::Region_AustraliaNewZealand)
        printf("  Australia & New Zealand\n");
      if (sec_info.ImageInfo.GameRegion & xex::Region_RestOfEurope)
        printf("  Rest of Europe\n");
      if (sec_info.ImageInfo.GameRegion & xex::Region_Europe)
        printf("  Europe\n");
      if (sec_info.ImageInfo.GameRegion & xex::Region_RestOfWorld)
        printf("  Rest of the World\n");
    }
  }

  if (header.Magic == MAGIC_XEX2 || header.Magic == MAGIC_XEX1 || header.Magic == MAGIC_XEX25)
  {
    printf("\nAllowed Media\n");
    auto media_int = *(uint32_t*)&sec_info.AllowedMediaTypes;
    if (sec_info.ImageInfo.ImageFlags.Xgd2MediaOnly)
    {
      if (sec_info.AllowedMediaTypes.DvdCd)
        printf("  DVD-XGD2 (Xbox360 Original Disc)\n");
      else
        printf("  Updated DVD-XGD2 (Updated version of Xbox360 Original Disc)\n");
    }
    else
    {
      if (!media_int || media_int == 0xFFFFFFFF)
        printf("  All Media Types\n");
      else {
        if (sec_info.AllowedMediaTypes.HardDisk)
          printf("  Hard Disk\n");
        if (sec_info.AllowedMediaTypes.DvdX2)
          printf("  DVD-X2 (Xbox OG Original Disc)\n");
        if (sec_info.AllowedMediaTypes.DvdCd)
          printf("  DVD / CD\n");
        if (sec_info.AllowedMediaTypes.Dvd5)
          printf("  DVD-5\n");
        if (sec_info.AllowedMediaTypes.Dvd9)
          printf("  DVD-9\n");
        if (sec_info.AllowedMediaTypes.SystemFlash)
          printf("  System Flash\n");
        if (sec_info.AllowedMediaTypes._Unknown40)
          printf("  _Unknown40\n");
        if (sec_info.AllowedMediaTypes.MemoryUnit)
          printf("  Memory Unit\n");
        if (sec_info.AllowedMediaTypes.MassStorageDevice)
          printf("  USB Mass Storage Device\n");
        if (sec_info.AllowedMediaTypes.SmbFilesystem)
          printf("  Networked SMB Share\n");
        if (sec_info.AllowedMediaTypes.DirectFromRam)
          printf("  Direct From RAM\n");
        if (sec_info.AllowedMediaTypes._Unknown800)
          printf("  _Unknown800\n");
        if (sec_info.AllowedMediaTypes.SecureVirtualOpticalDevice)
          printf("  Secure Virtual Optical Device (\"SVOD\")\n");
        if (sec_info.AllowedMediaTypes.WirelessNStorageDevice)
          printf("  WirelessN Storage Device\n");
        if (sec_info.AllowedMediaTypes.SystemExtendedPartition)
          printf("  System Extended Partition (\"SEP\")\n");
        if (sec_info.AllowedMediaTypes.SystemAuxiliaryPartition)
          printf("  System Auxiliary Partition (\"SAP\")\n");
        if (sec_info.AllowedMediaTypes.InsecurePackage)
          printf("  Insecure Package (\"CON\")\n");
        if (sec_info.AllowedMediaTypes.SaveGamePackage)
          printf("  Savegame Package (\"CON\")\n");
        if (sec_info.AllowedMediaTypes.LocallySignedPackage)
          printf("  Locally Signed Package (\"CON\")\n");
        if (sec_info.AllowedMediaTypes.LiveSignedPackage)
          printf("  Live Signed Package (\"LIVE\")\n");
        if (sec_info.AllowedMediaTypes.XboxPlatformPackage)
          printf("  Xbox Platform Package (\"PIRS\")\n");
      }
    }
  }


  auto privileges = xex.opt_header(XEX_HEADER_PRIVILEGES);
  auto privileges32 = xex.opt_header(XEX_HEADER_PRIVILEGES_32);
  if (privileges || privileges32)
  {
    printf("\nXEX Privileges\n");
    if (privileges)
    {
      auto* privs = (xex_opt::XexPrivileges*)&privileges;
      if (privs->NoForceReboot)
        printf("   0x0: No Force Reboot\n");
      if (privs->ForegroundTasks)
        printf("   0x1: Foreground Tasks\n");
      if (privs->NoOddMapping)
        printf("   0x2: No ODD Mapping\n");
      if (privs->HandleMceInput)
        printf("   0x3: Handles MCE Input\n");
      if (privs->RestrictHudFeatures)
        printf("   0x4: Restricted HUD Features\n");
      if (privs->HandleGamepadDisconnect)
        printf("   0x5: Handles Gamepad Disconnect\n");
      if (privs->InsecureSockets)
        printf("   0x6: Has Insecure Sockets\n");
      if (privs->Xbox1XspInterop)
        printf("   0x7: Xbox1 XSP Interoperability\n");
      if (privs->SetDashContext)
        printf("   0x8: Can Set Dash Context\n");
      if (privs->TitleUsesGameVoiceChannel)
        printf("   0x9: Uses Game Voice Channel\n");
      if (privs->TitlePal50Incompatible)
        printf("   0xA: PAL-50 Incompatible\n");
      if (privs->TitleInsecureUtilityDrive)
        printf("   0xB: Supports Insecure Utility Drive\n");
      if (privs->TitleXamHooks)
        printf("   0xC: Xam Hooks\n");
      if (privs->TitlePii)
        printf("   0xD: PII\n");
      if (privs->CrossplatformSystemLink)
        printf("   0xE: Crossplatform System Link\n");
      if (privs->MultidiscSwap)
        printf("   0xF: Multidisc Swap\n");
      if (privs->MultidiscInsecureMedia)
        printf("  0x10: Supports Insecure Multidisc Media\n");
      if (privs->Ap25Media)
        printf("  0x11: AP25 Media\n");
      if (privs->NoConfirmExit)
        printf("  0x12: No Confirm Exit\n");
      if (privs->AllowBackgroundDownload)
        printf("  0x13: Allows Background Downloads\n");
      if (privs->CreatePersistableRamdrive)
        printf("  0x14: Creates Persistable Ramdrive\n");
      if (privs->InheritPersistedRamdrive)
        printf("  0x15: Inherits Persisted Ramdrive\n");
      if (privs->AllowHudVibration)
        printf("  0x16: Allows HUD Vibration\n");
      if (privs->TitleBothUtilityPartitions)
        printf("  0x17: Can Use Both Utility Partitions\n");
      if (privs->HandleIPTVInput)
        printf("  0x18: Handles IPTV Input\n");
      if (privs->PreferBigButtonInput)
        printf("  0x19: Prefers Big Button Input\n");
      if (privs->AllowXsamReservation)
        printf("  0x1A: Allow Xsam Reservation\n");
      if (privs->MultidiscCrossTitle)
        printf("  0x1B: Multidisc Cross Title\n");
      if (privs->TitleInstallIncompatible)
        printf("  0x1C: Title Install Incompatible\n");
      if (privs->AllowAvatarGetMetadataByXUID)
        printf("  0x1D: Allow Avatar Get Metadata By XUID\n");
      if (privs->AllowControllerSwapping)
        printf("  0x1E: Allow Controller Swapping\n");
      if (privs->DashExtensibilityModule)
        printf("  0x1F: Dash Extensibility Module\n");
    }

    if (privileges32)
    {
      auto* privs = (xex_opt::XexPrivileges32*)&privileges32;
      if (privs->AllowNetworkReadCancel)
        printf("  0x20: Allow Network Read Cancel\n");
      if (privs->UninterruptableReads)
        printf("  0x21: Uninterruptable Reads\n");
      if (privs->RequireExperienceFull)
        printf("  0x22: Requires NXE\n");
      if (privs->GameVoiceRequiredUI)
        printf("  0x23: Game Voice Required UI\n");
      if (privs->TitleSetPresenceString)
        printf("  0x24: Sets Presence String\n");
      if (privs->NatalTiltControl)
        printf("  0x25: Natal Tilt Control\n");
      if (privs->TitleRequiresSkeletalTracking)
        printf("  0x26: Requires Skeletal Tracking\n");
      if (privs->TitleSupportsSkeletalTracking)
        printf("  0x27: Supports Skeletal Tracking\n");
      if (privs->UseLargeHDsFileCache)
        printf("  0x28: Uses Large HDs File Cache\n");
      if (privs->TitleSupportsDeepLink)
        printf("  0x29: Supports Deep Link\n");
      if (privs->TitleBodyProfile)
        printf("  0x2A: Supports Body Profile\n");
      if (privs->TitleWinUSB)
        printf("  0x2B: Supports WinUSB\n");
      if (privs->TitleSupportsDeepLinkRefresh)
        printf("  0x2C: Supports Deep Link Refresh\n");
      if (privs->LocalOnlySockets)
        printf("  0x2D: Local Only Sockets\n");
      if (privs->TitleContentAcquireAndDownload)
        printf("  0x2E: Title Content Acquire And Download\n");
      if (privs->AllowSystemForeground)
        printf("  0x2F: Allow System Foreground\n");
    }
  }

  if (header.Magic == MAGIC_XEX2 || header.Magic == MAGIC_XEX1)
  {
    printf("\nMedia ID\n  ");
    for (int i = 0; i < 0x10; i++)
      printf("%02X ", sec_info.ImageInfo.MediaID[i]);
    printf("\n");
  }

  auto* key = (const uint8_t*)xex.opt_header_ptr(XEX_HEADER_DISC_PROFILE_ID);
  if (key)
  {
    printf("\nDisc Profile ID\n  ");
    for (int i = 0; i < 0x10; i++)
      printf("%02X ", key[i]);
    printf("\n");
  }

  if (header.Magic != MAGIC_XEX3F && header.Magic != MAGIC_XEX0) // these two don't use crypto
  {
    key = encrypted ? xex.session_key() : sec_info.ImageInfo.ImageKey;
    if (encrypted)
      printf("\nEncryption Key (key decrypted using %s key)\n  ", key_names[xex.encryption_key_index()]);
    else
      printf("\nEncryption Key (raw value)\n  ");
    for (int i = 0; i < 0x10; i++)
      printf("%02X ", key[i]);
    printf("\n");
  }

  key = (uint8_t*)xex.opt_header_ptr(XEX_HEADER_LAN_KEY);
  if (key)
  {
    printf("\nLAN Key\n  ");
    for (int i = 0; i < 0x10; i++)
      printf("%02X ", key[i]);
    printf("\n");
  }

  key = (uint8_t*)xex.opt_header_ptr(XEX_PATCH_FILE_BASE_REFERENCE);
  if (key)
  {
    printf("\nPatch Base Reference\n  ");
    for (int i = 0; i < 0x14; i++)
      printf("%02X ", key[i]);
    printf("\n");
  }

  auto* time_range = xex.opt_header_ptr<xex_opt::XexSystemTimeRange>(XEX_HEADER_TIME_RANGE);
  if (!time_range)
  {
    time_range = xex.opt_header_ptr<xex_opt::XexSystemTimeRange>(XEX_HEADER_TIME_RANGE_ALT);
    if (time_range)
      printf("\n[+] Uses alt time range header!!!\n");
  }
  auto* kv_privs = xex.opt_header_ptr<xex_opt::XexKeyVaultPrivileges>(XEX_HEADER_KEY_VAULT_PRIVS);
  if (!kv_privs)
  {
    kv_privs = xex.opt_header_ptr<xex_opt::XexKeyVaultPrivileges>(XEX_HEADER_KEY_VAULT_PRIVS_ALT);
    if (kv_privs)
      printf("\n[+] Uses alt KV privs header!!!\n");
  }
  if (time_range || kv_privs)
  {
    printf("\nRestrictions for Use\n");
    // TODO: print these as strings!
    if (time_range)
    {
      printf("  Start Date:         %llX\n", (uint64_t)time_range->Start);
      printf("  End Date:           %llX\n", (uint64_t)time_range->End);
    }
    if (kv_privs)
    {
      printf("  KeyVault Mask:      %llX\n", (uint64_t)kv_privs->Mask);
      printf("  KeyVault Value:     %llX\n", (uint64_t)kv_privs->Match);
    }
    // TODO: consoleID table
  }

  auto* bound_path = xex.opt_header_ptr<xex_opt::XexStringHeader>(XEX_HEADER_BOUND_PATH);
  if (bound_path)
  {
    printf("\nBound Path\n");
    printf("  %.*s\n", (uint32_t)bound_path->Size, bound_path->Data);
  }

  key = (uint8_t*)xex.opt_header_ptr(XEX_HEADER_DEVICE_ID);
  if (key)
  {
    printf("\nBound Device ID\n  ");
    for (int i = 0; i < 0x14; i++)
      printf("%02X ", key[i]);
    printf("\n");
  }

  auto* tls_info = xex.opt_header_ptr<xex_opt::XexTlsData>(XEX_HEADER_TLS_DATA);
  if (tls_info)
  {
    printf("\nTLS Info\n");
    printf("  Number of Slots:    %d\n", (uint32_t)tls_info->TlsSlotCount);
    printf("  Data Size:          %08X\n", (uint32_t)tls_info->SizeOfTlsData);
    printf("  Raw Data Address:   %08X\n", (uint32_t)tls_info->AddressOfRawData);
    printf("  Raw Data Size:      %08X\n", (uint32_t)tls_info->SizeOfRawData);
  }

  if (header.Magic != MAGIC_XEX2D)
  {
    auto* exec_info = xex.opt_header_ptr<xex_opt::XexExecutionId>(XEX_HEADER_EXECUTION_ID);
    if (exec_info)
    {
      printf("\nExecution ID\n");
      printf("  Media ID:           %08X\n", (uint32_t)exec_info->MediaID);
      printf("  Title ID:           %s\n", titleid2str(exec_info->TitleID).c_str());
      printf("  Savegame ID:        %08X\n", (uint32_t)exec_info->SaveGameID);
      printf("  Version:            v%d.%d.%d.%d\n", exec_info->Version.Major, exec_info->Version.Minor, exec_info->Version.Build, exec_info->Version.QFE);
      printf("  Base Version:       v%d.%d.%d.%d\n", exec_info->BaseVersion.Major, exec_info->BaseVersion.Minor, exec_info->BaseVersion.Build, exec_info->BaseVersion.QFE);
      printf("  Platform:           %d\n", exec_info->Platform);
      printf("  Executable Type:    %d\n", exec_info->ExecutableType);
      printf("  Disc Number:        %d\n", exec_info->DiscNum);
      printf("  Number of Discs:    %d\n", exec_info->DiscsInSet);
    }
  }
  else
  {
    auto* exec_info = xex.opt_header_ptr<xex_opt::xex2d::XexExecutionId>(XEX_HEADER_EXECUTION_ID);
    if (exec_info)
    {
      printf("\nExecution ID (XEX2D)\n");
      printf("  Media ID:           %08X\n", (uint32_t)exec_info->MediaID);
      printf("  Title ID:           %s\n", titleid2str(exec_info->TitleID).c_str());
      printf("  Savegame ID:        %X\n", exec_info->SaveGameID);
      printf("  Version:            v%d.%d.%d.%d\n", exec_info->Version.Major, exec_info->Version.Minor, exec_info->Version.Build, exec_info->Version.QFE);
      printf("  UpdatedVersion:     %04X\n", (uint16_t)exec_info->UpdatedVersion);
      printf("  Region:             %04X\n", (uint16_t)exec_info->Region);
      printf("  Rating:             %08X\n", (uint32_t)exec_info->Rating);
      printf("  Platform:           %d\n", exec_info->Platform);
      printf("  Executable Type:    %d\n", exec_info->ExecutableType);
      printf("  Disc Number:        %d\n", exec_info->DiscNum);
    }
  }

  auto* exec_info25 = xex.opt_header_ptr<xex_opt::xex25::XexExecutionId>(XEX_HEADER_EXECUTION_ID_BETA);
  if (exec_info25)
  {
    printf("\nExecution ID (XEX25)\n");
    printf("  Media ID:           %08X\n", (uint32_t)exec_info25->MediaID);
    printf("  Title ID:           %s\n", titleid2str(exec_info25->TitleID).c_str());
    printf("  Savegame ID:        %08X\n", (uint32_t)exec_info25->SaveGameID);
    printf("  Version:            v%d.%d.%d.%d\n", exec_info25->Version.Major, exec_info25->Version.Minor, exec_info25->Version.Build, exec_info25->Version.QFE);
    printf("  Platform:           %d\n", (uint32_t)exec_info25->Platform);
    printf("  Executable Type:    %d\n", (uint32_t)exec_info25->ExecutableType);
    printf("  Disc Number:        %d\n", (uint32_t)exec_info25->DiscNum);
    printf("  Number of Discs:    %d\n", (uint32_t)exec_info25->DiscsInSet);
  }

  // TODO: read in as XEX3F/XEX0 depending on variant when XEX0 support is added!
  auto* exec_info3f = xex.opt_header_ptr<xex_opt::xex3f::XexExecutionId>(XEX_HEADER_EXECUTION_ID_BETA3F);
  if (exec_info3f)
  {
    if (header.Magic == MAGIC_XEX3F)
      printf("\nExecution ID (XEX3F)\n");
    else
      printf("\nExecution ID (XEX0)\n");
    printf("  Media ID:           %08X\n", (uint32_t)exec_info3f->MediaID);
    printf("  Title ID:           %s\n", titleid2str(exec_info3f->TitleID).c_str());
    printf("  Savegame ID:        %X\n", exec_info3f->SaveGameID);
    printf("  Version:            v%d.%d.%d.%d\n", exec_info3f->Version.Major, exec_info3f->Version.Minor, exec_info3f->Version.Build, exec_info3f->Version.QFE);
    printf("  UpdatedVersion:     %04X\n", (uint16_t)exec_info3f->UpdatedVersion);
    printf("  Region:             %04X\n", (uint16_t)exec_info3f->Region);
    printf("  Platform:           %d\n", exec_info3f->Platform);
    if (header.Magic == MAGIC_XEX3F)
      printf("  Executable Type:    %d\n", exec_info3f->ExecutableType);
    else
      printf("  Content Type:       %d\n", exec_info3f->ExecutableType);
    printf("  Disc Number:        %d\n", exec_info3f->DiscNum);
  }

  xe::kernel::xam::xdbf::SpaFile spa;
  if (LoadSpa(xex, spa)) {
    printf("\nSPA / XDBF Info\n");
    printf("  Title Name:         %s\n", spa.GetTitleName().c_str());
    xe::kernel::xam::xdbf::X_XDBF_XTHD_DATA title_data;
    if (spa.GetTitleData(&title_data))
    {
      printf("  Title Type:         %d\n", (uint32_t)title_data.title_type);
      printf("  XDBF Version:       v%d.%d.%d.%d\n", (uint32_t)title_data.title_version_major, (uint32_t)title_data.title_version_minor, (uint32_t)title_data.title_version_build, (uint32_t)title_data.title_version_revision);
    }
    printf("  Achievement Count:  %d\n", spa.GetAchievements(xe::kernel::xam::xdbf::XLanguage::kEnglish, nullptr));
  }

  auto* title_ids = xex.opt_header_ptr<uint32_t>(XEX_HEADER_ALTERNATE_TITLE_IDS);
  if (title_ids)
  {
    uint32_t size = _byteswap_ulong(*title_ids);
    uint32_t count = (size - 4) / sizeof(uint32_t);
    if (count > 0)
    {
      printf("\nAlternate Title Ids\n");
      title_ids++;
      for (uint32_t i = 0; i < count; i++)
      {
        uint32_t tid = _byteswap_ulong(*title_ids);
        title_ids++;
        printf("  %3d) %s\n", i, titleid2str(tid).c_str());
      }
    }
  }

  auto* patch_info_og = xex.opt_header_ptr<xex_opt::XexDeltaPatchDescriptor>(XEX_HEADER_DELTA_PATCH_DESCRIPTOR);
  if (patch_info_og) {
    xex_opt::XexDeltaPatchDescriptor patch_info = *patch_info_og;

    *(uint32_t*)&patch_info.SourceVersion = _byteswap_ulong(*(uint32_t*)&patch_info.SourceVersion);
    *(uint32_t*)&patch_info.TargetVersion = _byteswap_ulong(*(uint32_t*)&patch_info.TargetVersion);

    uint32_t media_id;
    media_id = _byteswap_ulong(*(uint32_t*)(&xex.security_info().ImageInfo.MediaID[0xC]));

    printf("\nDelta Patch Descriptor\n");
    printf("  Media ID:               %08X\n", media_id);
    printf("  Source Version:         v%d.%d.%d.%d\n", patch_info.SourceVersion.Major, patch_info.SourceVersion.Minor, patch_info.SourceVersion.Build, patch_info.SourceVersion.QFE);
    printf("  Target Version:         v%d.%d.%d.%d\n", patch_info.TargetVersion.Major, patch_info.TargetVersion.Minor, patch_info.TargetVersion.Build, patch_info.TargetVersion.QFE);
  
    printf("  Headers source offset:  %X\n", uint32_t(patch_info.DeltaHeadersSourceOffset));
    printf("  Headers source size:    %X\n", uint32_t(patch_info.DeltaHeadersSourceSize));
    printf("  Headers target offset   %X\n", uint32_t(patch_info.DeltaHeadersTargetOffset));

    printf("  Image source offset:    %X\n", uint32_t(patch_info.DeltaImageSourceOffset));
    printf("  Image source size:      %X\n", uint32_t(patch_info.DeltaImageSourceSize));
    printf("  Image target offset:    %X\n", uint32_t(patch_info.DeltaImageTargetOffset));

    printf("  Target header size:     %X\n", uint32_t(patch_info.SizeOfTargetHeaders));

    printf("\n  Source Digest\n    ");
    for (int i = 0; i < 0x14; i++)
      printf("%02X ", patch_info.DigestSource[i]);
    printf("\n");

    printf("\n  Source Image Key\n    ");
    for (int i = 0; i < 0x10; i++)
      printf("%02X ", patch_info.ImageKeySource[i]);
    printf("\n");
  }

  // TODO: ratings!

  auto* libs = xex.opt_header_ptr<xex_opt::XexImageLibraryVersions>(XEX_HEADER_BUILD_VERSIONS);
  if (libs)
  {
    printf("\nStatic Libraries\n");
    auto count = libs->Size / sizeof(xex_opt::XexImageLibraryVersion);

    for (uint32_t i = 0; i < count; i++)
    {
      auto& lib = libs->Libraries[i];

      char details[256];
      sprintf_s(details, "%3d) %-14.8s v%d.%d.%d.%d", i, lib.LibraryName, (uint16_t)lib.Version.Major, (uint16_t)lib.Version.Minor, (uint16_t)lib.Version.Build, (uint16_t)lib.Version.QFE);
    
      printf("  %-32s  (", details);

      if ((lib.Version.ApprovalType & xex::ApprovalType_Expired) == xex::ApprovalType_Expired)
        printf("Expired");
      else if (lib.Version.ApprovalType & xex::ApprovalType_PossiblyApproved)
        printf("Possibly Approved");
      else if (lib.Version.ApprovalType & xex::ApprovalType_Approved)
        printf("Approved");
      else
        printf("Unapproved");

      if (lib.Version.ApprovalType & xex::ApprovalType_Tool)
        printf(", Tool Version");
      if (lib.Version.ApprovalType & xex::ApprovalType_Executable)
        printf(", Executable Version");
      if (lib.Version.ApprovalType & xex::ApprovalType_Debug)
        printf(", Debug Build");
      printf(")\n");
    }
  }

  auto& import_tables = xex.import_tables();
  auto& imports = xex.imports();
  if (import_tables.size())
  {
    printf("\nImport Libraries\n");
    int i = 0;
    for (auto kvp : import_tables) {
      char details[256];
      sprintf_s(details, "%3d) %-14s v%d.%d.%d.%d", i, kvp.first.c_str(), kvp.second.Version.Major, kvp.second.Version.Minor, kvp.second.Version.Build, kvp.second.Version.QFE);

      printf("  %-32s  (min v%d.%d.%d.%d, %d imports)\n", details, 
        kvp.second.VersionMin.Major, kvp.second.VersionMin.Minor, kvp.second.VersionMin.Build, kvp.second.VersionMin.QFE, (uint32_t)(imports.at(kvp.first).size()));

      i++;
    }
  }

  auto& sections = xex.xex_sections();
  if (sections.size())
  {
    printf("\nResources\n");
    int i = 0;
    for (auto section : sections) {
      auto start = section.VirtualAddress + xex.base_address();
      auto end = start + section.VirtualSize;
      printf("  %3d) %08X - %08X : %.8s\n", i, start, end, section.Name);
      i++;
    }
  }

  if (!print_mem_pages)
    return;

  auto& page_descriptors = xex.page_descriptors();
  if (page_descriptors.size())
  {
    printf("\nMemory Pages\n");
    int i = 0;
    uint32_t address = xex.base_address();
    for (auto page : page_descriptors)
    {
      auto size = page.Size * page_size;
      auto details = "Data";
      if (page.Info & xex::PageInfoFlag_NoWrite)
      {
        if (page.Info & xex::PageInfoFlag_NoExecute)
          details = "Header/Resource";
        else
          details = "Code";
      }

      printf("  %3d) %08X - %08X : %s\n", i, address, address + size, details);
      address += size;
      i++;
    }
  }
}

int main(int argc, char* argv[])
{
  cxxopts::Options options("xex1tool");
  options.add_options()
    ("l,listing", "Print executable info")
    ("m,listmem", "Print executable info & memory pages")
    ("i,imports", "Print import libraries & functions")
    ("b,basefile", "Dump basefile from XEX", cxxopts::value<std::string>())
    ("d,dumpres", "Dump all resources to a dir (can be '.')", cxxopts::value<std::string>())
    ("v,verbose", "Enables verbose XEXFile debug output")
    ("a,address", "Convert a virtual memory address to file offset, or vice-versa", cxxopts::value<uint32_t>())
    ("positional", "Positional parameters",
      cxxopts::value<std::vector<std::string>>())
    ;
  options.positional_help("input-filepath");
  options.parse_positional({ "positional" });

  printf("xex1tool  -  emoose\n");

  auto result = options.parse(argc, argv);

  if (!result.count("positional"))
  {
    printf(options.help().c_str());
    return 0;
  }

  auto& positional = result["positional"].as<std::vector<std::string>>();

  if (!positional.size())
  {
    printf(options.help().c_str());
    return 0;
  }

  auto& filepath = positional[0];

  xex_log_verbose = result["v"].as<bool>();

  printf("Reading and parsing input XEX file...\n");

  FILE* file;
  auto res = fopen_s(&file, filepath.c_str(), "rb");

  if (!file)
  {
    printf("Error opening XEX file %s\n", filepath.c_str());
    return 0;
  }

  XEXFile xex;

  bool loadresult = xex.load(file);

  if (!loadresult)
  {
    printf("Error %d while loading XEX file %s\n", xex.load_error(), filepath.c_str());
    return xex.load_error();
  }

  if (result.count("a"))
  {
    uint32_t rva = result["a"].as<uint32_t>();
    printf("\n");

    bool convert = true;
    auto* data_descriptor = xex.data_descriptor();
    if (!data_descriptor)
      convert = false;
    else
    {
      xex_opt::XexDataFormat comp_format = (xex_opt::XexDataFormat)(uint16_t)data_descriptor->Format;
      convert = comp_format == xex_opt::XexDataFormat::None || comp_format == xex_opt::XexDataFormat::Raw;
    }

    if (!convert)
      printf("XEX isn't uncompressed, unable to convert address with -a!\n");
    else
    {
      // TODO: fix these functions to work with older formats
      if (xex.header().Magic != MAGIC_XEX2)
        printf("XEX isn't XEX2, addresses might not be correct!\n");

      uint32_t result = 0;
      if (rva >= xex.base_address())
      {
        result = xex.xex_va_to_offset(rva);
        printf("Virtual Address -> File Offset\n");
        printf("Virtual Addr: 0x%X\n", rva);
        printf("File Offset:  0x%X\n", result);
      }
      else
      {
        result = xex.xex_offset_to_va(rva);
        printf("File Offset -> Virtual Address\n");
        printf("File Offset:  0x%X\n", rva);
        printf("Virtual Addr: 0x%X\n", result);
      }

      if (!result)
      {
        printf("\nThe given address was unable to be converted, either:\n");
        printf("- The given number is invalid\n");
        printf("- The address is out-of-bounds\n");
        printf("- The VA is part of a zero-compressed block in the file\n");
        printf("(even with uncompressed XEXs, blocks of zeroes are removed from the file to save some space)\n");
      }
    }

    printf("\n");
  }

  if (result.count("b"))
  {
    auto& basefile = result["b"].as<std::string>();
    FILE* output;
    auto res = fopen_s(&output, basefile.c_str(), "wb");
    if (res != 0 || !output) {
      printf("Error %d opening basefile %s for write\n", res, basefile.c_str());
    }
    else {
      fwrite(xex.pe_data(), 1, xex.pe_data_length(), output);
      fclose(output);
      printf("Successfully dumped basefile to %s\n", basefile.c_str());

      if (xex.basefile_is_pe())
      {
        printf("\nLoad basefile into IDA with the following details\n");
        printf("DO NOT load as a PE or EXE file as the format is not valid\n");
        printf("File Type:       Binary file\n");
        printf("Processor Type:  PowerPC: ppcbe\n");
        printf("Load Address:    0x%08X\n", xex.base_address());
        printf("Entry Point:     0x%08X\n", xex.entry_point());
      }
    }
  }

  if (result.count("d"))
  {
    auto& sections = xex.xex_sections();
    if (sections.size())
    {
      auto& dump_path_s = result["d"].as<std::string>();
      if (dump_path_s != ".")
        std::filesystem::create_directory(dump_path_s);
      std::filesystem::path dump_path = dump_path_s;

      std::vector<std::string> dumped_names;
      for (auto section : sections)
      {
        char sectname_safe[9];
        std::copy_n(section.Name, 8, sectname_safe);
        sectname_safe[8] = '\0';

        // Check if we've dumped the same filename before, try adding a number if we have
        std::string sectname = sectname_safe;
        int i = 0;
        while (std::find(dumped_names.begin(), dumped_names.end(), sectname) != dumped_names.end())
            sectname = std::string(sectname_safe) + "_" + std::to_string(++i);

        dumped_names.push_back(sectname);

        std::filesystem::path res_path = dump_path / sectname;
        FILE* file;
        if (auto res = fopen_s(&file, res_path.string().c_str(), "wb") != 0 || !file) {
          printf("Error %d opening file %s for writing\n", res, res_path.string().c_str());
        }
        else {

          auto addr = xex.pe_rva_to_offset(section.VirtualAddress);
          if (xex.header().Magic == MAGIC_XEX3F || xex.header().Magic == MAGIC_XEX0 || !addr)
            addr = section.PointerToRawData;

          auto* data = xex.pe_data() + addr;
          fwrite(data, 1, std::min(section.SizeOfRawData, section.VirtualSize), file);
          fclose(file);
          printf("Extracted resource %.8s to %s\n", section.Name, res_path.string().c_str());
        }
      }
    }
  }

  if (result["i"].as<bool>())
    PrintImports(xex);

  if (result["l"].as<bool>() || result["m"].as<bool>())
    PrintInfo(xex, result["m"].as<bool>());
}
