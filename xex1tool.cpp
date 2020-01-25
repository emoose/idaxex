// xex1tool.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include <cstdio>
#include <filesystem>

#include "3rdparty/cxxopts.hpp"
#include "3rdparty/date.hpp"

#include "xex.hpp"
#include "xex_headerids.hpp"

extern const char* key_names[4];
extern bool xex_log_verbose;

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
    exe_type = "XEX2F ('XEX?')";
    exe_versions = ">=1529";
    break;
  }

  if (!exe_type)
    return; // wtf

  printf("  %s %s (%s)\n", exe_type, xex.basefile_is_pe() ? "Executable" : "Image", exe_versions);

  bool encrypted = false;
  if (xex.data_descriptor())
  {
    auto* desc = xex.data_descriptor();
    encrypted = desc->Flags != 0;
    if (encrypted && xex.encryption_key_index() != -1)
    {
      printf("  Uses %s key\n", key_names[xex.encryption_key_index()]);
    }

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

    printf("  %sEncrypted\n", (!encrypted ? "Not " : ""));
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

  auto mslogo = xex.has_header(XEX_HEADER_MSLOGO);
  if(mslogo)
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

  auto privileges = xex.opt_header(XEX_HEADER_PRIVILEGES);
  if (privileges)
  {
    printf("\nXEX Privileges\n");
    auto* privs = (xex_opt::XexPrivileges*)&privileges;
    if (privs->NoForceReboot)
      printf("  No Force Reboot\n");
    if (privs->ForegroundTasks)
      printf("  Foreground Tasks\n");
    if (privs->NoOddMapping)
      printf("  No ODD Mapping\n");
    if (privs->HandleMceInput)
      printf("  Handles MCE Input\n");
    if (privs->RestrictHudFeatures)
      printf("  Restricted HUD Features\n");
    if (privs->HandleGamepadDisconnect)
      printf("  Handles Gamepad Disconnect\n");
    if (privs->InsecureSockets)
      printf("  Has Insecure Sockets\n");
    if (privs->Xbox1XspInterop)
      printf("  Xbox1 XSP Interoperability\n");
    if (privs->SetDashContext)
      printf("  Can Set Dash Context\n");
    if (privs->TitleUsesGameVoiceChannel)
      printf("  Uses Game Voice Channel\n");
    if (privs->TitlePal50Incompatible)
      printf("  PAL-50 Incompatible\n");
    if (privs->TitleInsecureUtilityDrive)
      printf("  Supports Insecure Utility Drive\n");
    if (privs->TitleXamHooks)
      printf("  Xam Hooks\n");
    if (privs->TitlePii)
      printf("  PII\n");
    if (privs->CrossplatformSystemLink)
      printf("  Crossplatform System Link\n");
    if (privs->MultidiscSwap)
      printf("  Multidisc Swap\n");
    if (privs->MultidiscInsecureMedia)
      printf("  Supports Insecure Multidisc Media\n");
    if (privs->Ap25Media)
      printf("  AP25 Media\n");
    if (privs->NoConfirmExit)
      printf("  No Confirm Exit\n");
    if (privs->AllowBackgroundDownload)
      printf("  Allows Background Downloads\n");
    if (privs->CreatePersistableRamdrive)
      printf("  Creates Persistable Ramdrive\n");
    if (privs->InheritPersistedRamdrive)
      printf("  Inherits Persisted Ramdrive\n");
    if (privs->AllowHudVibration)
      printf("  Allows HUD Vibration\n");
    if (privs->TitleBothUtilityPartitions)
      printf("  Can Use Both Utility Partitions\n");
    if (privs->HandleIPTVInput)
      printf("  Handles IPTV Input\n");
    if (privs->PreferBigButtonInput)
      printf("  Prefers Big Button Input\n");
    if (privs->AllowXsamReservation)
      printf("  Allow Xsam Reservation\n");
    if (privs->MultidiscCrossTitle)
      printf("  Multidisc Cross Title\n");
    if (privs->TitleInstallIncompatible)
      printf("  Title Install Incompatible\n");
    if (privs->AllowAvatarGetMetadataByXUID)
      printf("  Allow Avatar Get Metadata By XUID\n");
    if (privs->AllowControllerSwapping)
      printf("  Allow Controller Swapping\n");
    if (privs->DashExtensibilityModule)
      printf("  Dash Extensibility Module\n");
  }

  auto privileges32 = xex.opt_header(XEX_HEADER_PRIVILEGES_32);
  if (privileges32)
  {
    printf("\nXEX Extended Privileges\n");
    auto* privs = (xex_opt::XexPrivileges32*)&privileges32;
    if (privs->AllowNetworkReadCancel)
      printf("  Allow Network Read Cancel\n");
    if (privs->UninterruptableReads)
      printf("  Uninterruptable Reads\n");
    if (privs->RequireExperienceFull)
      printf("  Requires NXE\n");
    if (privs->GameVoiceRequiredUI)
      printf("  Game Voice Required UI\n");
    if (privs->TitleSetPresenceString)
      printf("  Sets Presence String\n");
    if (privs->NatalTiltControl)
      printf("  Natal Tilt Control\n");
    if (privs->TitleRequiresSkeletalTracking)
      printf("  Requires Skeletal Tracking\n");
    if (privs->TitleSupportsSkeletalTracking)
      printf("  Supports Skeletal Tracking\n");
    if (privs->UseLargeHDsFileCache)
      printf("  Uses Large HDs File Cache\n");
    if (privs->TitleSupportsDeepLink)
      printf("  Supports Deep Link\n");
    if (privs->TitleBodyProfile)
      printf("  Supports Body Profile\n");
    if (privs->TitleWinUSB)
      printf("  Supports WinUSB\n");
    if (privs->TitleSupportsDeepLinkRefresh)
      printf("  Supports Deep Link Refresh\n");
    if (privs->LocalOnlySockets)
      printf("  Local Only Sockets\n");
    if (privs->TitleContentAcquireAndDownload)
      printf("  Title Content Acquire And Download\n");
    if (privs->AllowSystemForeground)
      printf("  Allow System Foreground\n");
  }

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

    uint32_t timestamp = stats->Timestamp;
    date::sys_seconds tp{ std::chrono::seconds{timestamp} };
    std::string s = date::format("%a %b %d %I:%M:%S %Y", tp);

    printf("  Filetime:           %08X - %s\n", timestamp, s.c_str());
  }
  auto stack_size = xex.opt_header(XEX_HEADER_STACK_SIZE);
  if (stack_size) {
    printf("  Stack Size:         %08X\n", stack_size);
  }

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

  printf("\nMedia ID\n  ");
  for (int i = 0; i < 0x10; i++)
    printf("%02X ", sec_info.ImageInfo.MediaID[i]);
  printf("\n");

  auto* key = (const uint8_t*)xex.opt_header_ptr(XEX_HEADER_DISC_PROFILE_ID);
  if (key)
  {
    printf("\nDisc Profile ID\n  ");
    for (int i = 0; i < 0x10; i++)
      printf("%02X ", key[i]);
    printf("\n");
  }

  key = encrypted ? xex.session_key() : sec_info.ImageInfo.ImageKey;
  if (encrypted)
    printf("\nEncryption Key (key decrypted using %s key)\n  ", key_names[xex.encryption_key_index()]);
  else
    printf("\nEncryption Key (raw value)\n  ");
  for (int i = 0; i < 0x10; i++)
    printf("%02X ", key[i]);
  printf("\n");

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

  auto* bound_path = xex.opt_header_ptr<xex_opt::XexStringHeader>(XEX_HEADER_BOUND_PATH);
  if (bound_path)
  {
    printf("\nBound Path\n");
    printf("  %.*s\n", (uint32_t)bound_path->Size, bound_path->Data);
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

  auto* exec_info = xex.opt_header_ptr<xex_opt::XexExecutionId>(XEX_HEADER_EXECUTION_ID);
  if (exec_info)
  {
    printf("\nExecution ID\n");
    printf("  Media ID:           %08X\n", (uint32_t)exec_info->MediaID);
    printf("  Title ID:           %08X\n", (uint32_t)exec_info->TitleID);
    printf("  Savegame ID:        %08X\n", (uint32_t)exec_info->SaveGameID);
    printf("  Version:            v%d.%d.%d.%d\n", exec_info->Version.Major, exec_info->Version.Minor, exec_info->Version.Build, exec_info->Version.QFE);
    printf("  Base Version:       v%d.%d.%d.%d\n", exec_info->BaseVersion.Major, exec_info->BaseVersion.Minor, exec_info->BaseVersion.Build, exec_info->BaseVersion.QFE);
    printf("  Platform:           %d\n", exec_info->Platform);
    printf("  Executable Type:    %d\n", exec_info->ExecutableType);
    printf("  Disc Number:        %d\n", exec_info->DiscNum);
    printf("  Number of Discs:    %d\n", exec_info->DiscsInSet);
  }

  auto* exec_info25 = xex.opt_header_ptr<xex_opt::xex25::XexExecutionId>(XEX_HEADER_EXECUTION_ID_BETA);
  if (exec_info25)
  {
    printf("\nExecution ID (XEX25)\n");
    printf("  Media ID:           %08X\n", (uint32_t)exec_info25->MediaID);
    printf("  Title ID:           %08X\n", (uint32_t)exec_info25->TitleID);
    printf("  Savegame ID:        %08X\n", (uint32_t)exec_info25->SaveGameID);
    printf("  Version:            v%d.%d.%d.%d\n", exec_info25->Version.Major, exec_info25->Version.Minor, exec_info25->Version.Build, exec_info25->Version.QFE);
    printf("  Platform:           %d\n", (uint32_t)exec_info25->Platform);
    printf("  Executable Type:    %d\n", (uint32_t)exec_info25->ExecutableType);
    printf("  Disc Number:        %d\n", (uint32_t)exec_info25->DiscNum);
    printf("  Number of Discs:    %d\n", (uint32_t)exec_info25->DiscsInSet);
  }

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
    ("b,basefile", "Dump basefile from XEX", cxxopts::value<std::string>())
    ("d,dumpres", "Dump all resources to a dir (can be '.')", cxxopts::value<std::string>())
    ("v,verbose", "Enables verbose XEXFile debug output")
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
    printf("Error loading XEX file %s\n", filepath.c_str());
    return 0;
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
        printf("File Type:       Binary file");
        printf("Processor Type:  PowerPC: ppcbe");
        printf("Load Address:    0x%08X", xex.base_address());
        printf("Entry Point:     0x%08X", xex.entry_point());
      }
    }
  }

  if (result.count("d")) {
    auto& sections = xex.xex_sections();
    if (sections.size())
    {
      auto& dump_path_s = result["d"].as<std::string>();
      if (dump_path_s != ".")
        std::filesystem::create_directory(dump_path_s);
      std::filesystem::path dump_path = dump_path_s;
      for (auto section : sections)
      {
        char sectname[9];
        memset(sectname, 0, 9);
        memcpy(sectname, section.Name, 8);

        std::filesystem::path res_path = dump_path / sectname;
        FILE* file;
        if (auto res = fopen_s(&file, res_path.string().c_str(), "wb") != 0 || !file) {
          printf("Error %d opening file %s for writing\n", res, res_path.string().c_str());
        }
        else {
          auto addr = xex.pe_rva_to_offset(section.VirtualAddress);
          auto* data = xex.pe_data() + addr;
          fwrite(data, 1, std::min(section.SizeOfRawData, section.VirtualSize), file);
          fclose(file);
          printf("Extracted resource %.8s to %s\n", section.Name, res_path.string().c_str());
        }
      }
    }
  }

  if (result["l"].as<bool>() || result["m"].as<bool>())
    PrintInfo(xex, result["m"].as<bool>());
}