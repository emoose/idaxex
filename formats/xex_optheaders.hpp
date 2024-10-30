#pragma once
#include <cstdint>
#include <cassert>
#include "../3rdparty/byte_order.hpp"
#include "xex_structs.hpp"

namespace xex_opt {
  struct XexImportDescriptor {
    xe::be<uint32_t> Size;
    xe::be<uint32_t> NameTableSize;
    xe::be<uint32_t> ModuleCount;
  };
  static_assert(sizeof(XexImportDescriptor) == 0xC, "xex_opt::XexImportDescriptor");

  struct XexImportTable {
    xe::be<uint32_t> TableSize;
    uint8_t NextImportDigest[0x14];
    xe::be<uint32_t> ModuleNumber;
    xex::Version Version;
    xex::Version VersionMin;
    uint8_t Unused;
    uint8_t ModuleIndex;
    xe::be<uint16_t> ImportCount;

    inline void endian_swap()
    {
      *(uint32_t*)&Version = xe::byte_swap(*(uint32_t*)&Version);
      *(uint32_t*)&VersionMin = xe::byte_swap(*(uint32_t*)&VersionMin);
    }

  };
  static_assert(sizeof(XexImportTable) == 0x28, "xex_opt::XexImportTable");

  namespace xex2d {
    struct XexImportTable {
      xe::be<uint32_t> TableSize;
      uint8_t NextImportDigest[0x14];
      xe::be<uint32_t> ModuleNumber;
      xex::Version Version;
      uint8_t Unused;
      uint8_t ModuleIndex;
      xe::be<uint16_t> ImportCount;
    };
    static_assert(sizeof(XexImportTable) == 0x24, "xex_opt::xex2d::XexImportTable");
  }
  struct XexCallcapImports {
    xe::be<uint32_t> BeginFunctionThunkAddress;
    xe::be<uint32_t> EndFunctionThunkAddress;
  };
  static_assert(sizeof(XexCallcapImports) == 0x8, "xex_opt::XexCallcapImports");

  struct XexExecutionId {
    xe::be<uint32_t> MediaID; // 0x0 sz:0x4
    xex::Version Version; // 0x4 sz:0x4
    xex::Version BaseVersion; // 0x8 sz:0x4
    union {
      xe::be<uint32_t> TitleID; // 0xC sz:0x4
#ifdef _MSC_VER // clang doesn't like these being in union...
      struct {
        xe::be<uint16_t> PublisherID; // 0xC sz:0x2
        xe::be<uint16_t> GameID; // 0xE sz:0x2
      };
#endif
    };
    uint8_t Platform; // 0x10 sz:0x1
    uint8_t ExecutableType; // 0x11 sz:0x1
    uint8_t DiscNum; // 0x12 sz:0x1
    uint8_t DiscsInSet; // 0x13 sz:0x1
    xe::be<uint32_t> SaveGameID; // 0x14 sz:0x4

    inline void endian_swap()
    {
      *(uint32_t*)&BaseVersion = xe::byte_swap(*(uint32_t*)&BaseVersion);
      *(uint32_t*)&Version = xe::byte_swap(*(uint32_t*)&Version);
    }

  }; // size 24
  static_assert(sizeof(XexExecutionId) == 0x18, "xex_opt::XexExecutionId");

  namespace xex25 {
    // xex25 version of execution ID is missing base version, and has 3 extra DWORDs
    // changing the uint8_t fields to uint32_t seems to fill in those extra DWORDs nicely
    struct XexExecutionId {
      xe::be<uint32_t> MediaID;
      xex::Version Version;
      union {
        xe::be<uint32_t> TitleID;
#ifdef _MSC_VER
        struct {
          xe::be<uint16_t> PublisherID;
          xe::be<uint16_t> GameID;
        };
#endif
      };
      xe::be<uint32_t> Platform;
      xe::be<uint32_t> ExecutableType;
      xe::be<uint32_t> DiscNum;
      xe::be<uint32_t> DiscsInSet;
      xe::be<uint32_t> SaveGameID;

      inline void endian_swap()
      {
        *(uint32_t*)&Version = xe::byte_swap(*(uint32_t*)&Version);
      }

    }; // size 32
    static_assert(sizeof(XexExecutionId) == 32, "xex_opt::xex25::XexExecutionId");
  }

  namespace xex2d {
    // xex2d version of execution ID is missing base version and has some extra data removed in later versions
    struct XexExecutionId {
      xe::be<uint32_t> MediaID;
      xex::Version Version;
      union {
        xe::be<uint32_t> TitleID;
#ifdef _MSC_VER
        struct {
          xe::be<uint16_t> PublisherID;
          xe::be<uint16_t> GameID;
        };
#endif
      };
      xe::be<uint16_t> UpdatedVersion;
      xe::be<uint16_t> Region;
      xe::be<uint32_t> Rating;
      uint8_t Platform;
      uint8_t ExecutableType;
      uint8_t SaveGameID;
      uint8_t DiscNum;

      inline void endian_swap()
      {
        *(uint32_t*)&Version = xe::byte_swap(*(uint32_t*)&Version);
      }

    }; // size 24
    static_assert(sizeof(xex_opt::xex2d::XexExecutionId) == 0x18, "xex_opt::xex25::XexExecutionId");
  }

  namespace xex3f {
    struct XexExecutionId {
      xe::be<uint32_t> MediaID;
      xex::Version Version;
      union {
        xe::be<uint32_t> TitleID;
#ifdef _MSC_VER
        struct {
          xe::be<uint16_t> PublisherID;
          xe::be<uint16_t> GameID;
        };
#endif
      };
      xe::be<uint16_t> UpdatedVersion;
      xe::be<uint16_t> Region;
      uint8_t Platform;
      uint8_t ExecutableType;
      uint8_t SaveGameID;
      uint8_t DiscNum;
    }; // size 20
    static_assert(sizeof(xex_opt::xex3f::XexExecutionId) == 0x14, "xex_opt::xex3f::XexExecutionId");
  }

  namespace xex0 {
    struct XexExecutionId {
      xe::be<uint32_t> MediaID;
      xex::Version Version;
      union {
        xe::be<uint32_t> TitleID;
#ifdef _MSC_VER
        struct {
          xe::be<uint16_t> PublisherID;
          xe::be<uint16_t> GameID;
        };
#endif
      };
      xe::be<uint16_t> UpdatedVersion;
      xe::be<uint16_t> Region;
      uint8_t Platform;
      uint8_t ContentType;
      uint8_t SaveGameID;
      uint8_t DiscNum;
    }; // size 20
    static_assert(sizeof(xex_opt::xex0::XexExecutionId) == 0x14, "xex_opt::xex0::XexExecutionId");
  }

  struct XexSectionHeader {
    char SectionName[0x8]; // 0x0 sz:0x8
    xe::be<uint32_t> VirtualAddress; // 0x8 sz:0x4
    xe::be<uint32_t> VirtualSize; // 0xC sz:0x4
  }; // size 16
  static_assert(sizeof(XexSectionHeader) == 0x10, "xex_opt::XexSectionHeader");

  struct XexSectionHeaders {
    xe::be<uint32_t> Size;
    XexSectionHeader Sections[1];
  };
  static_assert(sizeof(XexSectionHeaders) == 0x14, "xex_opt::XexSectionHeaders");

  struct XexImageLibraryVersion {
    char LibraryName[8];
    struct LIBVERSION {
      xe::be<uint16_t> Major;
      xe::be<uint16_t> Minor;
      xe::be<uint16_t> Build;
      xex::ApprovalType ApprovalType;
      uint8_t QFE;
    } Version;
  };
  static_assert(sizeof(XexImageLibraryVersion) == 0x10, "xex_opt::XexImageLibraryVersion");

  struct XexImageLibraryVersions {
    xe::be<uint32_t> Size;
    XexImageLibraryVersion Libraries[1];
  };
  static_assert(sizeof(XexImageLibraryVersions) == 0x14, "xex_opt::XexImageLibraryVersions");

  struct XexPrivileges {
    uint32_t NoForceReboot                   : 1; //= 0x00000001
    uint32_t ForegroundTasks                 : 1; //= 0x00000002
    uint32_t NoOddMapping                    : 1; //= 0x00000004
    uint32_t HandleMceInput                  : 1; //= 0x00000008
    uint32_t RestrictHudFeatures             : 1; //= 0x00000010
    uint32_t HandleGamepadDisconnect         : 1; //= 0x00000020
    uint32_t InsecureSockets                 : 1; //= 0x00000040
    uint32_t Xbox1XspInterop                 : 1; //= 0x00000080
    uint32_t SetDashContext                  : 1; //= 0x00000100
    uint32_t TitleUsesGameVoiceChannel       : 1; //= 0x00000200
    uint32_t TitlePal50Incompatible          : 1; //= 0x00000400
    uint32_t TitleInsecureUtilityDrive       : 1; //= 0x00000800
    uint32_t TitleXamHooks                   : 1; //= 0x00001000
    uint32_t TitlePii                        : 1; //= 0x00002000
    uint32_t CrossplatformSystemLink         : 1; //= 0x00004000
    uint32_t MultidiscSwap                   : 1; //= 0x00008000
    uint32_t MultidiscInsecureMedia          : 1; //= 0x00010000
    uint32_t Ap25Media                       : 1; //= 0x00020000
    uint32_t NoConfirmExit                   : 1; //= 0x00040000
    uint32_t AllowBackgroundDownload         : 1; //= 0x00080000
    uint32_t CreatePersistableRamdrive       : 1; //= 0x00100000
    uint32_t InheritPersistedRamdrive        : 1; //= 0x00200000
    uint32_t AllowHudVibration               : 1; //= 0x00400000
    uint32_t TitleBothUtilityPartitions      : 1; //= 0x00800000
    uint32_t HandleIPTVInput                 : 1; //= 0x01000000
    uint32_t PreferBigButtonInput            : 1; //= 0x02000000
    uint32_t AllowXsamReservation            : 1; //= 0x04000000
    uint32_t MultidiscCrossTitle             : 1; //= 0x08000000
    uint32_t TitleInstallIncompatible        : 1; //= 0x10000000
    uint32_t AllowAvatarGetMetadataByXUID    : 1; //= 0x20000000
    uint32_t AllowControllerSwapping         : 1; //= 0x40000000
    uint32_t DashExtensibilityModule         : 1; //= 0x80000000
  };
  static_assert(sizeof(XexPrivileges) == 4, "xex_opt::XexPrivileges");

  struct XexPrivileges32 {
    uint32_t AllowNetworkReadCancel          : 1; //= 0x00000001
    uint32_t UninterruptableReads            : 1; //= 0x00000002
    uint32_t RequireExperienceFull           : 1; //= 0x00000004
    uint32_t GameVoiceRequiredUI             : 1; //= 0x00000008
    uint32_t TitleSetPresenceString          : 1; //= 0x00000010
    uint32_t NatalTiltControl                : 1; //= 0x00000020
    uint32_t TitleRequiresSkeletalTracking   : 1; //= 0x00000040
    uint32_t TitleSupportsSkeletalTracking   : 1; //= 0x00000080
    uint32_t UseLargeHDsFileCache            : 1; //= 0x00000100
    uint32_t TitleSupportsDeepLink           : 1; //= 0x00000200
    uint32_t TitleBodyProfile                : 1; //= 0x00000400
    uint32_t TitleWinUSB                     : 1; //= 0x00000800
    uint32_t TitleSupportsDeepLinkRefresh    : 1; //= 0x00001000
    uint32_t LocalOnlySockets                : 1; //= 0x00002000
    uint32_t TitleContentAcquireAndDownload  : 1; //= 0x00004000
    uint32_t AllowSystemForeground           : 1; //= 0x00008000
  };
  static_assert(sizeof(XexPrivileges32) == 4, "xex_opt::XexPrivileges32");

  enum XexDataFormat : uint16_t {
    None = 0,
    Raw = 1,
    Compressed = 2,
    DeltaCompressed = 3
  };

  struct XexFileDataDescriptor {
    xe::be<uint32_t> Size;
    xe::be<uint16_t> Flags;
    xe::be<uint16_t> Format;

    XexDataFormat DataFormat() const
    {
      return static_cast<XexDataFormat>((uint16_t)Format);
    }
  };
  static_assert(sizeof(XexFileDataDescriptor) == 8, "xex_opt::XexFileDataDescriptor");

  // After XexFileDataDescriptor when Format == 1 (aka "uncompressed")
  struct XexRawDataDescriptor {
    xe::be<uint32_t> DataSize;
    xe::be<uint32_t> ZeroSize;
  };
  static_assert(sizeof(XexRawDataDescriptor) == 8, "xex_opt::XexRawDataDescriptor");

  struct XexDataDescriptor {
    xe::be<uint32_t> Size;
    uint8_t DataDigest[0x14];
  };
  static_assert(sizeof(XexDataDescriptor) == 0x18, "xex_opt::XexDataDescriptor");

  // After XexFileDataDescriptor when Format == 2 (aka compressed)
  struct XexCompressedDataDescriptor {
    xe::be<uint32_t> WindowSize;
    XexDataDescriptor FirstDescriptor;
  };
  static_assert(sizeof(XexCompressedDataDescriptor) == 0x1C, "xex_opt::XexCompressedDataDescriptor");

  struct XexVitalStats {
    xe::be<uint32_t> Checksum;
    xe::be<uint32_t> Timestamp; // UNIX timestamp
  };
  static_assert(sizeof(XexVitalStats) == 8, "xex_opt::XexVitalStats");

#define XEX_HV_MAGIC_0      0x48000000
#define XEX_HV_MAGIC_HVE      0x00485645
#define XEX_HV_MAGIC_HVI      0x00485649
#define XEX_HV_MAGIC_2      0x48000000

  struct HvImageExportTable { // XEX_HV_MAGIC_HVE magic
    xe::be<uint32_t> Magic[3];
    xe::be<uint32_t> ModuleNumber[2];
    xe::be<uint32_t> Version[3];
    xe::be<uint32_t> ImageBaseAddress;
    xe::be<uint32_t> Count;
    xe::be<uint32_t> Base;
  };
  static_assert(sizeof(HvImageExportTable) == 0x2C, "xex_opt::HvImageExportTable");

  namespace xex1 {
    struct HvImageRootImport { // XEX_HV_MAGIC_HVI magic, only used in XEX1, offset from ImageInfo.RootImportAddress
      xe::be<uint32_t> Magic[3];
      xe::be<uint32_t> ImageBaseAddress;
      xe::be<uint32_t> ImportTableCount;
      uint32_t FirstImportDigest[7]; // contains 0x14 byte hash + 2 uint32s?
    };
    static_assert(sizeof(HvImageRootImport) == 0x30, "xex_opt::xex1::HvImageRootImport");
  }

  struct XexServiceIdList {
    xe::be<uint32_t> Size;
    xe::be<uint32_t> CustomServiceIDs[4];
  };
  static_assert(sizeof(XexServiceIdList) == 0x14, "xex_opt::XexServiceIdList");

  struct XexSystemTimeRange {
    xe::be<uint64_t> Start;
    xe::be<uint64_t> End;
  };
  static_assert(sizeof(XexSystemTimeRange) == 0x10, "xex_opt::XexSystemTimeRange");

  struct XexTlsData {
    xe::be<uint32_t> TlsSlotCount;
    xe::be<uint32_t> AddressOfRawData;
    xe::be<uint32_t> SizeOfRawData;
    xe::be<uint32_t> SizeOfTlsData;
  };
  static_assert(sizeof(XexTlsData) == 0x10, "xex_opt::XexTlsData");

  struct XexKeyVaultPrivileges {
    xe::be<uint64_t> Mask;
    xe::be<uint64_t> Match;
  };
  static_assert(sizeof(XexKeyVaultPrivileges) == 0x10, "xex_opt::XexKeyVaultPrivileges");

  struct XexPageHeapOptions {
    xe::be<uint32_t> Size;
    xe::be<uint32_t> Flags;
  };
  static_assert(sizeof(XexPageHeapOptions) == 0x8, "xex_opt::XexPageHeapOptions");

  struct XexConsoleIdTable {
    xe::be<uint32_t> Size;
    uint8_t ConsoleId[0x5][1];
  };
  static_assert(sizeof(XexConsoleIdTable) == 0xC, "xex_opt::XexConsoleIdTable");

  struct XexDeltaPatchDescriptor {
    xe::be<uint32_t> Size;
    xex::Version TargetVersion;
    xex::Version SourceVersion;
    uint8_t DigestSource[20];
    uint8_t ImageKeySource[16];
    xe::be<uint32_t> SizeOfTargetHeaders;
    xe::be<uint32_t> DeltaHeadersSourceOffset;
    xe::be<uint32_t> DeltaHeadersSourceSize;
    xe::be<uint32_t> DeltaHeadersTargetOffset;
    xe::be<uint32_t> DeltaImageSourceOffset;
    xe::be<uint32_t> DeltaImageSourceSize;
    xe::be<uint32_t> DeltaImageTargetOffset;
  };
  static_assert(sizeof(XexDeltaPatchDescriptor) == 0x4C, "xex_opt::XexDeltaPatchDescriptor");

  struct XexLanKey {
    uint8_t Key[0x10];
  };
  static_assert(sizeof(XexLanKey) == 0x10, "xex_opt::XexLanKey");

  struct XexGameRatings {
    uint8_t Ratings[0x40];
  };
  static_assert(sizeof(XexGameRatings) == 0x40, "xex_opt::XexGameRatings");

#pragma pack(push, 1)
  struct XexStringHeader {
    xe::be<uint32_t> Size;
    char Data[1]; // should be null terminated hopefully
  };
  static_assert(sizeof(XexStringHeader) == 5, "xex_opt::XexStringHeader");
#pragma pack(pop)

  namespace xex3f {
    struct XexSectionHeader {
      char SectionName[8];
      xe::be<uint32_t> VirtualAddress;
      xe::be<uint32_t> VirtualSize;
      xe::be<uint32_t> PointerToRawData;
      xe::be<uint32_t> SizeOfRawData;
      xe::be<uint32_t> PageInfoFlags; // HvPageInfoFlags
      xe::be<uint32_t> Unknown1C;
    };
    static_assert(sizeof(xex3f::XexSectionHeader) == 0x20, "xex_opt::xex3f::XexSectionHeader");
  
    struct XexSectionHeaders {
      xe::be<uint32_t> Size; // (Size - 4) / 0x20 = count
      XexSectionHeader Sections[1];
    };
  }
};
