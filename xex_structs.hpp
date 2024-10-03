#pragma once
#include <cstdint>
#include <cassert>
#include "3rdparty/byte_order.hpp"

namespace xex {
  struct XexModuleFlags {
    uint32_t TitleProcess               : 1; //= 0x00000001
    uint32_t TitleImports               : 1; //= 0x00000002
    uint32_t Debugger                   : 1; //= 0x00000004
    uint32_t Dll                        : 1; //= 0x00000008
    uint32_t Patch                      : 1; //= 0x00000010
    uint32_t PatchFull                  : 1; //= 0x00000020
    uint32_t PatchDelta                 : 1; //= 0x00000040
    uint32_t UserMode                   : 1; //= 0x00000080
    uint32_t                            : 22; //= 0x00000100-0x20000000
    uint32_t BoundPath                  : 1; //= 0x40000000
    uint32_t SilentLoad                 : 1; //= 0x80000000
  };
  static_assert(sizeof(XexModuleFlags) == 4, "xex::XexModuleFlags");

  struct XexHeader {
    xe::be<uint32_t> Magic; // 0x0 sz:0x4
    XexModuleFlags ModuleFlags; // 0x4 sz:0x4
    xe::be<uint32_t> SizeOfHeaders; // 0x8 sz:0x4
    xe::be<uint32_t> SizeOfDiscardableHeaders; // 0xC sz:0x4
    xe::be<uint32_t> SecurityInfo; // 0x10 sz:0x4
    xe::be<uint32_t> HeaderDirectoryEntryCount; // 0x14 sz:0x4
  }; // size 0x18
  static_assert(sizeof(XexHeader) == 0x18, "xex::XexHeader");

  struct ImageFlags {
    uint32_t Unknown1                   : 1; //= 0x00000001
    uint32_t ManufacturingUtility       : 1; //= 0x00000002
    uint32_t ManufacturingSupportTool   : 1; //= 0x00000004
          // ManufacturingAwareModule          = 0x00000006
    uint32_t Xgd2MediaOnly              : 1; //= 0x00000008
    uint32_t DataCenterRequired         : 1; //= 0x00000010
    uint32_t DataCenterAware            : 1; //= 0x00000020
    uint32_t                            : 2; //= 0x00000040-0x00000080

    // HV privileges section:
    uint32_t CardeaKey                  : 1; //= 0x00000100
    uint32_t XeikaKey                   : 1; //= 0x00000200
    uint32_t TitleUserMode              : 1; //= 0x00000400
    uint32_t SystemUserMode             : 1; //= 0x00000800
    uint32_t Orange0                    : 1; //= 0x000010001
    uint32_t Orange1                    : 1; //= 0x00002000
    uint32_t Orange2                    : 1; //= 0x00004000
    uint32_t SignedKeyVaultRequired     : 1; //= 0x00008000
    uint32_t IptvSignupApplication      : 1; //= 0x00010000
    uint32_t IptvTitleApplication       : 1; //= 0x00020000
    uint32_t NccpKeys                   : 1; //= 0x00040000

    uint32_t                            : 7; //= 0x00040000-0x02000000
    uint32_t KeyVaultPrivilegesRequired : 1; //= 0x04000000
    uint32_t OnlineActivationRequired   : 1; //= 0x08000000
    uint32_t PageSize4Kb                : 1; //= 0x10000000
    uint32_t NoGameRegion               : 1; //= 0x20000000
    uint32_t RevocationCheckOptional    : 1; //= 0x40000000
    uint32_t RevocationCheckRequired    : 1; //= 0x80000000
  };
  static_assert(sizeof(ImageFlags) == 4, "xex::ImageFlags");

  enum GameRegion : uint32_t
  {
    Region_NorthAmerica = 0x000000FF,
    Region_Japan = 0x00000100,
    Region_China = 0x00000200,
    Region_RestOfAsia = 0x0000FC00,
    Region_AustraliaNewZealand = 0x00010000,
    Region_RestOfEurope = 0x00FE0000,
    Region_Europe = 0xFF0000,
    Region_RestOfWorld = 0xFF000000,
    Region_All = 0xFFFFFFFF
  };
  static_assert(sizeof(GameRegion) == 4, "xex::GameRegion");

  enum ApprovalType : uint8_t
  {
    ApprovalType_Unapproved = 0x00,
    ApprovalType_Tool = 0x4,
    ApprovalType_Executable = 0x10,
    ApprovalType_PossiblyApproved = 0x20,
    ApprovalType_Approved = 0x40,
    ApprovalType_Expired = 0x60,
    ApprovalType_Debug = 0x80,
  };
  static_assert(sizeof(ApprovalType) == 1, "xex::ApprovalType");

  struct AllowedMediaTypes {
    uint32_t HardDisk                    : 1; //= 0x00000001
    uint32_t DvdX2                       : 1; //= 0x00000002
    uint32_t DvdCd                       : 1; //= 0x00000004
    uint32_t Dvd5                        : 1; //= 0x00000008
    uint32_t Dvd9                        : 1; //= 0x00000010
    uint32_t SystemFlash                 : 1; //= 0x00000020
    uint32_t _Unknown40                  : 1; //= 0x00000040
    uint32_t MemoryUnit                  : 1; //= 0x00000080
    uint32_t MassStorageDevice           : 1; //= 0x00000100
    uint32_t SmbFilesystem               : 1; //= 0x00000200
    uint32_t DirectFromRam               : 1; //= 0x00000400
    uint32_t _Unknown800                 : 1; //= 0x00000800
    uint32_t SecureVirtualOpticalDevice  : 1; //= 0x00001000
    uint32_t WirelessNStorageDevice      : 1; //= 0x00002000 (\Device\Nomnil)
    uint32_t SystemExtendedPartition     : 1; //= 0x00004000 (SEP)
    uint32_t SystemAuxiliaryPartition    : 1; //= 0x00008000 (SAP)
    uint32_t                             : 8; //= 0x00010000-0x00800000
    uint32_t InsecurePackage             : 1; //= 0x01000000
    uint32_t SaveGamePackage             : 1; //= 0x02000000
    uint32_t LocallySignedPackage        : 1; //= 0x04000000
    uint32_t LiveSignedPackage           : 1; //= 0x08000000
    uint32_t XboxPlatformPackage         : 1; //= 0x10000000
  };
  static_assert(sizeof(AllowedMediaTypes) == 4, "xex::AllowedMediaTypes");

  struct Version {
    uint32_t QFE : 8;
    uint32_t Build : 16;
    uint32_t Minor : 4;
    uint32_t Major : 4;
  };
  static_assert(sizeof(Version) == 4, "xex::Version");

  struct XexDirectoryEntry {
    xe::be<uint32_t> Key; // 0x0 sz:0x4
    xe::be<uint32_t> Value; // 0x4 sz:0x4
  }; // size 8
  static_assert(sizeof(XexDirectoryEntry) == 8, "xex::XexDirectoryEntry");

  enum HvPageInfoFlags
  {
    PageInfoFlag_NoWrite = 1,
    PageInfoFlag_NoExecute = 2,
    PageInfoFlag_Protect = 4,
    PageInfoFlag_Encrypt = 8,
  };

  struct HvPageInfo {
    union {
      struct {
        uint32_t Info : 4;
        uint32_t Size : 28;
      };
      uint32_t SizeInfo;
    };
    uint8_t DataDigest[0x14]; // Digest of the next page + next page descriptor
  };
  static_assert(sizeof(HvPageInfo) == 0x18, "xex:HvPageInfo");

  // FunctionType inside RUNTIME_FUNCTION
  enum class RuntimeFunctionType
  {
    SaveMillicode = 0x0,
    NoHandler = 0x1,
    RestoreMillicode = 0x2,
    Handler = 0x3,
  };
};

namespace xex2 {
  struct HvImageInfo {
    uint8_t Signature[0x100];
    xe::be<uint32_t> InfoSize;
    xex::ImageFlags ImageFlags;
    xe::be<uint32_t> LoadAddress;
    uint8_t ImageHash[0x14]; // SHA1(first_page, first_page_descriptor)
    xe::be<uint32_t> ImportTableCount;
    uint8_t ImportDigest[0x14]; // SHA1(import_table[4:])
    uint8_t MediaID[0x10];
    uint8_t ImageKey[0x10];
    xe::be<uint32_t> ExportTableAddress;
    uint8_t HeaderHash[0x14]; // SHA1(xex_headers[0:SizeOfHeaders]) - except for this HvImageInfo section itself, this section is explicitly excluded from the hash!
    xe::be<xex::GameRegion> GameRegion;
  };
  static_assert(sizeof(HvImageInfo) == 0x174, "xex2::HvImageInfo");

  struct SecurityInfo {
    xe::be<uint32_t> Size;
    xe::be<uint32_t> ImageSize;
    HvImageInfo ImageInfo;
    xex::AllowedMediaTypes AllowedMediaTypes;
    xe::be<uint32_t> PageDescriptorCount;
  };
  static_assert(sizeof(SecurityInfo) == 0x184, "xex2::SecurityInfo");
};

namespace xex1 {
  struct HvImageInfo {
    uint8_t Signature[0x100];
    uint8_t ImportDigest[0x14];
    uint8_t ImageHash[0x14]; // confirmed
    xe::be<uint32_t> LoadAddress;
    uint8_t ImageKey[0x10];
    uint8_t MediaID[0x10];
    xe::be<xex::GameRegion> GameRegion;
    xex::ImageFlags ImageFlags;
    xe::be<uint32_t> ExportTableAddress;
  };
  static_assert(sizeof(HvImageInfo) == 0x158, "xex1::HvImageInfo");

  struct SecurityInfo {
    xe::be<uint32_t> Size;
    xe::be<uint32_t> ImageSize;
    HvImageInfo ImageInfo;
    xex::AllowedMediaTypes AllowedMediaTypes;
    xe::be<uint32_t> PageDescriptorCount;
  };
  static_assert(sizeof(SecurityInfo) == 0x168, "xex1::SecurityInfo");
};

namespace xex25 {
  struct HvImageInfo {
    uint8_t Signature[0x100];
    uint8_t ImportDigest[0x14];
    uint8_t ImageHash[0x14];
    xe::be<uint32_t> LoadAddress;
    uint8_t ImageKey[0x10];
    xex::ImageFlags ImageFlags;
    xe::be<uint32_t> ExportTableAddress;
  };
  static_assert(sizeof(HvImageInfo) == 0x144, "xex25::HvImageInfo");

  struct SecurityInfo {
    xe::be<uint32_t> Size;
    xe::be<uint32_t> ImageSize;
    HvImageInfo ImageInfo;
    xex::AllowedMediaTypes AllowedMediaTypes;
    xe::be<uint32_t> PageDescriptorCount;
  };
  static_assert(sizeof(SecurityInfo) == 0x154, "xex25::SecurityInfo");
};

namespace xex2d {
  struct SecurityInfo {
    xe::be<uint32_t> Size;
    uint8_t Signature[0x100];
    uint8_t HeaderHash[0x14];
    uint8_t ImageHash[0x14];
    xe::be<uint32_t> LoadAddress;
    xe::be<uint32_t> ImageSize;
    xe::be<uint32_t> CurrentVersion;
    xe::be<uint32_t> LowestAcceptableVersion;
    xe::be<uint16_t> PageDescriptorCount;
    xe::be<uint16_t> ImageFlags;
  };
  static_assert(sizeof(SecurityInfo) == 0x140, "xex2d::SecurityInfo");
};

namespace xex0 {
  struct ModuleFlags {
    /* 0x01 */ uint32_t SystemProcess : 1;
    /* 0x02 */ uint32_t TitleProcess : 1;
    /* 0x04 */ uint32_t Dll : 1;
    /* 0x08 */ uint32_t Debugger : 1; // xex3f only
  };
  static_assert(sizeof(ModuleFlags) == 4, "xex::ModuleFlags");

  struct XexHeader {
    /* 0x00 */ xe::be<uint32_t> Magic;
    /* 0x04 */ xe::be<uint32_t> SizeOfHeaders;
    /* 0x08 */ xe::be<uint32_t> LoadAddress;
    /* 0x0C */ xe::be<uint32_t> ImageSize;
    /* 0x10 */ xe::be<uint32_t> HeaderDirectoryEntryCount;
  }; // size 0x14
  static_assert(sizeof(XexHeader) == 0x14, "xex0::XexHeader");
};

namespace xex3f {
  struct XexHeader {
    /* 0x00 */ xe::be<uint32_t> Magic;
    /* 0x04 */ xex0::ModuleFlags ModuleFlags;
    /* 0x08 */ xe::be<uint32_t> SizeOfHeaders;
    /* 0x0C */ xe::be<uint32_t> SizeOfDiscardableHeaders;
    /* 0x10 */ xe::be<uint32_t> LoadAddress;
    /* 0x14 */ xe::be<uint32_t> ImageSize;
    /* 0x18 */ xe::be<uint32_t> HeaderDirectoryEntryCount;
  }; // size 0x1C
  static_assert(sizeof(XexHeader) == 0x1C, "xex3f::XexHeader");
};
