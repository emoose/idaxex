#pragma once

// XEX header types
#define XEX_HEADER_STRUCT(key, struct)    (((key) << 8) | (sizeof (struct) >> 2))
#define XEX_HEADER_FIXED_SIZE(key, size)  (((key) << 8) | ((size) >> 2))
#define XEX_HEADER_ULONG(key)             (((key) << 8) | 1)
#define XEX_HEADER_FLAG(key)              ((key) << 8)
#define XEX_HEADER_SIZEDSTRUCT(key)       (((key) << 8) | 0xFF)
#define XEX_HEADER_STRING(key)            XEX_HEADER_SIZEDSTRUCT(key)

// XEX header IDs (todo: tidy up, add missing IDs?)
#define XEX_HEADER_SECTION_TABLE_BETA     XEX_HEADER_SIZEDSTRUCT (0x0001)
#define XEX_HEADER_SECTION_TABLE          XEX_HEADER_SIZEDSTRUCT (0x0002)
#define XEX_FILE_DATA_DESCRIPTOR_HEADER   XEX_HEADER_SIZEDSTRUCT (0x0003)
#define XEX_PATCH_FILE_BASE_REFERENCE     XEX_HEADER_FIXED_SIZE  (0x0004, 20)
#define XEX_HEADER_DELTA_PATCH_DESCRIPTOR XEX_HEADER_SIZEDSTRUCT (0x0005)

#define XEX_HEADER_KEY_VAULT_PRIVS        XEX_HEADER_STRUCT      (0x0040, xex_opt::XexKeyVaultPrivileges)
#define XEX_HEADER_KEY_VAULT_PRIVS_ALT    XEX_HEADER_SIZEDSTRUCT (0x0040) // alternate keyvault privs header ID? (source: ???)
#define XEX_HEADER_TIME_RANGE             XEX_HEADER_STRUCT      (0x0041, xex_opt::XexSystemTimeRange)
#define XEX_HEADER_TIME_RANGE_ALT         XEX_HEADER_SIZEDSTRUCT (0x0041) // alternate time range header ID?? (source: ???)
#define XEX_HEADER_CONSOLE_ID_TABLE       XEX_HEADER_SIZEDSTRUCT (0x0042) // blocked console ID list?
#define XEX_HEADER_DISC_PROFILE_ID        XEX_HEADER_FIXED_SIZE  (0x0043, 16)

#define XEX_HEADER_BOUND_PATH             XEX_HEADER_STRING      (0x0080)
#define XEX_HEADER_PE_EXPORTS_BETA        XEX_HEADER_STRUCT      (0x0081, IMAGE_DATA_DIRECTORY) // unsure! may be PE exports header in some pre-XEX2, can't remember which
#define XEX_HEADER_DEVICE_ID              XEX_HEADER_FIXED_SIZE  (0x0081, 20)

#define XEX_HEADER_EXECUTION_ID_BETA3F    XEX_HEADER_STRUCT      (0x0100, xex_opt::xex3f::XexExecutionId)

#define XEX_HEADER_ORIGINAL_BASE_ADDRESS  XEX_HEADER_ULONG       (0x0100)
#define XEX_HEADER_ENTRY_POINT            XEX_HEADER_FLAG        (0x0101)
#define XEX_HEADER_PE_BASE                XEX_HEADER_ULONG       (0x0102)
#define XEX_HEADER_IMPORTS_BETA           XEX_HEADER_SIZEDSTRUCT (0x0102) // XEX25
#define XEX_HEADER_IMPORTS                XEX_HEADER_SIZEDSTRUCT (0x0103)
#define XEX_HEADER_STACK_SIZE_BETA        XEX_HEADER_FLAG        (0x0104) // XEX25
#define XEX_HEADER_EXPORTS_XEX1           XEX_HEADER_FLAG        (0x0104) // XEX1
#define XEX_HEADER_TLS_DATA_BETA          XEX_HEADER_STRUCT      (0x0105, xex_opt::XexTlsData) // XEX25

#define XEX_HEADER_VITAL_STATS            XEX_HEADER_STRUCT      (0x0180, xex_opt::XexVitalStats)
#define XEX_HEADER_CALLCAP_IMPORTS        XEX_HEADER_STRUCT      (0x0181, xex_opt::XexCallcapImports)
#define XEX_HEADER_FASTCAP_ENABLED        XEX_HEADER_FLAG        (0x0182)
#define XEX_HEADER_PE_MODULE_NAME         XEX_HEADER_STRING      (0x0183)

#define XEX_HEADER_BUILD_VERSIONS         XEX_HEADER_SIZEDSTRUCT (0x0200)
#define XEX_HEADER_BUILD_VERSIONS_BETA    XEX_HEADER_SIZEDSTRUCT (0x0201) // XEX25

#define XEX_HEADER_TLS_DATA               XEX_HEADER_STRUCT      (0x0201, xex_opt::XexTlsData)
#define XEX_HEADER_STACK_SIZE             XEX_HEADER_FLAG        (0x0202)
#define XEX_HEADER_FSCACHE_SIZE           XEX_HEADER_ULONG       (0x0203)
#define XEX_HEADER_XAPI_HEAP_SIZE         XEX_HEADER_ULONG       (0x0204)

#define XEX_HEADER_PAGE_HEAP_SIZE_FLAGS   XEX_HEADER_STRUCT      (0x0280, xex_opt::XexPageHeapOptions)

#define XEX_HEADER_PRIVILEGES             XEX_HEADER_FLAG        (0x0300)
#define XEX_HEADER_PRIVILEGES_32          XEX_HEADER_FLAG        (0x0301) // privilege IDs 32 onward
#define XEX_HEADER_PRIVILEGES_64          XEX_HEADER_FLAG        (0x0302) // privilege IDs 64 onward

#define XEX_HEADER_EXECUTION_ID           XEX_HEADER_STRUCT      (0x0400, xex_opt::XexExecutionId)
#define XEX_HEADER_EXECUTION_ID_BETA      XEX_HEADER_STRUCT      (0x0400, xex_opt::xex25::XexExecutionId) // XEX25
#define XEX_HEADER_SERVICE_ID_LIST        XEX_HEADER_SIZEDSTRUCT (0x0401)
#define XEX_HEADER_WORKSPACE_SIZE         XEX_HEADER_ULONG       (0x0402)
#define XEX_HEADER_GAME_RATINGS           XEX_HEADER_FIXED_SIZE  (0x0403, 64)
#define XEX_HEADER_LAN_KEY                XEX_HEADER_FIXED_SIZE  (0x0404, 16)
#define XEX_HEADER_MSLOGO                 XEX_HEADER_SIZEDSTRUCT (0x0405)
#define XEX_HEADER_MULTIDISK_MEDIA_IDS    XEX_HEADER_SIZEDSTRUCT (0x0406)
#define XEX_HEADER_ALTERNATE_TITLE_IDS    XEX_HEADER_SIZEDSTRUCT (0x0407)
#define XEX_HEADER_ADDITIONAL_TITLE_MEM   XEX_HEADER_ULONG       (0x0408)

#define XEX_HEADER_PE_IMPORTS             XEX_HEADER_STRUCT      (0xE103, IMAGE_DATA_DIRECTORY) // unsure if this is correct struct!
#define XEX_HEADER_PE_EXPORTS             XEX_HEADER_STRUCT      (0xE104, IMAGE_DATA_DIRECTORY)
#define XEX_HEADER_USERMODE_IMPORTS       XEX_HEADER_SIZEDSTRUCT (0xE105)
