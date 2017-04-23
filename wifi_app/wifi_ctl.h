#ifndef __WIFI_CTL_H__
#define __WIFI_CTL_H__

#ifdef __cplusplus
extern "C" {
#endif

#define DOT11_OPERATION_MODE_UNKNOWN            0x00000000
#define DOT11_OPERATION_MODE_STATION            0x00000001
#define DOT11_OPERATION_MODE_AP                 0x00000002
#define DOT11_OPERATION_MODE_EXTENSIBLE_STATION 0x00000004
#define DOT11_OPERATION_MODE_EXTENSIBLE_AP      0x00000008
#define DOT11_OPERATION_MODE_NETWORK_MONITOR    0x80000000

#define _NDIS_CONTROL_CODE(request,method) \
            CTL_CODE(FILE_DEVICE_PHYSICAL_NETCARD, request, method, FILE_ANY_ACCESS)

#define IOCTL_FILTER_ENUERATE_ALL_INSTANCES _NDIS_CONTROL_CODE(2, METHOD_BUFFERED)

#define IOCTL_FILTER_GET_CHANNEL        _NDIS_CONTROL_CODE(14, METHOD_BUFFERED)
#define IOCTL_FILTER_SET_NICMODE        _NDIS_CONTROL_CODE(15, METHOD_BUFFERED)
#define IOCTL_FILTER_SET_CHANNEL        _NDIS_CONTROL_CODE(16, METHOD_BUFFERED)
#define IOCTL_FILTER_READ_PACKET        _NDIS_CONTROL_CODE(17, METHOD_BUFFERED)
#define IOCTL_FILTER_SEND_PACKET        _NDIS_CONTROL_CODE(18, METHOD_BUFFERED)
#define IOCTL_FILTER_SET_PROMISCUOUS    _NDIS_CONTROL_CODE(19, METHOD_BUFFERED)
#define IOCTL_FILTER_SET_PHYID          _NDIS_CONTROL_CODE(20, METHOD_BUFFERED)

int     init_wifi_device();
void    close_wifi_device();

ULONG   wifi_get_channel();
BOOL    wifi_set_channel(ULONG channel);
ULONG   wifi_set_mode(ULONG mode);
BOOL    wifi_set_phytype(ULONG phytype);
ULONG   wifi_read_packet(PVOID buf, ULONG len);
BOOL    wifi_write_packet(PVOID buf, ULONG len);
BOOL    wifi_send_deauth(PVOID bssid, PVOID sta);

//WLAN API FOR vc6
typedef enum _WLAN_INTERFACE_STATE { 
        wlan_interface_state_not_ready              = 0,
        wlan_interface_state_connected              = 1,
        wlan_interface_state_ad_hoc_network_formed  = 2,
        wlan_interface_state_disconnecting          = 3,
        wlan_interface_state_disconnected           = 4,
        wlan_interface_state_associating            = 5,
        wlan_interface_state_discovering            = 6,
        wlan_interface_state_authenticating         = 7
} WLAN_INTERFACE_STATE, *PWLAN_INTERFACE_STATE;

typedef struct _WLAN_INTERFACE_INFO {
        GUID                 InterfaceGuid;
        WCHAR                strInterfaceDescription[256];
        WLAN_INTERFACE_STATE isState;
} WLAN_INTERFACE_INFO, *PWLAN_INTERFACE_INFO;

typedef struct _WLAN_INTERFACE_INFO_LIST {
        DWORD               dwNumberOfItems;
        DWORD               dwIndex;
        WLAN_INTERFACE_INFO InterfaceInfo[];
} WLAN_INTERFACE_INFO_LIST, *PWLAN_INTERFACE_INFO_LIST;

#define DOT11_SSID_MAX_LENGTH  32
#define WLAN_MAX_PHY_TYPE_NUMBER        8

typedef struct _DOT11_SSID {
        ULONG uSSIDLength;
        UCHAR ucSSID[DOT11_SSID_MAX_LENGTH];
} DOT11_SSID, *PDOT11_SSID;

typedef enum _DOT11_BSS_TYPE { 
        dot11_BSS_type_infrastructure  = 1,
        dot11_BSS_type_independent     = 2,
        dot11_BSS_type_any             = 3
} DOT11_BSS_TYPE, *PDOT11_BSS_TYPE;

typedef enum _DOT11_PHY_TYPE { 
        dot11_phy_type_unknown     = 0,
        dot11_phy_type_any         = 0,
        dot11_phy_type_fhss        = 1,
        dot11_phy_type_dsss        = 2,
        dot11_phy_type_irbaseband  = 3,
        dot11_phy_type_ofdm        = 4,
        dot11_phy_type_hrdsss      = 5,
        dot11_phy_type_erp         = 6,
        dot11_phy_type_ht          = 7,
        dot11_phy_type_vht         = 8,
        dot11_phy_type_IHV_start   = 0x80000000,
        dot11_phy_type_IHV_end     = 0xffffffff
} DOT11_PHY_TYPE, *PDOT11_PHY_TYPE;

typedef enum _DOT11_AUTH_ALGORITHM { 
        DOT11_AUTH_ALGO_80211_OPEN        = 1,
                DOT11_AUTH_ALGO_80211_SHARED_KEY  = 2,
                DOT11_AUTH_ALGO_WPA               = 3,
                DOT11_AUTH_ALGO_WPA_PSK           = 4,
                DOT11_AUTH_ALGO_WPA_NONE          = 5,
                DOT11_AUTH_ALGO_RSNA              = 6,
                DOT11_AUTH_ALGO_RSNA_PSK          = 7,
                DOT11_AUTH_ALGO_IHV_START         = 0x80000000,
                DOT11_AUTH_ALGO_IHV_END           = 0xffffffff
} DOT11_AUTH_ALGORITHM, *PDOT11_AUTH_ALGORITHM;

typedef enum _DOT11_CIPHER_ALGORITHM { 
        DOT11_CIPHER_ALGO_NONE           = 0x00,
                DOT11_CIPHER_ALGO_WEP40          = 0x01,
                DOT11_CIPHER_ALGO_TKIP           = 0x02,
                DOT11_CIPHER_ALGO_CCMP           = 0x04,
                DOT11_CIPHER_ALGO_WEP104         = 0x05,
                DOT11_CIPHER_ALGO_WPA_USE_GROUP  = 0x100,
                DOT11_CIPHER_ALGO_RSN_USE_GROUP  = 0x100,
                DOT11_CIPHER_ALGO_WEP            = 0x101,
                DOT11_CIPHER_ALGO_IHV_START      = 0x80000000,
                DOT11_CIPHER_ALGO_IHV_END        = 0xffffffff
} DOT11_CIPHER_ALGORITHM, *PDOT11_CIPHER_ALGORITHM;

typedef struct _WLAN_AVAILABLE_NETWORK {
        WCHAR                  strProfileName[256];
        DOT11_SSID             dot11Ssid;
        DOT11_BSS_TYPE         dot11BssType;
        ULONG                  uNumberOfBssids;
        BOOL                   bNetworkConnectable;
        ULONG       wlanNotConnectableReason;
        ULONG                  uNumberOfPhyTypes;
        DOT11_PHY_TYPE         dot11PhyTypes[WLAN_MAX_PHY_TYPE_NUMBER];
        BOOL                   bMorePhyTypes;
        ULONG    wlanSignalQuality;
        BOOL                   bSecurityEnabled;
        DOT11_AUTH_ALGORITHM   dot11DefaultAuthAlgorithm;
        DOT11_CIPHER_ALGORITHM dot11DefaultCipherAlgorithm;
        DWORD                  dwFlags;
        DWORD                  dwReserved;
} WLAN_AVAILABLE_NETWORK, *PWLAN_AVAILABLE_NETWORK;

typedef struct _WLAN_AVAILABLE_NETWORK_LIST {
        DWORD                  dwNumberOfItems;
        DWORD                  dwIndex;
        WLAN_AVAILABLE_NETWORK Network[1];
} WLAN_AVAILABLE_NETWORK_LIST, *PWLAN_AVAILABLE_NETWORK_LIST;

#define DOT11_RATE_SET_MAX_LENGTH               126 // 126 bytes

typedef struct _WLAN_RATE_SET {
        ULONG  uRateSetLength;
        USHORT usRateSet[DOT11_RATE_SET_MAX_LENGTH];
} WLAN_RATE_SET, *PWLAN_RATE_SET;

typedef struct _WLAN_BSS_ENTRY {
        DOT11_SSID        dot11Ssid;
        ULONG             uPhyId;
        UCHAR dot11Bssid[6];//MAC
        DOT11_BSS_TYPE    dot11BssType;
        DOT11_PHY_TYPE    dot11BssPhyType;
        LONG              lRssi;
        ULONG             uLinkQuality;
        BOOLEAN           bInRegDomain;
        USHORT            usBeaconPeriod;
        ULONGLONG         ullTimestamp;
        ULONGLONG         ullHostTimestamp;
        USHORT            usCapabilityInformation;
        ULONG             ulChCenterFrequency;
        WLAN_RATE_SET     wlanRateSet;
        ULONG             ulIeOffset;
        ULONG             ulIeSize;
} WLAN_BSS_ENTRY, *PWLAN_BSS_ENTRY;

typedef struct _WLAN_BSS_LIST {
        DWORD          dwTotalSize;
        DWORD          dwNumberOfItems;
        WLAN_BSS_ENTRY wlanBssEntries[1];
} WLAN_BSS_LIST, *PWLAN_BSS_LIST;

typedef enum _WLAN_INTF_OPCODE { 
        wlan_intf_opcode_autoconf_start                              = 0x000000000,
                wlan_intf_opcode_autoconf_enabled,
                wlan_intf_opcode_background_scan_enabled,
                wlan_intf_opcode_media_streaming_mode,
                wlan_intf_opcode_radio_state,
                wlan_intf_opcode_bss_type,
                wlan_intf_opcode_interface_state,
                wlan_intf_opcode_current_connection,
                wlan_intf_opcode_channel_number,
                wlan_intf_opcode_supported_infrastructure_auth_cipher_pairs,
                wlan_intf_opcode_supported_adhoc_auth_cipher_pairs,
                wlan_intf_opcode_supported_country_or_region_string_list,
                wlan_intf_opcode_current_operation_mode,
                wlan_intf_opcode_supported_safe_mode,
                wlan_intf_opcode_certified_safe_mode,
                wlan_intf_opcode_hosted_network_capable,
                wlan_intf_opcode_management_frame_protection_capable,
                wlan_intf_opcode_autoconf_end                                = 0x0fffffff,
                wlan_intf_opcode_msm_start                                   = 0x10000100,
                wlan_intf_opcode_statistics,
                wlan_intf_opcode_rssi,
                wlan_intf_opcode_msm_end                                     = 0x1fffffff,
                wlan_intf_opcode_security_start                              = 0x20010000,
                wlan_intf_opcode_security_end                                = 0x2fffffff,
                wlan_intf_opcode_ihv_start                                   = 0x30000000,
                wlan_intf_opcode_ihv_end                                     = 0x3fffffff
} WLAN_INTF_OPCODE, *PWLAN_INTF_OPCODE;

typedef enum _WLAN_OPCODE_VALUE_TYPE { 
        wlan_opcode_value_type_query_only           = 0,
                wlan_opcode_value_type_set_by_group_policy  = 1,
                wlan_opcode_value_type_set_by_user          = 2,
                wlan_opcode_value_type_invalid              = 3
} WLAN_OPCODE_VALUE_TYPE, *PWLAN_OPCODE_VALUE_TYPE;

typedef enum _WLAN_INTERFACE_TYPE { 
        wlan_interface_type_emulated_802_11  = 0,
                wlan_interface_type_native_802_11,
                wlan_interface_type_invalid
} WLAN_INTERFACE_TYPE, *PWLAN_INTERFACE_TYPE;

#define WLAN_MAX_PHY_INDEX	64

typedef struct _WLAN_INTERFACE_CAPABILITY {
        WLAN_INTERFACE_TYPE interfaceType;
        BOOL                bDot11DSupported;
        DWORD               dwMaxDesiredSsidListSize;
        DWORD               dwMaxDesiredBssidListSize;
        DWORD               dwNumberOfSupportedPhys;
        DOT11_PHY_TYPE      dot11PhyTypes[WLAN_MAX_PHY_INDEX];
} WLAN_INTERFACE_CAPABILITY, *PWLAN_INTERFACE_CAPABILITY;

typedef enum _DOT11_RADIO_STATE { 
        dot11_radio_state_unknown,
                dot11_radio_state_on,
                dot11_radio_state_off
} DOT11_RADIO_STATE, *PDOT11_RADIO_STATE;

typedef struct _WLAN_PHY_RADIO_STATE {
        DWORD             dwPhyIndex;
        DOT11_RADIO_STATE dot11SoftwareRadioState;
        DOT11_RADIO_STATE dot11HardwareRadioState;
} WLAN_PHY_RADIO_STATE, *PWLAN_PHY_RADIO_STATE;

typedef struct _WLAN_RADIO_STATE {
        DWORD                dwNumberOfPhys;
        WLAN_PHY_RADIO_STATE PhyRadioState[64];
} WLAN_RADIO_STATE, *PWLAN_RADIO_STATE;

typedef DWORD (WINAPI * WlanGetInterfaceCapability_FUNC)(HANDLE hClientHandle, const GUID *pInterfaceGuid, PVOID pReserved, PWLAN_INTERFACE_CAPABILITY *ppCapability);
typedef DWORD (WINAPI * WlanQueryInterface_FUNC)(HANDLE hClientHandle, const GUID *pInterfaceGuid,WLAN_INTF_OPCODE OpCode, PVOID pReserved, PDWORD pdwDataSize, PVOID *ppData, PWLAN_OPCODE_VALUE_TYPE pWlanOpcodeValueType);
typedef DWORD (WINAPI * WlanOpenHandle_FUNC)(DWORD dwClientVersion, PVOID pReserved, PDWORD pdwNegotiatedVersion, PHANDLE phClientHandle);
typedef DWORD (WINAPI * WlanSetInterface_FUNC)(HANDLE hClientHandle, const GUID *pInterfaceGuid, DWORD OpCode, DWORD dwDataSize, const PVOID pData, PVOID pReserved);
typedef DWORD (WINAPI * WlanEnumInterfaces_FUNC)(HANDLE hClientHandle, PVOID pReserved, PWLAN_INTERFACE_INFO_LIST *ppInterfaceList);
typedef DWORD (WINAPI * WlanGetAvailableNetworkList_FUNC)(HANDLE hClientHandle, const GUID *pInterfaceGuid, DWORD dwFlags, PVOID pReserved, PWLAN_AVAILABLE_NETWORK_LIST *ppAvailableNetworkList);
typedef DWORD (WINAPI * WlanGetNetworkBssList_FUNC)(HANDLE hClientHandle, const GUID *pInterfaceGuid, const  PDOT11_SSID pDot11Ssid, DOT11_BSS_TYPE dot11BssType, BOOL bSecurityEnabled, PVOID pReserved, PWLAN_BSS_LIST *ppWlanBssList);
typedef DWORD (WINAPI * WlanCloseHandle_FUNC)(HANDLE hClientHandle, PVOID pReserved);
typedef void (WINAPI * WlanFreeMemory_FUNC)(PVOID pMemory);

extern WlanOpenHandle_FUNC                      WlanOpenHandle;
extern WlanSetInterface_FUNC                    WlanSetInterface;
extern WlanEnumInterfaces_FUNC                  WlanEnumInterfaces;
extern WlanGetAvailableNetworkList_FUNC         WlanGetAvailableNetworkList;
extern WlanFreeMemory_FUNC                      WlanFreeMemory;
extern WlanCloseHandle_FUNC                     WlanCloseHandle;
extern WlanQueryInterface_FUNC                  WlanQueryInterface;
extern WlanGetInterfaceCapability_FUNC          WlanGetInterfaceCapability;

int init_wlan_api();

#ifdef __cplusplus
}
#endif

#endif