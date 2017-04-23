#include <Windows.h>
#include <winioctl.h>
#include <stdlib.h>
#include <tchar.h>

#include "wifi_ctl.h"
#include "wifi_parser.h"

HANDLE dev = NULL;
HMODULE wlan_lib = NULL;

typedef struct _instance_info{
        USHORT len;
        PWCHAR name;
        CLSID Guid;
} instance_info, *pinstance_info;

#define MAX_WIFI_INSTANCE       8

typedef struct {
        WCHAR wifi_list[1024];
        instance_info instance[MAX_WIFI_INSTANCE];
        DWORD nic_num;
        pinstance_info cur_nic;
        HANDLE hwlan;
} WifiNic;

WifiNic g_Nic = {0};

BOOL wifi_set_channel(ULONG channel)
{
        char buf[1204] = {0};
        ULONG retBytes = 0;
        
        if (INVALID_HANDLE_VALUE == dev || g_Nic.cur_nic == NULL)
                return -1;
        
        *(PULONG)buf = channel;
        memcpy(buf+4, g_Nic.cur_nic->name, g_Nic.cur_nic->len);
        
        return DeviceIoControl(dev, IOCTL_FILTER_SET_CHANNEL, 
                buf, 
                sizeof(ULONG) + g_Nic.cur_nic->len, 
                NULL, 
                0, 
                &retBytes, 
                NULL);
}

BOOL wifi_write_packet(PVOID buf, ULONG len)
{
        char pkt[4096] = {0};
        ULONG retBytes = 0;
        
        if (len <=0 || len + 4 + g_Nic.cur_nic->len > sizeof(pkt))
                return FALSE;

        *(PULONG)pkt = len;
        memcpy(pkt + 4, buf, len);
        memcpy(pkt + 4 + len, g_Nic.cur_nic->name, g_Nic.cur_nic->len);

        return DeviceIoControl(dev, IOCTL_FILTER_SEND_PACKET, 
                pkt, 
                len + sizeof(ULONG) + g_Nic.cur_nic->len, 
                NULL, 
                0, 
                &retBytes, 
                NULL);
}

#define DEAUTH_REQ      \
        "\xC0\x00\x3A\x01\xCC\xCC\xCC\xCC\xCC\xCC\xBB\xBB\xBB\xBB\xBB\xBB" \
        "\xBB\xBB\xBB\xBB\xBB\xBB\x00\x00\x02\x00"

BOOL wifi_send_deauth(PVOID bssid, PVOID sta)
{
        UCHAR DeauthPacket[32];

        memcpy(DeauthPacket, DEAUTH_REQ, 26);

        //send to station
        if (sta == NULL)
                memset(DeauthPacket+4, 0xff, 6);        //DA
        else
                memcpy(DeauthPacket+4, sta, 6);
        
        memcpy(DeauthPacket+10, bssid, 6);              //SA
        memcpy(DeauthPacket+16, bssid, 6);              //BSSID

        /* send to ap
        if (sta) {
                memcpy(DeauthPacket+4, bssid, 6);
                memcpy(DeauthPacket+10, sta, 6);
                wifi_write_packet(DeauthPacket, 26);
        }*/

        return wifi_write_packet(DeauthPacket, 26);
}

ULONG wifi_read_packet(PVOID buf, ULONG len)
{
        ULONG retBytes = 0;

        if (INVALID_HANDLE_VALUE == dev || g_Nic.cur_nic == NULL)
                return -1;
        
        memcpy(buf, g_Nic.cur_nic->name, g_Nic.cur_nic->len);
        DeviceIoControl(dev, IOCTL_FILTER_READ_PACKET, 
                g_Nic.cur_nic->name, 
                g_Nic.cur_nic->len, 
                buf, 
                len, 
                &retBytes, 
                NULL);

        return retBytes;
}

ULONG wifi_get_channel()
{
        ULONG retBytes = 0, channel = 0;
        
        if (INVALID_HANDLE_VALUE == dev || g_Nic.cur_nic == NULL)
                return -1;

        DeviceIoControl(dev, IOCTL_FILTER_GET_CHANNEL, 
                g_Nic.cur_nic->name, 
                g_Nic.cur_nic->len, 
                &channel, 
                sizeof(channel), 
                &retBytes, 
                NULL);
        
        //_tprintf(_T("wifi_get_channel:%d\n"), channel);

        return channel;
}

BOOL wifi_set_phytype(ULONG phytype)
{
        char buf[1204] = {0};
        ULONG retBytes = 0;
        
        if (INVALID_HANDLE_VALUE == dev || g_Nic.cur_nic == NULL)
                return -1;

        *(PULONG)buf = phytype;
        memcpy(buf+4, g_Nic.cur_nic->name, g_Nic.cur_nic->len);

        return DeviceIoControl(dev, IOCTL_FILTER_SET_PHYID, 
                buf, 
                sizeof(ULONG) + g_Nic.cur_nic->len, 
                NULL, 
                0, 
                &retBytes, 
                NULL);
}

ULONG wifi_set_mode(ULONG mode)
{
        char buf[1204] = {0};
        ULONG i, ret, retBytes = 0, last_mode = 0;
        PWLAN_INTERFACE_CAPABILITY pCapability;
        ULONG radioStateInfoSize = sizeof(WLAN_RADIO_STATE);
        PWLAN_RADIO_STATE pradioStateInfo;

        if (INVALID_HANDLE_VALUE == dev || g_Nic.cur_nic == NULL)
                return -1;

        if (mode == DOT11_OPERATION_MODE_NETWORK_MONITOR && WlanQueryInterface(g_Nic.hwlan,
                &g_Nic.cur_nic->Guid,
                wlan_intf_opcode_radio_state,
                0,
                &radioStateInfoSize,
                (PVOID*)&pradioStateInfo,
                0) == ERROR_SUCCESS) {
                WLAN_PHY_RADIO_STATE radioState;
                
                WlanGetInterfaceCapability(g_Nic.hwlan, &g_Nic.cur_nic->Guid, 0, &pCapability);

                for ( i = 0; i < pradioStateInfo->dwNumberOfPhys; ++i ) {
                        if ( pradioStateInfo->PhyRadioState[i].dwPhyIndex < pCapability->dwNumberOfSupportedPhys
                                && (pCapability->dot11PhyTypes[pradioStateInfo->PhyRadioState[i].dwPhyIndex] == dot11_phy_type_ofdm
                                || pCapability->dot11PhyTypes[pradioStateInfo->PhyRadioState[i].dwPhyIndex] == dot11_phy_type_erp
                                || pCapability->dot11PhyTypes[pradioStateInfo->PhyRadioState[i].dwPhyIndex] == dot11_phy_type_ht)
                                && pradioStateInfo->PhyRadioState[i].dot11HardwareRadioState == dot11_radio_state_on
                                && pradioStateInfo->PhyRadioState[i].dot11SoftwareRadioState != dot11_radio_state_on )
                        {
                                radioState.dwPhyIndex = pradioStateInfo->PhyRadioState[i].dwPhyIndex;
                                radioState.dot11SoftwareRadioState = dot11_radio_state_on;
                                radioState.dot11HardwareRadioState = dot11_radio_state_on;
                                
                                WlanSetInterface(g_Nic.hwlan, 
                                        &g_Nic.cur_nic->Guid, 
                                        wlan_intf_opcode_radio_state, 
                                        sizeof(radioState), 
                                        &radioState, 
                                        0);
                        }
                }

                WlanFreeMemory(pradioStateInfo);
        }

        ret = WlanSetInterface(
                g_Nic.hwlan,
                &g_Nic.cur_nic->Guid,
                wlan_intf_opcode_current_operation_mode,
                sizeof(ULONG),
                &mode,
                NULL
                );

        if (ret == ERROR_SUCCESS){
                if (mode == DOT11_OPERATION_MODE_NETWORK_MONITOR)
                        DeviceIoControl(dev, IOCTL_FILTER_SET_PROMISCUOUS, 
                        g_Nic.cur_nic->name, 
                        g_Nic.cur_nic->len, 
                        NULL, 
                        0, 
                        &retBytes, 
                        NULL);
                
                return 0;
        }

        *(PULONG)buf = mode;
        memcpy(buf+4, g_Nic.cur_nic->name, g_Nic.cur_nic->len);

        DeviceIoControl(dev, IOCTL_FILTER_SET_NICMODE, 
                buf, 
                sizeof(ULONG) + g_Nic.cur_nic->len, 
                &last_mode, 
                sizeof(last_mode), 
                &retBytes, 
                NULL);
        
        _tprintf(_T("wifi_set_monitormode:%x -> %x\n"), last_mode, mode);

        return last_mode;
}

int init_wifi_device()
{
        ULONG ver, retBytes = 0;
        PUCHAR p;
        HANDLE hClientHandle = NULL;
        int i;

        if (wlan_lib == NULL)
                init_wlan_api();

        WlanOpenHandle(2, 0, &ver, &hClientHandle);
        if (hClientHandle == NULL)
                return -1;

        dev = CreateFile(_T("\\\\.\\WIFILWF"),
                GENERIC_READ | GENERIC_WRITE, 
                FILE_SHARE_READ | FILE_SHARE_WRITE, 
                NULL, 
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL, 
                NULL);
        
        if (INVALID_HANDLE_VALUE == dev)
                return -1;

        /* 初始化wifi网卡接口 */
        memset(&g_Nic, 0, sizeof(g_Nic));

        g_Nic.hwlan = hClientHandle;

        DeviceIoControl(dev, IOCTL_FILTER_ENUERATE_ALL_INSTANCES, 
                NULL, 
                0, 
                g_Nic.wifi_list, 
                sizeof(g_Nic.wifi_list), 
                &retBytes, 
                NULL);

        for (p = (PUCHAR)g_Nic.wifi_list; retBytes > 0; ){
                WCHAR GuidString[39] = {0};

                i = g_Nic.nic_num;

                g_Nic.instance[i].len = *(PUSHORT)p;
                g_Nic.instance[i].name = (PWCHAR)(p + sizeof(USHORT));
                if (*(PUSHORT)p < 4)
                        break;
                
                _tprintf(_T("wifi list:%s\n"), g_Nic.instance[i].name);

                memcpy(GuidString, g_Nic.instance[i].name, 38*sizeof(WCHAR));
                CLSIDFromString(GuidString, &g_Nic.instance[i].Guid);
                //StringFromGUID2(nic_info->InterfaceGuid,  (LPOLESTR) &GuidString, sizeof(GuidString)/sizeof(*GuidString));

                p += sizeof(USHORT) + g_Nic.instance[i].len;
                retBytes -= sizeof(USHORT) + g_Nic.instance[i].len;

                g_Nic.nic_num++;
        }

        g_Nic.cur_nic = g_Nic.nic_num > 0 ? g_Nic.instance:NULL;

        //CloseHandle(dev);

        return 0;
}

void close_wifi_device()
{
        if (dev != INVALID_HANDLE_VALUE){
                CloseHandle(dev);
                dev = INVALID_HANDLE_VALUE;
        }

        if (g_Nic.hwlan)
                WlanCloseHandle(g_Nic.hwlan, NULL);
}

WlanOpenHandle_FUNC                     WlanOpenHandle = NULL;
WlanSetInterface_FUNC                   WlanSetInterface = NULL;
WlanEnumInterfaces_FUNC                 WlanEnumInterfaces = NULL;
WlanGetAvailableNetworkList_FUNC        WlanGetAvailableNetworkList = NULL;
WlanFreeMemory_FUNC                     WlanFreeMemory = NULL;
WlanCloseHandle_FUNC                    WlanCloseHandle = NULL;
WlanQueryInterface_FUNC                 WlanQueryInterface = NULL;
WlanGetInterfaceCapability_FUNC         WlanGetInterfaceCapability = NULL;

int init_wlan_api()
{
        wlan_lib = LoadLibrary(_T("Wlanapi.dll"));

        WlanOpenHandle = (WlanOpenHandle_FUNC)GetProcAddress(wlan_lib, "WlanOpenHandle");
        WlanEnumInterfaces = (WlanEnumInterfaces_FUNC)GetProcAddress(wlan_lib, "WlanEnumInterfaces");
        WlanSetInterface = (WlanSetInterface_FUNC)GetProcAddress(wlan_lib, "WlanSetInterface");
        WlanFreeMemory = (WlanFreeMemory_FUNC)GetProcAddress(wlan_lib, "WlanFreeMemory");
        WlanCloseHandle = (WlanCloseHandle_FUNC)GetProcAddress(wlan_lib, "WlanCloseHandle");
        WlanQueryInterface = (WlanQueryInterface_FUNC)GetProcAddress(wlan_lib, "WlanQueryInterface");
        WlanGetInterfaceCapability = (WlanGetInterfaceCapability_FUNC)GetProcAddress(wlan_lib, "WlanGetInterfaceCapability");

        return 0;
}