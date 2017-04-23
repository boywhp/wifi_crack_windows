#ifndef _PROTINSTALL_H_
#define _PROTINSTALL_H_

// Copyright And Configuration Management ----------------------------------
//
//                NDISPROT String Definitions - ProtInstall.h
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


//
// ATTENTION!!!
// ------------
// If you make changes to the NDISPROT string definitions you must also make
// matching changes in this file.
//

////////////////////////////////////////////////////////////////////////////
//// Device Naming String Definitions
//


//
// Driver INF File and PnP ID Names
//
#define NDISPROT_SERVICE_PNP_DEVICE_ID_A      "ms_wifi_lwf"
#define NDISPROT_SERVICE_PNP_DEVICE_ID_W      L"ms_wifi_lwf"

#define NDISPROT_SERVICE_INF_FILE_A           "WIFILWF"
#define NDISPROT_SERVICE_INF_FILE_W           L"WIFILWF"

#ifdef UNICODE
#define NDISPROT_SERVICE_PNP_DEVICE_ID        NDISPROT_SERVICE_PNP_DEVICE_ID_W
#define NDISPROT_SERVICE_INF_FILE             NDISPROT_SERVICE_INF_FILE_W
#else
#define NDISPROT_SERVICE_PNP_DEVICE_ID        NDISPROT_SERVICE_PNP_DEVICE_ID_A
#define NDISPROT_SERVICE_INF_FILE             NDISPROT_SERVICE_INF_FILE_A
#endif

#endif // _PROTINSTALL_H_
