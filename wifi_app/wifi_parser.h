#ifndef __WIFI_PASER_H__
#define __WIFI_PASER_H__

#ifdef __cplusplus
extern "C" {
#endif

typedef unsigned int    guint32;
typedef unsigned short  guint16;
typedef int             gint32;

#define LINKTYPE_IEEE802_11     105

typedef struct pcap_hdr_s {
        guint32 magic_number;   /* magic number */
        guint16 version_major;  /* major version number */
        guint16 version_minor;  /* minor version number */
        gint32  thiszone;       /* GMT to local correction */
        guint32 sigfigs;        /* accuracy of timestamps */
        guint32 snaplen;        /* max length of captured packets, in octets */
        guint32 network;        /* data link type */
} pcap_hdr_t;

typedef struct pcaprec_hdr_s {
        guint32 ts_sec;         /* timestamp seconds */
        guint32 ts_usec;        /* timestamp microseconds */
        guint32 incl_len;       /* number of octets of packet saved in file */
        guint32 orig_len;       /* actual length of packet */
} pcaprec_hdr_t;

void*   open_pcap_file(const char* file_name);
int     write_pcap_file(void* file, void* buf, int len);
int     read_pcap_file(void* file, void* buf, int len);
void    close_pcap_file(void* file);

/*
 * 802.11 wifi structs defines
 */
typedef unsigned char           uint8_t;
typedef unsigned short          uint16_t;
typedef unsigned int            uint32_t;
typedef uint16_t                USHORT;
typedef uint8_t                 UCHAR;
typedef unsigned __int64        ULONGLONG;

#pragma pack(push, 1)

#define DOT11_MAX_CHANNEL       14
#define DOT11_MIN_CHANNEL       1

// copy from wdk usbnwifi/inc/80211hdr.h
#define DOT11_ADDRESS_SIZE 6

#define DOT11_CURRENT_VERSION  0

#define DOT11_MAX_MSDU_SIZE     (2346U)

typedef enum {
        DOT11_FRAME_TYPE_MANAGEMENT = 0,
        DOT11_FRAME_TYPE_CONTROL = 1,
        DOT11_FRAME_TYPE_DATA = 2,
        DOT11_FRAME_TYPE_RESERVED = 3,
} DOT11_FRAME_TYPE, * PDOT11_FRAME_TYPE;

typedef enum {
        DOT11_MGMT_SUBTYPE_ASSOCIATION_REQUEST = 0,    // Association Request
        DOT11_MGMT_SUBTYPE_ASSOCIATION_RESPONSE = 1,   // Association Response
        DOT11_MGMT_SUBTYPE_REASSOCIATION_REQUEST = 2,  // Ressociation Request
        DOT11_MGMT_SUBTYPE_REASSOCIATION_RESPONSE = 3, // Reassociation Response
        DOT11_MGMT_SUBTYPE_PROBE_REQUEST = 4,          // Probe Request
        DOT11_MGMT_SUBTYPE_PROBE_RESPONSE = 5,         // Probe Response
                
        DOT11_MGMT_SUBTYPE_BEACON = 8,                 // Beacon
        DOT11_MGMT_SUBTYPE_ATIM = 9,                   // Announcement Traffic Indication Message (ATIM)
        DOT11_MGMT_SUBTYPE_DISASSOCIATION = 10,        // Disassociation
        DOT11_MGMT_SUBTYPE_AUTHENTICATION = 11,        // Authentication
        DOT11_MGMT_SUBTYPE_DEAUTHENTICATION = 12,      // Deauthentication
        DOT11_MGMT_SUBTYPE_MANAGEMENT_ACTION = 13,     // Management Action
} DOT11_MGMT_SUBTYPE, * PDOT11_MGMT_SUBTYPE;

typedef union {
        struct {
                USHORT  Version: 2;     // Protocol Version
                USHORT  Type: 2;
                USHORT  Subtype: 4;
                USHORT  ToDS: 1;
                USHORT  FromDS: 1;
                USHORT  MoreFrag: 1;
                USHORT  Retry: 1;
                USHORT  PwrMgt: 1;
                USHORT  MoreData: 1;
                USHORT  WEP: 1;
                USHORT  Order: 1;
        };
        USHORT usValue;
} DOT11_FRAME_CTRL, * PDOT11_FRAME_CTRL;

typedef UCHAR DOT11_MAC_ADDRESS[6];
typedef DOT11_MAC_ADDRESS * PDOT11_MAC_ADDRESS;

typedef union {
        struct {
                USHORT  FragmentNumber: 4;
                USHORT  SequenceNumber: 12;
        };
        USHORT usValue;
} DOT11_SEQUENCE_CONTROL, * PDOT11_SEQUENCE_CONTROL;

// Generic 802.11 header
typedef struct DOT11_MAC_HEADER {
        DOT11_FRAME_CTRL    FrameControl;
        USHORT              DurationID;
        DOT11_MAC_ADDRESS   Address1;
        DOT11_MAC_ADDRESS   Address2;
        DOT11_MAC_ADDRESS   Address3;
} DOT11_MAC_HEADER, * PDOT11_MAC_HEADER;

// Mgmt frame header
typedef struct DOT11_MGMT_HEADER {
    DOT11_FRAME_CTRL        FrameControl;
    USHORT                  DurationID;
    DOT11_MAC_ADDRESS       DA;
    DOT11_MAC_ADDRESS       SA;
    DOT11_MAC_ADDRESS       BSSID;
    DOT11_SEQUENCE_CONTROL  SequenceControl;
} DOT11_MGMT_HEADER, * PDOT11_MGMT_HEADER;
#define DOT11_MGMT_HEADER_SIZE          sizeof(DOT11_MGMT_HEADER)

typedef union {
        struct {
                USHORT          ESS: 1;
                USHORT          IBSS: 1;
                USHORT          CFPollable: 1;
                USHORT          CFPollRequest: 1;
                USHORT          Privacy: 1;
                USHORT          ShortPreamble: 1;
                USHORT          PBCC: 1;
                USHORT          ChannelAgility: 1;
                USHORT          Reserved: 2;
                USHORT          ShortSlotTime:1;
                USHORT          Reserved2: 2;
                USHORT          DSSSOFDM: 1;
                USHORT          Reserved3: 2;
        };        
        USHORT usValue;        
} DOT11_CAPABILITY, * PDOT11_CAPABILITY;

#define RSNA_CIPHER_WEP40       1
#define RSNA_CIPHER_TKIP        2
#define RSNA_CIPHER_CCMP        4
#define RSNA_CIPHER_WEP104      5

// Cipher suite selector types
typedef struct _CIPHER_SUITE_STRUCT	{
        UCHAR Oui[3];// Default 00 0f ac -> 802.11
        UCHAR Type;// Default -> RSNA_CIPHER_CCMP
} CIPHER_SUITE_STRUCT, *PCIPHER_SUITE_STRUCT;

typedef struct {
        USHORT Version;
        CIPHER_SUITE_STRUCT GroupCipherSuite;
        USHORT PairwiseCipherCount;
        
} RSN_INFO;

typedef struct {
        UCHAR   ElementID;      // Element Id
        UCHAR   Length;         // Length of SSID
} DOT11_INFO_ELEMENT, * PDOT11_INFO_ELEMENT;

typedef struct DOT11_BEACON_FRAME {
        ULONGLONG           Timestamp;      // the value of sender's TSFTIMER
        USHORT              BeaconInterval; // the number of time units between target beacon transmission times
        DOT11_CAPABILITY    Capability;
        //DOT11_INFO_ELEMENT  InfoElements;
} DOT11_BEACON_FRAME, * PDOT11_BEACON_FRAME;

#define DOT11_INFO_ELEMENT_ID_SSID                  0
#define DOT11_INFO_ELEMENT_ID_SUPPORTED_RATES       1
#define DOT11_INFO_ELEMENT_ID_FH_PARAM_SET          2
#define DOT11_INFO_ELEMENT_ID_DS_PARAM_SET          3
#define DOT11_INFO_ELEMENT_ID_CF_PARAM_SET          4
#define DOT11_INFO_ELEMENT_ID_TIM                   5
#define DOT11_INFO_ELEMENT_ID_IBSS_PARAM_SET        6
#define DOT11_INFO_ELEMENT_ID_COUNTRY_INFO          7
#define DOT11_INFO_ELEMENT_ID_FH_PARAM              8
#define DOT11_INFO_ELEMENT_ID_FH_PATTERN_TABLE      9
#define DOT11_INFO_ELEMENT_ID_REQUESTED             10
#define DOT11_INFO_ELEMENT_ID_CHALLENGE             16
#define DOT11_INFO_ELEMENT_ID_ERP                   42
#define DOT11_INFO_ELEMENT_ID_RSN                   48
#define DOT11_INFO_ELEMENT_ID_EXTD_SUPPORTED_RATES  50
#define DOT11_INFO_ELEMENT_ID_VENDOR_SPECIFIC       221

//https://searchcode.com/codesearch/view/25924149/
// EAPOL Key descripter frame format related length
#define LEN_KEY_DESC_NONCE			32
#define LEN_KEY_DESC_IV				16
#define LEN_KEY_DESC_RSC			8
#define LEN_KEY_DESC_ID				8
#define LEN_KEY_DESC_REPLAY			8
#define LEN_KEY_DESC_MIC			16

// RSN IE Length definition
#define MAX_LEN_OF_RSNIE         	90
#define MIN_LEN_OF_RSNIE         	8

/* EAPOL-Key types */
#define EAPOL_RC4_KEY		1
#define EAPOL_WPA2_KEY		2	/* 802.11i/WPA2 */
#define EAPOL_WPA_KEY		254	/* WPA */

/* RC4 EAPOL-Key header field sizes */
#define EAPOL_KEY_REPLAY_LEN	8
#define EAPOL_KEY_IV_LEN	16
#define EAPOL_KEY_SIG_LEN	16

/* RC4 EAPOL-Key */
typedef struct {
        unsigned char type;			/* Key Descriptor Type */
        unsigned short length;			/* Key Length (unaligned) */
        unsigned char replay[EAPOL_KEY_REPLAY_LEN];	/* Replay Counter */
        unsigned char iv[EAPOL_KEY_IV_LEN];		/* Key IV */
        unsigned char index;				/* Key Flags & Index */
        unsigned char signature[EAPOL_KEY_SIG_LEN];	/* Key Signature */
        unsigned char key[1];				/* Key (optional) */
} eapol_key_header_t;

typedef	union _KEY_INFO
{
        struct {
                UCHAR	KeyMic:1;
                UCHAR	Secure:1;
                UCHAR	Error:1;
                UCHAR	Request:1;
                UCHAR	EKD_DL:1;       // EKD for AP; DL for STA
                UCHAR	Rsvd:3;
                UCHAR	KeyDescVer:3;   // <------
                UCHAR	KeyType:1;
                UCHAR	KeyIndex:2;
                UCHAR	Install:1;
                UCHAR	KeyAck:1;
        };
        USHORT Value;
}	KEY_INFO, *PKEY_INFO;

// WPA1/2 EAPOL Key descriptor format
typedef	struct _KEY_DESCRIPTER
{
        UCHAR		Type;
        KEY_INFO	KeyInfo;
        USHORT		KeyLength;
        UCHAR		ReplayCounter[LEN_KEY_DESC_REPLAY];
        UCHAR		KeyNonce[LEN_KEY_DESC_NONCE];
        UCHAR		KeyIv[LEN_KEY_DESC_IV];
        UCHAR		KeyRsc[LEN_KEY_DESC_RSC];
        UCHAR		KeyId[LEN_KEY_DESC_ID];
        UCHAR		KeyMic[LEN_KEY_DESC_MIC];
        USHORT		KeyDataLen;
        UCHAR		KeyData[MAX_LEN_OF_RSNIE];
}	KEY_DESCRIPTER, *PKEY_DESCRIPTER;

typedef	struct _EAPOL_PACKET
{
        UCHAR	 			ProVer;
        UCHAR	 			ProType;
        USHORT	 			Length;
        KEY_DESCRIPTER		        KeyDesc;
}	EAPOL_PACKET, *PEAPOL_PACKET;

#define HDSK_FLAG_EAPOL1        1
#define HDSK_FLAG_EAPOL2        2
#define HDSK_FLAG_EAPOL3        4
#define HDSK_FLAG_EAPOL4        8
#define HDSK_FLAG_HDUMP         0x10
#define HDSK_FLAG_FDUMP         0x20

typedef struct _wpa_hdsk
{
        uint8_t ssid[32];
        uint8_t apmac[6];        
        uint8_t stmac[6];     /* supplicant MAC           */
        uint8_t anonce[32];   /* authenticator nonce      */
        uint8_t snonce[32];   /* supplicant nonce         */        
        uint8_t keymic[16];   /* eapol frame MIC          */
        uint8_t keyver;       /* key version (TKIP / AES) */
        uint8_t flags;        /* handshake completion     */
        uint32_t eapol_size;  /* eapol frame size         */
        uint8_t eapol[256];   /* eapol frame contents     */
} wpa_hdsk, *pwpa_hdsk;

#pragma pack(pop)

typedef struct _fake_ap_entry {
        struct _fake_ap_entry* next;
        char ssid[32];
        unsigned char bssid[6];
        struct _wpa_hdsk wpa;
} fake_ap_entry, *pfake_ap_entry;

typedef struct _wifi_sta {
        struct _wifi_sta *next;	        /* next supplicant              */
        struct _wifi_ap *ap;	        /* parent AP                    */
        struct _wpa_hdsk wpa;	        /* WPA handshake data           */
        unsigned char mac[6];           /* client MAC address           */
        pfake_ap_entry fake_ap;         /* current station fake ap list */
        uint8_t eapol_frames[4][512];
        int eapol_frame_lens[4];
        int eapol_count;
        uint32_t eapol_last_tick;
} wifi_sta, *pwifi_sta;

typedef struct _wifi_ap {
        struct _wifi_ap* next;
        unsigned char bssid[6];         //MAC
        unsigned char essid[33];        //SSID NAME

        uint8_t *beacon_frame;
        int beacon_frame_len;

        int tag_channel;
        int channel;
        int wpa_ver;
        int eapol_ok_count;

        int stat_count;
        pwifi_sta station;
} wifi_ap, *pwifi_ap;

typedef struct _wifi_parser {
        pwifi_ap ap_list;
        int ap_num;
        int flag;
        void (*recv)(struct _wifi_parser* parser, void* buf, int len, int channel);
} wifi_parser, *pwifi_parser;

void*   init_wifi_parser();
void    close_wifi_parser(void* parser);
void    dump_wifi_stations(void* parser, void* essid);
int     get_wifi_ap_count(void* parser);
void    wifi_log(const char *fmt, ...);
int     wifi_send_ssid(const char* essid);

#define MAC2STR(a) (a)[0], (a)[1], (a)[2], (a)[3], (a)[4], (a)[5]
#define MACSTR "%02x:%02x:%02x:%02x:%02x:%02x"

extern  int wifi_fake_ap_enable;

#ifdef __cplusplus
}
#endif

#endif