#include <arpa/inet.h>//ip -> bin
#include <cstdio>
#include <iostream>
#include <pcap.h>
#include <radiotap.h>
//#include <ieee802_11.h>
#include <netinet/in.h>
#include <map>
#include "80211header.h"

using namespace std;

#define PCAP_OPENFLAG_PROMISCUOUS 1   // Even if it isn't my mac, receive packet

struct pcap_pkthdr *pkt_header;
struct ieee80211_radiotap_header *irh;  //ieee802.11 radiotap
struct Type_Subtype *ts;
struct Beacon_frame *b_f;
struct tag0 *t0;
struct tag1 *t1;
struct tag3 *t3;

char errbuf[PCAP_ERRBUF_SIZE];

int main(int argc, char **argv)
{
    char *dev;
    dev = argv[1];
    if(argc < 2)
    {
        printf("Input argument error!\n");
        if (dev == NULL)
        {
            printf("Your device is : %s\n",dev);
            exit(1);
        }
    }
    else
    printf("DEV : %s\n", dev);

    pcap_t *fp;
    if((fp= pcap_open_live(dev, BUFSIZ, PCAP_OPENFLAG_PROMISCUOUS , 1, errbuf)) == NULL)
    {
        fprintf(stderr,"Unable to open the adapter. %s is not supported by Pcap\n", dev);
    }
    const u_char *pkt_data;
    int res;
    int i;
    int pkt_length;

    int bf = 0;
    int d = 0;
    int p = 0;
    int q = 0;
    int n = 0;

    while(1)
    {
        while((res=pcap_next_ex(fp,&pkt_header,&pkt_data))>=0)
        {
            if(res == 0)continue;
            pkt_length = pkt_header->len;
            irh = (struct ieee80211_radiotap_header*)pkt_data;
            /*
            printf("-------------------ieee802.11 packet-------------------\n");
            printf("Header revision : %02x\n",irh->it_version);
            printf("Header pad : %02x\n",irh->it_pad);
            printf("Header length : %d\n",irh->it_len);
            printf("Present flags : %02x\n",irh->it_present);
            */
            pkt_data += irh->it_len;
            pkt_length -= irh->it_len;

            ts = (struct Type_Subtype*)pkt_data;
            printf("Frame control : %02x\n",ts->fc);    //Frame Control Field
            //printf("Duration : %02x\n",ts->duration);   //Duration
                switch(ts->fc){
                case 0x80:
                    //printf("Beacon Frame\n");
                    pkt_data += 4;  //type_subtype length
                    pkt_length -= 4;
                    b_f = (struct Beacon_frame*)pkt_data;
                    printf("Da : ");
                    for(i=0;i<6;i++)
                        printf("%02x ",b_f->da[i]);
                    printf("\n");
                    printf("Sa : ");
                    for(i=0;i<6;i++)
                        printf("%02x ",b_f->sa[i]);
                    printf("\n");
                    printf("Bssid : ");
                    for(i=0;i<6;i++)
                        printf("%02x ",b_f->bssid[i]);
                    printf("\n");

                    pkt_data +=32;  //jump to tag 20 + 12
                    pkt_length -=32;
                    while(pkt_length>0)
                    {
                        switch(pkt_data[0])
                        case 0x00:
                            t0 = (struct tag0*)pkt_data;
                            //printf("Tag Number : %02x\n",t0->tag_number);
                            printf("ESSID's length : %d\n",t0->tag_length);
                            for(i=0;i<t0->tag_length;i++)
                                printf("%c",t0->ESSID[i]);
                            printf("\n");
                            pkt_data += 2+t0->tag_length;//total tag's length
                            pkt_length -= 2+t0->tag_length;
                            //break;
                        case 0x01:
                            t1 = (struct tag1*)pkt_data;
                            //printf("Tag Number : %02x\n",t1->tag_number);
                            pkt_data += 2+t1->tag_length;
                            pkt_length -= 2+t1->tag_length;
                            //break;
                        case 0x03:
                            t3 = (struct tag3*)pkt_data;
                            //printf("Tag Number : %02x\n",t3->tag_number);
                            printf("Chanel : %d\n",t3->chanel);
                            pkt_data += 2+t3->tag_length;
                            pkt_length -= 2+t3->tag_length;
                           break;
                    }
                    bf++;
                    break;
                case 0x4208:
                    //printf("Data\n");
                    d++;
                    break;
                case 0x40:
                    //printf("Probe\n");
                    p++;
                    break;
                case 0x4188:
                case 0x4288:
                    //printf("QosData\n");
                    q++;
                    break;

                case 0x1148:
                case 0x0148:
                case 0x0948:
                case 0x1948:
                    n++;
                    break;
            }
            printf("BeaconFrame : %d\n",bf);
            printf("#Data : %d\n",d);
            printf("Probe : %d\n",p);
            printf("QosData : %d\n",q);
            printf("Null : %d\n",n);        //count station to bssid data packet (null function + QOS data)
        }

    }
    return 0;
}
