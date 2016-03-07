/*--------------------------------------------------------
 * StartClient.c
 *
 *  Created on: 2014-5-15
 *      Author: eshifhu
 * This is the client part of program, mainly function is
 * call the lib of pcap, initial the capture,and socket.
 * a loop function was stuck, once a specified package coming
 * callback function starts.
 * Then, send the information to server side.
 * Data was split to 2 times send, Head infor and LDAP payload
 * infor.
 *--------------------------------------------------------*/

#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ldap.h>
#include <lber-int.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h> 
#include "systemPara.h"

void
got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

void
print_hex_ascii_line(const u_char *payload, int len, int offset);


void
print_app_banner(void);


void
print_app_usage(void);


/*
 * print help text
 */
void
print_app_usage(void)
{



    printf("\n");
    printf("Options:\n");
    printf(" interface Listen on <interface> for packets.\n");
    printf("\n\n");


return;
}


/*
 * print data in rows of 16 bytes: offset hex ascii
 *
 * 00000 47 45 54 20 2f 20 48 54 54 50 2f 31 2e 31 0d 0a GET / HTTP/1.1..
 */
void
print_hex_ascii_line(const u_char *payload, int len, int offset)
{


    int i;
    int gap;
    const u_char *ch;


    /* offset */
    printf("%05d ", offset);
    
    /* hex */
    ch = payload;
    for(i = 0; i < len; i++) {
        printf("%02x ", *ch);
        ch++;
        /* print extra space after 8th byte for visual aid */
        if (i == 7)
            printf(" ");
    }
    /* print space to handle line less than 8 bytes */
    if (len < 8)
        printf(" ");
    
    /* fill hex gap with spaces if not full line */
    if (len < 16) {
        gap = 16 - len;
        for (i = 0; i < gap; i++) {
            printf(" ");
        }
    }
    printf(" ");
    
    /* ascii (if printable) */
    ch = payload;
    for(i = 0; i < len; i++) {
        if (isprint(*ch))
            printf("%c", *ch);
        else
            printf(".");
        ch++;
    }


    printf("\n");


return;
}



/*
 * dissect/print packet
 */
void
got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
	PrintCap capInfor;
	ber_tag_t       tag;
	ber_int_t		msgid;
	ber_int_t		msgid_before;
	ber_len_t       len;
    BerElement      *ber;
    Sockbuf         *sb;
    ber_len_t max = 409600;
	ber_tag_t LdapOpt;
	TcpHeadInfo socketTcpHead;
	
	
	printf("\n\nBeing Inside CallBack Function !\n");
	static int count = 1; /* packet counter */
	printf("\nPacket number %d:\n", count);
	
	socketTcpHead.GetPackageNumber = count;
    count++;
	
	int PPfd[2];
	if(pipe(PPfd)<0)  
  	{  
    	printf("pipe create error!/n");  
    	return ;  
  	}
	    
#ifdef DEBUG	
		/* enable debugging */
        int ival = -1;
        ber_set_option( NULL, LBER_OPT_DEBUG_LEVEL, &ival );
#endif 
		sb = ber_sockbuf_alloc();
    	ber_sockbuf_ctrl( sb, LBER_SB_OPT_SET_MAX_INCOMING, &max );

		
    
	/* declare pointers to packet headers */
    const struct sniff_ethernet *ethernet; 		/* The ethernet header [1] */
    const struct sniff_ip *ip; 					/* The IP header */
    const struct sniff_tcp *tcp; 				/* The TCP header */
    const u_char *payload; 						/* Packet payload */
	
	static int reassembleFlag = 0;				/* The Number of Segments 0: No Reassemble, Non-zero: the number of segment*/
	static char reassemblePack[10]={0,0,0,0,0,0,0,0,0,0}; /*assume max segments is 10 */
	char TcpFlagPush = 1;  						/* Mark the Reassembled TCP segment*/

    int size_ip;
    int size_tcp;
    int size_payload;
    
        
    /* define ethernet header */
    ethernet = (struct sniff_ethernet*)(packet);
    
    /* define/compute ip header offset */
    ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
    size_ip = IP_HL(ip)*4;
    
	if (size_ip < 20) {
        printf(" * Error! Invalid IP header length: %u bytes\n", size_ip);
        return;
    }
	
	socketTcpHead.size_ip = size_ip;
	socketTcpHead.TimeStmap = header->ts;

    /* print source and destination IP addresses */
    //printf(" From: %s\n", inet_ntoa(ip->ip_src));
    //printf(" To: %s\n", inet_ntoa(ip->ip_dst));
	
	memcpy(socketTcpHead.ipSrc, inet_ntoa(ip->ip_src), 16);
	memcpy(socketTcpHead.ipDst, inet_ntoa(ip->ip_dst), 16);
	
	//printf("Debug memCpy__sy IP SRC \n");
    socketTcpHead.Prctl = ip->ip_p;
    
    /* define/compute tcp header offset */
    tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
    size_tcp = TH_OFF(tcp)*4;
	
	/* Check the TCP Flag whether cotains the PSH flag
	If the PSH flag was set, means this is the last Frame,
	Payload should be reassembled, it package without PSH
	this is a large package, package was splited into some pieces */
	
	if (tcp->th_flags & TH_PUSH){
		TcpFlagPush=1;  //The last(only 1) frame
		memcpy(socketTcpHead.ReassemblePakNum,reassemblePack,10);
		
	}else{
		TcpFlagPush=0;  //Tcp transmit on going check next captured info
	}
	/*-------------------------------------*/
	
	socketTcpHead.size_tcp = size_tcp;
	
    if (size_tcp < 20) {
        printf(" Error!* Invalid TCP header length: %u bytes\n", size_tcp);
        return;
    }
    

	//printf(" Src port: %d\n", ntohs(tcp->th_sport));
    //printf(" Dst port: %d\n", ntohs(tcp->th_dport));
	//if (ntohs(tcp->th_sport)==0x185 || ntohs(tcp->th_dport)==0x185)
	//	{
	//		 printf(" LDAP pkt captured!!\n");
	//	}
	
	socketTcpHead.portSrc = ntohs(tcp->th_sport);
	socketTcpHead.portDst = ntohs(tcp->th_dport);
	
    /* define/compute tcp payload (segment) offset */
    payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);
	//print_hex_ascii_line(payload,strlen(payload),0);
	
    
    /* compute tcp payload (segment) size */
    size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);
	//print_hex_ascii_line(payload,size_payload,0);
	//printf("Capinfo: size_payload:%d\n",size_payload);
	
	ReassembleSize+=size_payload;
	socketTcpHead.Payload_size = ReassembleSize;
	socketTcpHead.ReassembleFlag=reassembleFlag;
    
	/*
     * Print payload data; it might be binary, so don't just
     * treat it as a string.
     
    if (size_payload > 0) {
        printf(" Payload (%d bytes):\n", size_payload);
    }*/

	
	char *SocketBuff=(char *)malloc(sizeof(socketTcpHead));
	memcpy(SocketBuff, &socketTcpHead, sizeof(socketTcpHead));
	/*
 	
    		printf("Pkt number:			%d\n", socketTcpHead.GetPackageNumber);
    		printf("IP layer len:		%d\n", socketTcpHead.size_ip);
    		printf("TCP layer len:		%d\n", socketTcpHead.size_tcp);
    		printf("Protocol:			%d\n", socketTcpHead.Prctl);
    		printf("Src IP:				%s\n", socketTcpHead.ipSrc);
    		printf("Dst IP:				%s\n", socketTcpHead.ipDst);
    		printf("Payload len:		%d\n", socketTcpHead.Payload_size);
			printf("The TCP Push Flag:  %d\n", TcpFlagPush);
			printf("ResmFlag:%d\n",socketTcpHead.ReassembleFlag);
			printf("TCP PUSH? :%d\n", TcpFlagPush);
	int i;
	for(i=0;i<10;i++)
	printf("ReassmPack infor[%d]:%d\n",i,reassemblePack[i]);
	*/

	
	
	if(TcpFlagPush){
		
		capInfor.PackageHead = socketTcpHead;
		memcpy((FrameBuff+FrameBuffOffset),payload,size_payload);
				
		write(PPfd[1],FrameBuff,size_payload+FrameBuffOffset);
		ber_sockbuf_add_io( sb, &ber_sockbuf_io_fd, LBER_SBIOD_LEVEL_PROVIDER, (void *)&PPfd[0] );
  		
		ber = ber_alloc_t(LBER_USE_DER);
    		if( ber == NULL ) {
    			printf("\nFailed at:\n  >File name: %s\n  >Function : %s\n  >Line No. : %d\n",  __FILE__, __FUNCTION__, __LINE__);
				perror( "ber_alloc_t" );
    			return( EXIT_FAILURE );
			}
		
		for (;;) {
			
				tag = ber_get_next( sb, &len, ber);
				//printf("\ber_get_next,tag is :%d and size is %d\n", tag, len);
				if( tag != LBER_ERROR ) break;
				if( errno == EWOULDBLOCK ) continue;
				if( errno == EAGAIN ) continue;
				perror( "ber_get_next" );
				printf("\nFailed at:\n  >File name: %s\n  >Function : %s\n  >Line No. : %d\n",  __FILE__, __FUNCTION__, __LINE__);
				return( EXIT_FAILURE );
			}
    		
    		//determine the Ldap option kind 
    		LdapOpt=checkLDAPoption(ber, &msgid);
    		
    		if(LdapOpt==LBER_ERROR){
    			printf("|-Error:LDAP option decode failed.\n");
    			printf("\nFailed at:\n  >File name: %s\n  >Function : %s\n  >Line No. : %d\n",  __FILE__, __FUNCTION__, __LINE__);
    		}
		
		printf("Ready for outputs ...\n");
				
			//ListDisplay(LdapOpt, msgid, ber, capInfor);
			FormatPrintLdap(LdapOpt, msgid, ber, capInfor);
				
		
			/* no more segment,clear all of them for next time counting*/
			memset(FrameBuff,0,40960);
			memset(reassemblePack,0,10);
			FrameBuffOffset=0;
			reassembleFlag=0;
			ReassembleSize=0;
		
	}else{
		/* In this Case, LDAP PDU is large, lenght more than MTU like 1400 byteÅC
		TCP should be reassembled. Client side hold the piece of PDU until the TCP Flag of
		PSH is set, then transfer the all PDU in one time to server. Currently there is a limitation
		due to the Buff size of array, max size of buff for pervious PDU is 10240byte.
		*/
			memcpy((FrameBuff+FrameBuffOffset),payload,size_payload);
			printf("Segment reassembled, No Sending.");
			FrameBuffOffset += size_payload;
			reassemblePack[reassembleFlag]=(count-1);
			reassembleFlag+=1;
			//memcpy(socketTcpHead.ReassemblePakNum,reassemblePack,10);
			printf("FrameBuff Size is now:%d  ReasmFlag:%d\n",FrameBuffOffset,reassembleFlag);
			printf("TCPHEAD PAYLOAD Size is now:%d\n",socketTcpHead.Payload_size);
		
	}
	printf("Close pipe.\n");
	ber_sockbuf_free( sb );
	close(PPfd[0]);
	close(PPfd[1]);
	return;
}

int StartClient(char *BindIP, char *ServIP, char *targetdev, char *Filter)
{
	memset(FrameBuff,0,40960);
	int FrameBuffOffset=0;
	int ReassembleSize=0;
	char *dev = NULL;            				/* capture device name */
	struct bpf_program fp;            			/* compiled filter program (expression) */
	pcap_t *handle;              			  	/* packet capture handle */
	char errbuf[PCAP_ERRBUF_SIZE]; 		       	/* error buffer */
	bpf_u_int32 mask;            		   		/* subnet mask */
   	bpf_u_int32 net;               		  		/* ip */
    int num_packets = -1;               		/* number of packets to capture */
	dev = targetdev;								/*Set the target dev */
	char buff[100];
	bzero(buff,100);
	char filter_exp[128] = FILTER_EXP; 		 /*Define the caputer filter:LDAP only and without TCP 3 handshake*/
	int frc = strncmp(Filter,"NULL",4);

	
	if(Filter != NULL && frc !=0 ){
		sprintf(buff, " and host %s", Filter);
		strcat(filter_exp, buff); 
	}
	
	

	
//#ifdef DEBUG
	printf("The Filter:%s\n",filter_exp);
//#endif 	
	
	/* Socket defination */
	/*--------------Keep it ---------------*/
	struct ifreq ifr;
	char *iface = BOND0;
	struct sockaddr_in client_addr;
	bzero(&client_addr,sizeof(client_addr));
	memset(&ifr, 0, sizeof(ifr));



    
	    
      /* get network number and mask associated with capture device */
    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
        fprintf(stderr, "Couldn't get netmask for device %s: %s\n",
         dev, errbuf);
        net = 0;
        mask = 0;
    }


    int rc =0;
	
	handle = pcap_open_live(dev, SNAP_LEN, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        exit(EXIT_FAILURE);
    }

    /* compile the filter expression */
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n",
         filter_exp, pcap_geterr(handle));
        exit(EXIT_FAILURE);
    }

    /* apply the compiled filter */
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n",
         filter_exp, pcap_geterr(handle));
        exit(EXIT_FAILURE);
    }
	printf("Initial Interface for CAP ...OK\n");
	
	printf("Callback func starting...\n"); 
    /* now we can set our callback function */

	pcap_loop(handle, num_packets, got_packet, NULL);


    /* cleanup */
    pcap_freecode(&fp);
    pcap_close(handle);


    printf("\nCapture complete.\n");
	printf("Done\n");


return rc;
}

