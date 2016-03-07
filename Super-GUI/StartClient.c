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
#include <sys/ioctl.h>
#include <net/if.h>
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
	printf("\n\nBeing Inside CallBack Function !\n");
	TcpHeadInfo socketTcpHead;
	
	int client_socket = *args;
    
	static int count = 1; /* packet counter */
    
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
    
    printf("\nPacket number %d:\n", count);
	socketTcpHead.GetPackageNumber = count;
    count++;
    
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
    
    /* compute tcp payload (segment) size */
    size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);
    
	
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
	
#ifdef DEBUG    	
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
	
#endif
	
	
	if(TcpFlagPush){
		/*Flag of PSH in TCP layer was set. that means there are no more LDAP PDU in later.*/
		/*Check single LDAP PDU or reassmbled Package.*/

			/*send Head info to Server*/
			if(send(client_socket,SocketBuff,sizeof(socketTcpHead),0)<0)
		    {
		        printf("Send To Server:TcpHeadInfo failed\n");
		    	exit(1);
		    }
		
			printf("Send To Server TCP head..OK\n");
		
		
		/*send Payload (LDAP Streaming) to server*/
		
		memcpy((FrameBuff+FrameBuffOffset),payload,size_payload);
		
		//if(send(client_socket,payload,size_payload,0)<0)
		if(send(client_socket,FrameBuff,(size_payload+FrameBuffOffset),0)<0)
	    {
	        printf("Send To Server:Payload Info failed\n");
	    	exit(1);
	    }
		
			printf("Send To Server Payload..OK\n");
			
			/* no more segment,clear all of them for next time counting*/
			memset(FrameBuff,0,40960);
			memset(reassemblePack,0,10);
			FrameBuffOffset=0;
			reassembleFlag=0;
			ReassembleSize=0;
		
	}else{
		/* In this Case, LDAP PDU is large, lenght more than MTU like 1400 byteC
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
		
	return;
}

int StartClient(char *BindIP, char *ServIP, char *targetdev, char *Filter)
{
	memset(FrameBuff,0,40960);
	FrameBuffOffset=0;
	ReassembleSize=0;
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
	char filter_exp[128] = FILTER_EXP; 		 /*Define the caputer filter:LDAP only and no TCP 3 handshake*/
	int frc = strncmp(Filter,"NULL",4);
	
	if(Filter != NULL && frc !=0 ){
		sprintf(buff, " and host %s", Filter);
		strcat(filter_exp, buff); 
	}
	

	
//#ifdef DEBUG
	printf("The Filter:%s\n",filter_exp);
//#endif 	
	
	/* Socket defination */
	struct ifreq ifr;
	char *iface = BOND0;
	struct sockaddr_in client_addr;
	bzero(&client_addr,sizeof(client_addr));
	memset(&ifr, 0, sizeof(ifr));

	int client_socket = socket(AF_INET,SOCK_STREAM,0);
	
	//IPv4
	/* Need to improve , auto bind the bond0 */
	client_addr.sin_family = AF_INET;
	client_addr.sin_addr.s_addr = inet_addr(BindIP); 
	client_addr.sin_port = htons(0);
	
	//Create TCP socket
	
    if( client_socket < 0)
    {
        printf("Create Socket Failed!\n");
        exit(1);
    }
	
	//Bind the Socket with Struct
    if( bind(client_socket,(struct sockaddr*)&client_addr,sizeof(client_addr)))
    {
        printf("Client Bind Port Failed!\n");
        exit(1);
    }
	
	//Define the Server socket for comm
	struct sockaddr_in server_addr;
    bzero(&server_addr,sizeof(server_addr));
    server_addr.sin_family = AF_INET;
	
    if(inet_aton(ServIP,&server_addr.sin_addr) == 0) 
	
    {
        printf("Server IP Address Error!\n");
        exit(1);
    }
	server_addr.sin_port = htons(SERVER_PORT);
    socklen_t server_addr_length = sizeof(server_addr);
	    
	/*--------------------------------*/
	
	//Connect to the Server
	if(connect(client_socket,(struct sockaddr*)&server_addr, server_addr_length) < 0)
    {
        printf("Can Not Connect To Server!\n");
        exit(1);
    }
	
      /* get network number and mask associated with capture device */
    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
        fprintf(stderr, "Couldn't get netmask for device %s: %s\n",
         dev, errbuf);
        net = 0;
        mask = 0;
    }


    /* print capture info */
    //printf("Device: %s\n", dev);
    //printf("Number of packets: %d\n", num_packets);
    //printf("Filter expression: %s\n", filter_exp);
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

	pcap_loop(handle, num_packets, got_packet, (u_char *)&client_socket);


    /* cleanup */
    pcap_freecode(&fp);
    pcap_close(handle);


    printf("\nCapture complete.\n");
	printf("Done\n");


return rc;
}

