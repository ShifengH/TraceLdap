/*----------------------------------------------------------
 Author: Shifeng Hu
 Date: 2014-06-01 
 Location: MEXICO
 
 Version: 0.0.1
 
 This file realize the THREAD function, each connection will create 
 a thread for handle the communcation with clients.
========================
     |
Thread create
     |  
  initial
     |
receive the socket<----\
	 |                 |
  Decode PDU           |
     |                 |
  Display              |
     |_________________|      

========================

 Version: 0.0.2
 ---->Fixed to reassembled TCP segment. A large LDAP PDU will be captured
 as some pieces of TCP segment.Server and Client should be able to
 analyse reassembled package.
 
 Server:check the flag. if ReassmebleFlag is set, additional infor
 will be display.
 
 Client:check the TCP flag to assmeble the segment without flag
 sent to server when the PSH flag is set.
 
 ---->Fixed the bug when LdapModify happened without a value.
 Client is able to delete an attribute without any value, 
 just the attribute name.
 
 
 Version:0.0.3
----->Improve the Sync-Display,semaphore is used.

------------------------------------------------------------*/

#include <netinet/in.h>   // for sockaddr_in
#include <sys/types.h>    // for socket
#include <sys/socket.h>   // for socket
#include <stdio.h>        // for printf
#include <stdlib.h>       // for exit
#include <string.h>       // for bzero
#include <pcap.h>
#include <ctype.h>
#include <errno.h>
#include <arpa/inet.h>
#include <ldap.h>
#include <lber-int.h>
#include <semaphore.h>    //IPC
#include "systemPara.h"

int TrafficHandlingThread(PeerClient *client_info)
{
		
		char recvBuff[102400];
		memset(recvBuff,0, 102400);
		int rc;
		TcpHeadInfo socketTcpHead;
		int client_conn_pcap = client_info->client_conn;
		int client_conn_GUI = client_info->client_conn_GUI;
		int loop=0;
	
		PrintCap capInfor;
		capInfor.peer = *client_info;

	while(1){
    		loop ++;

			rc = recv(client_conn_pcap, (char *)&socketTcpHead, sizeof(socketTcpHead),0);
    		if(rc <= 0){
    			printf("TCP Head Recv failed!\n");
    			break;
    			exit (0);
    		}
    		if(send(client_conn_GUI,(char *)&socketTcpHead,sizeof(socketTcpHead),0)<0)
		    {
		        printf("Send To Server:TcpHeadInfo failed\n");
		    	break;
		    	exit(1);
		    }

    		capInfor.PackageHead = socketTcpHead;
    		
#ifdef DEBUGA    		
    		printf("TCP Head info len:	%d\n", rc);
    		printf("Time tag: 			%u:%u\n", PCAP.TimeStmap.tv_sec,PCAP.TimeStmap.tv_usec );
    		printf("Pkt number:			%d\n", capInfor.PackageHead.GetPackageNumber);
    		printf("IP layer len:		%d\n", capInfor.PackageHead.size_ip);
    		printf("TCP layer len:		%d\n", capInfor.PackageHead.size_tcp);
    		printf("Protocol:			%d\n", capInfor.PackageHead.Prctl);
    		printf("Src IP:				%s\n", capInfor.PackageHead.ipSrc);
    		printf("Dst IP:				%s\n", capInfor.PackageHead.ipDst);
    		printf("Payload len			%d\n", capInfor.PackageHead.Payload_size);
#endif    		
	//Get Payload
			rc = recv(client_conn_pcap, (char *)&recvBuff, socketTcpHead.Payload_size,0);
    		if(rc <= 0){
    			printf("TCP Head Recv failed!\n");
    			break;
    			exit (0);
    		}	
			
	//Proxy Payload to GUI
			print_hex_ascii_line((char *)&recvBuff,socketTcpHead.Payload_size,0);
		
			if(send(client_conn_GUI,(char *)&recvBuff,socketTcpHead.Payload_size,0)<0)
		    {
		        printf("Send To Server:TcpHeadInfo failed\n");
		    	break;
		    	exit(1);
		    }
    	   	
	}
        //close(client_conn);
}
