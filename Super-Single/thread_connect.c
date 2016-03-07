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

int newthread_start(PeerClient *client_info)
{
		
		ber_tag_t       tag;
		ber_int_t		msgid;
		ber_int_t		msgid_before;
		ber_len_t       len;
     	BerElement      *ber;
     	Sockbuf         *sb;
    	ber_len_t max = 409600;
		ber_tag_t LdapOpt;
		int rc;
		TcpHeadInfo socketTcpHead;
		int client_conn = client_info->client_conn;
		int loop=0;
	
		PrintCap capInfor;
		capInfor.peer = *client_info;
	
#ifdef DEBUG	
		/* enable debugging */
        int ival = -1;
        ber_set_option( NULL, LBER_OPT_DEBUG_LEVEL, &ival );
#endif 
		sb = ber_sockbuf_alloc();
    	ber_sockbuf_ctrl( sb, LBER_SB_OPT_SET_MAX_INCOMING, &max );

    	while(1){
    		loop ++;
    		//printf(">>>>>>>>>>>>>>>>>While Loop the %d Packet<<<<<<<<<<<<<<<<<<<<<<\n", loop);	
    
    		/*---------------------------------------------------------------------
    		 Recieve the data from Socket, Function of "recv" is a standard func of
    		 getting data from socket, the purpose of "recv" is getting the TCP head
    		 related infor that sent from client, and put into a struct. 
    		 This struct must be exactly aligned with client side,otherwis the data
    		 may not readable
    		----------------------------------------------------------------------*/
    		//printf("\n\nDebug:-------Recv Data of TCP head\n");
   			rc = recv(client_conn, (char *)&socketTcpHead, sizeof(socketTcpHead),0);
    		if(rc < 0){
    			printf("TCP Head Recv failed!\n");
    			exit (0);
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
    		
    		/*----------------------------------------------------------------------
    		 "ber_sockbuf_add_io" is a function that supplied by "liblber" , it can
    		 get the socket information like "recv", that means here no need to call
    		 recv agian.
    		 Why here use the "ber_sockbuf_add_io" instead of recv?
    		 this time the payload, actually there is ldap protocol data streams are
    		 sent by client, and LDAP protocol use BER(ASN.1) encode method,if use
    		 this function, handy for decode the ldap information.
    		 Like recv, it also is stuck before any data coming. 
    				sb : 		socket buff, storing the data gather from socket.
    		-------------------------------------------------------------------------*/
    		//printf("Debug:-------Recv Data of Payload infor\n");
    		
    		ber_sockbuf_add_io( sb, &ber_sockbuf_io_tcp, LBER_SBIOD_LEVEL_PROVIDER, (void *)&client_conn );
			
    		//printf("Debug:-------Decode BER starting\n");
    		//Create and allocate memory for BER struct, BER struct can store the infor which was parsed by above function
        	ber = ber_alloc_t(LBER_USE_DER);
    		if( ber == NULL ) {
				perror( "ber_alloc_t" );
				return( EXIT_FAILURE );
			}
    		
    		/*----------------------------------------------------------------------
    		 "ber_get_next", it links the socket buff and BER struct. now all ldap data
    		 has been transfer to the struct of ber. lib of lber and ldap can use it for
    		 ldap layer decoding.
    		-------------------------------------------------------------------------*/
    		for (;;) {
				tag = ber_get_next( sb, &len, ber);
				if( tag != LBER_ERROR ) break;
				if( errno == EWOULDBLOCK ) continue;
				if( errno == EAGAIN ) continue;
				//perror( "ber_get_next" );
				return( EXIT_FAILURE );
			}
    		
    		//determine the Ldap option kind 
    		LdapOpt=checkLDAPoption(ber, &msgid);
    		
    		if(LdapOpt==LBER_ERROR){
    			printf("|-Error:LDAP option decode failed.\n");
    		}
    		/*  -1 Sem: Sync the displaying in STDOUT. Only 1 thread is able to 
    		throw the information to screen in same time, othre thread is waiting 
    		for the bin_sem become a non-zero(1) value to take the charge in output
    		*/
    		//printf("Debug:------Sem Wait!\n");
    	
    	/*-----------------Sync-Area--BEGIN---Semaphore-Control-------------------------------*/	
    	/*---Below function displays decoded information of PDU to screen inside each thread--*/
    	/*---Screen resource would be used by different	threads, in order to make a complete--*/
    	/*---LDAP packet output,I use semaphore to sync each thread. the below command lines--*/
    	/*---realize a packet decode and display.---------------------------------------------*/
    	/*-*/  sem_wait(&bin_sem);
    	/*-*/	//printf("Debug:------Sem OK go ahead!\n");
    	/*-*/	msgid_before = msgid;
    	/*-*/	
    	/*-*/	//printf("Debug:------Format output infor\n");
    	/*-*/	FormatPrintLdap(LdapOpt, msgid, ber, capInfor);
    	/*-*/	
    	/*-*/	/* +1 Sem: After this time the LDAP PDU Decoding&Outputing completed, 
    	/*-*/	// plus 1 to set the bin_sem, then other thread will be able to use the
    	/*-*/	// STDOUT.
    	/*-*/
    	/*-*/ sem_post(&bin_sem);// +1 Sem
    	/*-----------------Sync-Area---END----Semaphore-Control--------------------------------*/
    	
	}
        //close(client_conn);
}
