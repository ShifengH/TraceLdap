/*----------------------------------------------------------
 Author: Shifeng Hu
 Date: 2015-12-03 
 Location: MIANYANG
 
 Version: 0.0.1
 
 
------------------------------------------------------------*/

/*------------Update Information----------------------------
 Note that: Always keep this style for trace update as below
 Eidtor:XXXX XXX XXX
 Date: YYYY-MM-DD
 Location: XXXXX
 Update Infor:
 SVN version:
 Bug fixed Number:
------------------------------------------------------------*/
 

#include <netinet/in.h>    // for sockaddr_in
#include <sys/types.h>    // for socket
#include <sys/socket.h>    // for socket
#include <stdio.h>        // for printf
#include <stdlib.h>        // for exit
#include <string.h>        // for bzero
#include <pcap.h>
#include <ctype.h>
#include <errno.h>
#include <arpa/inet.h>
#include <ldap.h>
#include <lber-int.h>
#include <fcntl.h>
#include <sys/time.h>
#include "systemPara.h"

int StartGUIServer(char *BindIP);
void print_hex_ascii_line(const u_char *payload, int len, int offset);


int main(int argc, char *argv[])
{
	StartGUIServer(argv[1]);
}

void
print_hex_ascii_line(const u_char *payload, int len, int offset)
{


    int i;
    int gap;
    const u_char *ch;


    /* offset */
    printf("%05d\n", offset);
    
    /* hex */
    ch = payload;
    for(i = 1; i <= len; i++) {
        printf("%02x ", *ch);
        ch++;
        /* print extra space after 8th byte for visual aid */
        if (i%8 == 0)
            printf(" ");
    	if (i%16 == 0)
    		printf("\n");
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
    printf("\n");
    
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

int StartGUIServer(char *BindIP)
{

	printf("Server is being started. Initial...\n");
	printf("Version: %s\n","0.0.1");
	
	int thread_count = 0;
	//pthread_t threads[MAX_THREAD_NUM];
	char recvBuff[1024], SendBuff[1024];
	
	memset(recvBuff,0,1024);
	memset(SendBuff,0,1024);
	
	PeerClient client_info;
	TcpHeadInfo socketTcpHead;
	struct timeval TimeStmap;
	pthread_t threads[MAX_THREAD_NUM];

    //Set Socket
	int opt =1;
    
	struct sockaddr_in server_addr_trf;   //Socket for pcap
	struct sockaddr_in server_addr_ctrl;  //Socket for GUI
	
    bzero(&server_addr_trf,sizeof(server_addr_trf));
	bzero(&server_addr_trf,sizeof(server_addr_ctrl));
	
    server_addr_trf.sin_family = AF_INET;
    server_addr_trf.sin_addr.s_addr =inet_addr(BindIP);
    server_addr_trf.sin_port = htons(SERVER_PORT); //6666
	
	server_addr_ctrl.sin_family = AF_INET;
    server_addr_ctrl.sin_addr.s_addr =inet_addr(BindIP);
    server_addr_ctrl.sin_port = htons(SERVER_PORT_GUI);//6677
		
	
	
    //Create Server Socket, use TCP 
    int server_socket_pcap = socket(PF_INET,SOCK_STREAM,0);
    if( server_socket_pcap < 0)
    {
        printf("Error!Create Socket Failed!");
        exit(1);
    }
	
	int server_socket_GUI = socket(PF_INET,SOCK_STREAM,0);
	if( server_socket_GUI < 0)
    {
        printf("Error!Create Socket Failed!");
        exit(1);
    }
	printf("Create Socket PCAP :%d\n",server_socket_pcap);
	printf("Create Socket GUI  :%d\n",server_socket_GUI);
	
   	setsockopt(server_socket_pcap,SOL_SOCKET,SO_REUSEADDR,&opt,sizeof(opt));
	setsockopt(server_socket_GUI,SOL_SOCKET,SO_REUSEADDR,&opt,sizeof(opt));

    
    // Bind the struct and Socket
    if( bind(server_socket_pcap,(struct sockaddr*)&server_addr_trf,sizeof(server_addr_trf)))
    {
        printf("Server Trf Bind Port : %d Failed!, this port might be used for other App already.", SERVER_PORT); 
        exit(1);
    }
	
	printf("Bind traffic port socket. Port:%d .....OK\n",SERVER_PORT);
	
	if( bind(server_socket_GUI,(struct sockaddr*)&server_addr_ctrl,sizeof(server_addr_ctrl)))
    {
        printf("Server ctrl Bind Port : %d Failed!, this port might be used for other App already.", SERVER_PORT_GUI); 
        exit(1);
    }
	printf("Bind control socket. Port:%d .....OK\n",SERVER_PORT_GUI);
    
	//Listen the socket port
    if ( listen(server_socket_pcap, LENGTH_OF_LISTEN_QUEUE) )
    {
        printf("Server Listen Failed!"); 
        exit(1);
    }
	printf("Listening on Port:6666......OK\n");
	
	if ( listen(server_socket_GUI, LENGTH_OF_LISTEN_QUEUE) )
    {
        printf("Server Listen Failed!"); 
        exit(1);
    }
	printf("Listening on Port:6677......OK\n");
	/*-----------------------------------------------------------
	Server go inside a dead loop.
	    _____________
	    | listening  |
		|     |      |
		|  Accept    |
		|     |      |
		|  Create    |
		|  Thread    |
		|     |      |
		|   Loop     |
	------------------------------------------------------------*/
	

    	//define the client side struct socket
        struct sockaddr_in client_addr, client_addr_GUI;
        socklen_t length = sizeof(client_addr);
    	
		/*-------------------------------------------------------
         Waiting for the client connect the server socket,
    	 once client connected , function of accpet will return 
    	 a new socket( client_conn) that used for communication 
    	 between clients and Server. 
    	----------------------------------------------------------*/
		printf("Waiting for Client connects.\n");
	
		int client_conn_GUI = accept(server_socket_GUI,(struct sockaddr*)&client_addr_GUI,&length);
        if ( client_conn_GUI < 0)
        {
            printf("Server Accept Failed!\n");
         
        }
		printf("GUI Client connectivity established.\n");
		printf("Connected Client:  addr:%s - Port:%d.\n", inet_ntoa(client_addr_GUI.sin_addr),ntohs(client_addr_GUI.sin_port));
	int rc;

	
	while(1)
	{
		int client_conn_pcap = accept(server_socket_pcap,(struct sockaddr*)&client_addr,&length);
        if ( client_conn_pcap < 0)
        {
            printf("Server Accept Failed!\n");
         
        }
		printf("PCAP Client connected.\n");

    	
    	client_info.PeerAddr = inet_ntoa(client_addr.sin_addr);
    	client_info.PeerPort = ntohs(client_addr.sin_port);
    	client_info.client_conn = client_conn_pcap;
		client_info.client_conn_GUI = client_conn_GUI;
    	

    	printf("Connected Peer addr:%s , and Port:%d.\n", client_info.PeerAddr,client_info.PeerPort);
		printf("A new connection coming.\n");
		
		int pthread_err = pthread_create(threads + (thread_count++), NULL, (void *)TrafficHandlingThread, (void *)&client_info);
		if (pthread_err != 0)
		{
			printf("Create thread Failed!\n");
			return EXIT_FAILURE;
		}
		
		printf("Creating a Thread for [%s:%d].\n",client_info.PeerAddr,client_info.PeerPort );
	/*
		
	//Get Header
	rc = recv(client_conn_pcap, (char *)&socketTcpHead, sizeof(socketTcpHead),0);
    		if(rc < 0){
    			printf("TCP Head Recv failed!\n");
    			exit (0);
    		}
	printf("Got Header  size:%d\n",sizeof(socketTcpHead));
	printf("Got Payload size:%d\n",socketTcpHead.Payload_size);	
	
	print_hex_ascii_line((char *)&socketTcpHead,sizeof(socketTcpHead),8);
	
	//Proxy Header to GUI
	if(send(client_conn_GUI,(char *)&socketTcpHead,sizeof(socketTcpHead),0)<0)
		    {
		        printf("Send To Server:TcpHeadInfo failed\n");
		    	exit(1);
		    }
		
	
	//Get Payload
	rc = recv(client_conn_pcap, (char *)&recvBuff, socketTcpHead.Payload_size,0);
    		if(rc < 0){
    			printf("TCP Head Recv failed!\n");
    			exit (0);
    		}	
	print_hex_ascii_line((char *)&recvBuff,socketTcpHead.Payload_size,0);
		
		//Proxy Payload to GUI
	if(send(client_conn_GUI,(char *)&recvBuff,socketTcpHead.Payload_size,0)<0)
		    {
		        printf("Send To Server:TcpHeadInfo failed\n");
		    	exit(1);
		    }
			
	printf("End\n"); */
	}
    close(server_socket_pcap);
	close(server_socket_GUI);
    return 0;
}
