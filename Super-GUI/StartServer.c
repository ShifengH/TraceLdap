/*----------------------------------------------------------
 Author: Shifeng Hu
 Date: 2014-06-01 
 Location: MEXICO
 
 Version: 0.0.1
 
 This function is the main part of this program, create a 
 Server socket for clients connection, and use multi-threads
 for recieve each client's information which was captured.
 
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
#include "systemPara.h"

int StartServer(char *BindIP, DISPOPT *dispOpt)
{

	printf("Server is being started. Initial...\n");
	printf("Version: %s\n",VERSION);
	int thread_count = 0;
	pthread_t threads[MAX_THREAD_NUM];

    //Set Socket
	int opt =1;
    struct sockaddr_in server_addr;
    bzero(&server_addr,sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr =inet_addr(BindIP);
    server_addr.sin_port = htons(SERVER_PORT);
	
	PeerClient client_info;

    //Create Server Socket, use TCP 
    int server_socket = socket(PF_INET,SOCK_STREAM,0);
    if( server_socket < 0)
    {
        printf("Error!Create Socket Failed!");
        exit(1);
    }
	
   	setsockopt(server_socket,SOL_SOCKET,SO_REUSEADDR,&opt,sizeof(opt));

    
    // Bind the struct and Socket
    if( bind(server_socket,(struct sockaddr*)&server_addr,sizeof(server_addr)))
    {
        printf("Server Bind Port : %d Failed!, this port might be used for other App already.", SERVER_PORT); 
        exit(1);
    }
	printf("Bind socket. Port:6666 .....OK\n");
    
	//Listen the socket port
    if ( listen(server_socket, LENGTH_OF_LISTEN_QUEUE) )
    {
        printf("Server Listen Failed!"); 
        exit(1);
    }
	
	printf("Listening on Port:6666......OK\n");

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
	
    while (1) 
    {

#ifdef DEBUG
    	printf(">>DEBUG<< While loop inside!\n");
#endif
    	//define the client side struct socket
        struct sockaddr_in client_addr;
        socklen_t length = sizeof(client_addr);
    	
		/*-------------------------------------------------------
         Waiting for the client connect the server socket,
    	 once client connected , function of accpet will return 
    	 a new socket( client_conn) that used for communication 
    	 between clients and Server. 
    	----------------------------------------------------------*/
		printf("Waiting for Client connects.\n");
    	
    	int client_conn = accept(server_socket,(struct sockaddr*)&client_addr,&length);
        if ( client_conn < 0)
        {
            printf("Server Accept Failed!\n");
            break;
        }
    	
    	client_info.PeerAddr = inet_ntoa(client_addr.sin_addr);
    	client_info.PeerPort = ntohs(client_addr.sin_port);
    	client_info.client_conn = client_conn;
    	
#ifdef DEBUG
    	printf("Connected Peer addr:%s , and Port:%d.\n", client_info.PeerAddr,client_info.PeerPort);
		printf("A new connection coming.\n");
#endif    	
    	
    	/*---------------------------------------------------------
    	 Multiple threads are used for each client connection, a new
    	 thread will be created once a new connection come, "PL host
    	 trys to connect host, threads may up to 34 " . Socket id 
    	 is passed as a parameter fo new thread. Communication is
    	 happend inside new thread.
    	----------------------------------------------------------*/
    	
    	int pthread_err = pthread_create(threads + (thread_count++), NULL, (void *)newthread_start, (void *)&client_info);
		if (pthread_err != 0)
		{
			printf("Create thread Failed!\n");
			return EXIT_FAILURE;
		}
		printf("Creating a Thread for [%s:%d].\n",client_info.PeerAddr,client_info.PeerPort );
     }
    
	printf("While loop dead, Server died too\n");
    close(server_socket);
    return 0;
}
