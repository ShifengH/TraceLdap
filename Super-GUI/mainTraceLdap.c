/*--------------------------------------------------------------
 The tool of trace for Ldap procotol in UDC CUDB node, working 
 on 13B version.
 Designer: Shifeng Hu
 Email:shifeng.hu@ericsson.com
 Date: 2014-06-09 
 Version:0.0.3
 ----------------------------------------------------------------*/

/*--------------------------------------------------------------
 File:TraceLdap.c
 
 the main function inside.
 The tool was called by SC as well as PL. The 1st step is to 
 confirm the role of caller, If the SC calls it, start the Server
 part program, otherwise, Start client part program.

Server Program: StartServer():
Initialize socket, recieve the package and format print it.


Client Program: StartClient():
Initialize socket, capture, and send package to Server.


two interrpute signals function:
 	SIGINT,   response the Ctrl+C key, after this print the 
 	total capture infor.
	SIGWINCH, if the terminal window(Shell window) size was
	changed, the display should be adjust as well.
	(Singal response was desgined but detail not yet).

Version:0.0.2	
     Large LDAP PDU support TCP reassembled decode.
     
Version:0.0.3	
	 semaphore being introduced, make the displaying sequence to be correct
	 
----------------------------------------------------------------*/

#include <netinet/in.h>    // for sockaddr_in
#include <sys/types.h>    // for socket
#include <sys/socket.h>    // for socket
#include <sys/ioctl.h>
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
#include <unistd.h>
#include <signal.h>
#include <semaphore.h>   //êMçÜó 
#include "systemPara.h"

struct winsize size; 



//char *GetPLBond0IP(void);

void GetWinSize(int sig);
void Ctrl_C_Kill(int sig);
void printUsage(int argc);

void GetWinSize(int sig)
{
#ifdef DEBUG 
	printf("Windows size change Signal!\n");
#endif
	if (isatty(STDOUT_FILENO) == 0)  
  	exit(1);
	
	/*-------------------------------------------------
	 struct size store the current vlaue of row/column
	 iotcl func can get the new size of current window
	--------------------------------------------------*/
 	if(ioctl(STDOUT_FILENO, TIOCGWINSZ, &size)<0)
		{
			perror("ioctl TIOCGWINSZ error");
			exit(1);   
		}
	/*-------------------------------------------------
	 Suggetion Terminal size that progarm running is at
	 least 80 columns, if not , give a suggestion
	--------------------------------------------------*/
	if(size.ws_col< MIN_COLUMN_WIN)
	{
		printf("\rPlease change more big of the terminal!\n");
		printf("Current Windows size:%d rows, %d columns\n", size.ws_row, size.ws_col);
	}	
#ifdef DEBUG
	printf("New size: %d rows, %d columns\n", size.ws_row, size.ws_col);
#endif
	
}

void Ctrl_C_Kill(int sig)
{
	/* Kill all Clients */
	
	printf("\nStop trace service..\n");
	//printf("packages were captured!\n");
	printf("-----Finish-----\n");
	exit(0);
}
	
int whatHostis()
{
	char name[15];
	char *SC ="SC_2_1";
	char *PL ="PL_2_";
	int rc=0;
	gethostname(name, sizeof(name));
	rc = strncmp(name,SC,5);
	if(rc == 0){
		//check the HOST is SC_2_1
		if(strncmp(name,SC,6)!=0)
		{
			printf("This version only support running in SC_2_1, Please change to SC_2_1 and run again.\n");
			exit(0);
		}
		
#ifdef DEBUG	
		printf("Debug:this is SC\n");
#endif	
		
		return HOST_SC;
	}else if(strncmp(name,PL,5)==0){

#ifdef DEBUG	
		printf("Debug:this is PL\n");
#endif		
		return HOST_PL;
	}else 
	
	return 2;
}

	
	
int main(int argc, char *argv[])
{

	signal(SIGINT, Ctrl_C_Kill);
	//signal(SIGWINCH, GetWinSize);
	
	int role;
	printf("Start...\n");
	
	role = whatHostis();
	
	if(role > 1)
	{
		printf("Could not get host!\n");
		exit(1);
	}

	if(role == HOST_SC)
	{
		/*---------Parameter check------------*/
		int ch;
		int opterr = 0;
		DISPOPT dispOpt;

		while((ch = getopt(argc, argv, "vhH")) != -1){
		   switch(ch)
		   {
		      	case 'v':
			        printf("------------>TraceLdap<-----------\n");
			   		printf("------The version is:%s--------\n",VERSION);
			   		printf("-\033[1m\033[40;33mEmail me:Shifeng.hu@ericsson.com\033[0m-\n");
			   		printf("------------>2014-06-09<----------\n");
			   		exit(0);
			   		break;
		      	case 'h':
		         printUsage(argc); exit(0); break;
				
		   		case 'H':
		   			//HEXDUMP
		   			dispOpt.hex=1;
		   			break;
		      	default:
		         	printUsage(argc); exit(0); break;
		   }
		}
		
		printf("This is SC host, start server.\n");
		
		if(sem_init(&bin_sem,0,1))   //èâénâªêMçÜó é∏?  
    		{  
    			printf("Semaphore initialization failed\n");  
    			exit(EXIT_FAILURE);  
    		}
		
		/*---Server will never die, but Ctrl C can kill it */
		
		StartServer(SERVER_BINDIP, &dispOpt);
		
	}else{
		if(role == HOST_PL){
			
			if(argc < 2) {
				printUsage(argc);
				exit(0);
			}
			
			char *BindIP = argv[1];
			char *ServIP = argv[2];
			char *Filter = argv[3];
			char *dev	 = argv[4];
			
			printf("This is PL host, starting connect to server.\n");
			printf("The input para list:\n");
			printf("BindIP:%s, ServIP:%s, TargetDEV:%s\n",BindIP, ServIP, dev);
			printf("User Filter of host:%s\n", Filter);
#ifdef VM	
			StartClient(BindIP, ServIP, "any", Filter);
#else
			StartClient(BindIP, ServIP, dev, Filter);
#endif			
		}
	}

}
void printUsage(int argc)
	{
		printf("\n--------------TraceLdap-------------------\n"); 
		printf("Usage:\n");
		printf("Just run the program: ./TraceLdap\n");
		printf("Program will listen and wait the client connects,\n");
		printf("Ctrl+C can terminate the server process.\n\n");
		printf("Option:\n");
		printf("./TraceLdap -[vhH]\n");
		printf("-v : display the version of tool\n");
		printf("-h : show the usage\n");
		printf("-H : Detail display, hex stream model(not support yet)\n\n");
		printf("This version only can be executed at SC_2_1 host.\n");
		printf("After the server program is started,run below script in other terminal\n");
		printf("  /cluster/tmp/start.sh -start (or -b)\n");
		printf("then all PL hosts start the client program to connect and capture.\n");
		printf("For more detail, can check start.sh --help\n");
	}
