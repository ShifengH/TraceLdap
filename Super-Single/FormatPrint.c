/*------------------------------------------------------
	File:FormatPrint.c
	Author:shifeng hu
	
	Print the detail info on Stdout
-------------------------------------------------------*/
#include "portable.h"
#include <stdio.h>
#include <netinet/in.h>    // for sockaddr_in
#include <sys/types.h>    // for socket
#include <stdlib.h>        // for exit
#include <string.h>        // for bzero
#include <ctype.h>
#include <errno.h>
#include <arpa/inet.h>
#include <ldap.h>
#include <lber-int.h>
#include <slap.h>
#include <sys/time.h>
#include <time.h>
#include "systemPara.h"




Linklist* init_Node()//‰Žn‰»
{

    Linklist *head = malloc(sizeof(Linklist));
    head->length = 0;
    head->node = NULL; 
	return head;
}

int look_Node(Linklist *head)
{
	

    Node *ElementInList = head->node;

    int i = 0;
    if (NULL == head->node)
    {
        printf("Empty List!\n");
        return -1;
    }
	
    while (NULL!=ElementInList)
    {
    	
    	printf("[%d]->%s:%s:%d\n",
    		i,
    		ElementInList->String.String,
    		ElementInList->String.StrValue,
    		ElementInList->String.intValue
    	);
    
        i++;
        ElementInList = ElementInList->next;

    }
    printf("\n>END Length:%d \n",i);
    return 0;
}


void add_Node(Linklist *head, Str *StrAdd)
{
	/*
		|A-B-Next|A-B-Next|A-B-Next|
	1.   |Null
	2.   |0010(a) A1-B1-NULL|
	3.   |0010 A1-B1-0028|0028(a) A2-B2-Null|
	4.   |0010 A1-B1-0028|0028 A2-B2-003F|003F A3-B3-Null|
	*/
	
	

    Node *ElementInList=head->node; //The 1st element in the list
    int i = 0;
    if (NULL == ElementInList)  // Nothing so far, the 1st adding.
    {
        Node *a = malloc(sizeof(Node));//Apply new area for a element.
		a->String=*StrAdd;	
        a->next = NULL;
        head->node = a;
    }else{
    	while (NULL != ElementInList->next) i++,ElementInList=ElementInList->next;//ˆÚ?Žw?“ž?”ö

    	
    	Node *a = malloc(sizeof(Node));
		a->String=*StrAdd;    	
        a->next=NULL;
        ElementInList->next=a;
    
    } 
	memset(StrAdd,0,sizeof(StrAdd));
    head->length = i; 
	
}

void InsertList(Linklist *head, char *Name, char *str_val, int int_val)
{
		Str Temp;
		Temp.String=Name;
		Temp.len_Str=strlen(Name);
	
		Temp.StrValue=str_val;	
		if(str_val==NULL) 
			Temp.len_Val=0;
		else 
			{
				Temp.len_Val=strlen(str_val);
				
			}
		Temp.intValue=int_val;
	
		add_Node(head, &Temp);

}
void ListDisplay(ber_tag_t LdapOpt, ber_int_t msgid, BerElement *ber, PrintCap capInfor)
{
		struct tm *ptm;
		int rc;
		char *LdapOptStr;
		char time_string[16];
  		long milliseconds;
		int k = 0;
		Str StrTemp;
		//char *AV;
		Linklist *head;
	
		head = init_Node(); 
		
		milliseconds = PCAP.TimeStmap.tv_usec / 100;
		ptm=localtime (&PCAP.TimeStmap.tv_sec);
		strftime (time_string, sizeof (time_string),"%H:%M:%S", ptm);
		sprintf(time_string, "%s.%04ld",time_string,milliseconds);
		
		InsertList(head,"---------------TCP HEAD INFORMATION---------------",NULL,0);
		InsertList(head,"Time", 		time_string,	0);
		InsertList(head,"Src IP",	PCAP.ipSrc,		0);
		InsertList(head,"Src Port", 	NULL,			PCAP.portSrc);
		InsertList(head,"Dst IP", 	PCAP.ipDst,		0);
		InsertList(head,"Dst Port", 	NULL,			PCAP.portDst);
		InsertList(head,"Payload len", NULL, PCAP.Payload_size);	
		
	if(PCAP.ReassembleFlag > 0){
		
		InsertList(head,"TCP segment reassembled", NULL, 0);
		/*
		for(k=0;k< PCAP.ReassembleFlag;k++)
		{ printf("#%d ",PCAP.ReassemblePakNum[k]); }
		printf("\n");
		*/
		}	
		InsertList(head,"--------------------------------------------------",NULL,0);


	switch (LdapOpt)
	{
		case LDAP_REQ_BIND:{
				LdapOptStr = LdapOptTag[0];
				PBIND Pbind;
				rc = checkbind(ber, &Pbind);
				if(rc != 0)
					{ printf(">>Error<<  Bind Req Decode failed!\n");}
			InsertList(head,"LDAP Type",LdapOptStr,0);
			InsertList(head,"MessageID",NULL,msgid);
			InsertList(head,"BindDN", Pbind.dn,0);
			//InsertList(head,"Method", Method[Pbind.method],0);
			InsertList(head,"Method", NULL,Pbind.method);
			/*
			switch(Pbind.method)
			{
				case LDAP_AUTH_NONE: 	add_Node(head, "Method",  Method[0], 0,0);break;
				case LDAP_AUTH_SIMPLE:	add_Node(head, "Method",  Method[1], 0,0);break;	
				case LDAP_AUTH_SASL:	add_Node(head, "Method",  Method[4], 0,0);break;
				case LDAP_AUTH_KRBV4: 	
				case LDAP_AUTH_KRBV41:	
				case LDAP_AUTH_KRBV42:	add_Node(head, "Method",  Method[3],0,0);break;
				default :				add_Node(head, "Method",  Method[2],0,0);break;
							
			}
				add_Node(head, "Password",  Pbind.Passwd,0,0);*/
				break;	
		}
		default:printf("Later do this\n");break;
}
look_Node(head);
}

	
void FormatPrintLdap(ber_tag_t LdapOpt, ber_int_t msgid, BerElement *ber, PrintCap capInfor)
	{	
		struct tm *ptm;
		int rc;
		char *LdapOptStr;
		char time_string[15];
  		long milliseconds;
		int k = 0;
		
		milliseconds = PCAP.TimeStmap.tv_usec / 100;
		ptm=localtime (&PCAP.TimeStmap.tv_sec);
		strftime (time_string, sizeof (time_string),"%H:%M:%S", ptm);
		
	  printf("\n __Time:  %s.%04ld_______________________________________________________\n",time_string,milliseconds);
		printf("|\n");
		//printf("|- Peer:%s - Package:%d-\n", PEER.PeerAddr, PCAP.GetPackageNumber);
		printf("|- \033[1m\033[40;34mSrcIP\033[0m:%-15s(%d)  \033[1m\033[40;34mDstIP\033[0m:%-15s(%d)\n", PCAP.ipSrc,  PCAP.portSrc, PCAP.ipDst, PCAP.portDst);
	if(PCAP.ReassembleFlag > 0){
		printf("|- Payload len:%d \033[1m\033[40;31mTCP segment reassembled\033[0m.Package:",PCAP.Payload_size);
		for(k=0;k< PCAP.ReassembleFlag;k++)
		{ printf("#%d ",PCAP.ReassemblePakNum[k]); }
		printf("\n");
		
	}else{
		printf("|- Payload len:%d\n",PCAP.Payload_size);
	}	
		printf("|_____________________________________________________________________________\n");
		printf("|\n");
		
		switch (LdapOpt)
		{
			case LDAP_REQ_BIND:{
					LdapOptStr = LdapOptTag[0];
					PBIND Pbind;
					rc = checkbind(ber, &Pbind);
					if(rc != 0)
						{ printf(">>Error<<  Bind Req Decode failed!\n");}
					printf("|-\033[1m\033[40;33mLDAP Type\033[0m:\t%-26s  \033[1m\033[40;33mMessageID\033[0m: \t%d\n",LdapOptStr,msgid);
					printf("|--\033[1m\033[40;35mBindDN\033[0m:\t%s\n",		Pbind.dn );
				switch(Pbind.method)
				{
					case LDAP_AUTH_NONE: 	printf("|--Method:\t%s\n", 	Method[0] );break;
					case LDAP_AUTH_SIMPLE:	printf("|--Method:\t%s\n", 	Method[1] );break;	
					case LDAP_AUTH_SASL:	printf("|--Method:\t%s\n", 	Method[4] );break;
					case LDAP_AUTH_KRBV4: 	
					case LDAP_AUTH_KRBV41:	
					case LDAP_AUTH_KRBV42:	printf("|--Method:\t%s\n", 	Method[3] );break;
					default :				printf("|--Method:\t%s\n", 	Method[2] );break;
								
				}

					printf("|--Password:\t%s\n",	Pbind.Passwd );	
					break;	
					}
			case LDAP_REQ_UNBIND:{
					LdapOptStr = LdapOptTag[1];
					printf("|-\033[1m\033[40;33mLDAP Type\033[0m:\t%-26s  \033[1m\033[40;33mMessageID\033[0m: \t%d\n",LdapOptStr,msgid);
					break;
					}
			
			case LDAP_REQ_SEARCH:{
					LdapOptStr = LdapOptTag[2];
					printf("|-\033[1m\033[40;33mLDAP Type\033[0m:\t%-26s  \033[1m\033[40;33mMessageID\033[0m: \t%d\n",LdapOptStr,msgid);
					PREQ preq;
					checkSearchReq(ber,&preq);
					break; 
				}
			
			case LDAP_REQ_MODIFY:{
					LdapOptStr = LdapOptTag[3];
					printf("|-\033[1m\033[40;33mLDAP Type\033[0m:\t%-26s  \033[1m\033[40;33mMessageID\033[0m: \t%d\n",LdapOptStr,msgid);
					checkModReq(ber);
					break;
				}
			case LDAP_REQ_ADD:{
					LdapOptStr = LdapOptTag[4];
					printf("|-\033[1m\033[40;33mLDAP Type\033[0m:\t%-26s  \033[1m\033[40;33mMessageID\033[0m: \t%d\n",LdapOptStr,msgid);
					checkADDReq(ber);
					break;
				}
			case LDAP_REQ_DELETE:{
					LdapOptStr = LdapOptTag[5];
					printf("|-\033[1m\033[40;33mLDAP Type\033[0m:\t%-26s  \033[1m\033[40;33mMessageID\033[0m: \t%d\n",LdapOptStr,msgid);
					checkDelReq(ber);
					break;
				}
			case LDAP_REQ_MODDN:		LdapOptStr = LdapOptTag[6];break;
			//case LDAP_REQ_MODRDN:		LdapOptStr = LdapOptTag[7];break;
			//case LDAP_REQ_RENAME:		LdapOptStr = LdapOptTag[8];break;
			case LDAP_REQ_COMPARE:		LdapOptStr = LdapOptTag[9];break;
			case LDAP_REQ_ABANDON:		LdapOptStr = LdapOptTag[10];break;
			case LDAP_REQ_EXTENDED:	    LdapOptStr = LdapOptTag[11];break;
				
			case LDAP_RES_BIND:{
					rc = checkBindRes(ber);	
					LdapOptStr = LdapOptTag[12];
					printf("|-\033[1m\033[40;33mLDAP Type\033[0m:\t%-26s  \033[1m\033[40;33mMessageID\033[0m: \t%d\n",LdapOptStr,msgid);
					printf("|-LDAP result:\t%s (%d).\n", LdapResultCode[rc],rc );
					break;
				}
				
			case LDAP_RES_SEARCH_ENTRY:	 {
					LdapOptStr = LdapOptTag[13];
					printf("|-\033[1m\033[40;33mLDAP Type\033[0m:\t%-26s  \033[1m\033[40;33mMessageID\033[0m: \t%d\n",LdapOptStr,msgid);
					int numAttr = checkSearchEntry(ber);
					printf("| Total %d attributes decoded\n",numAttr);
					break;	
				}
				
			case LDAP_RES_SEARCH_REFERENCE: LdapOptStr = LdapOptTag[14];break;
			case LDAP_RES_SEARCH_RESULT:	LdapOptStr = LdapOptTag[15];printf("|-\033[1m\033[40;33mLDAP Type\033[0m:\t%-26s  \033[1m\033[40;33mMessageID\033[0m: \t%d\n",LdapOptStr,msgid);checkSearchDone(ber);break;
			case LDAP_RES_MODIFY:		   	LdapOptStr = LdapOptTag[16];printf("|-\033[1m\033[40;33mLDAP Type\033[0m:\t%-26s  \033[1m\033[40;33mMessageID\033[0m: \t%d\n",LdapOptStr,msgid);checkSearchDone(ber);break;
			case LDAP_RES_ADD:			  	LdapOptStr = LdapOptTag[17];printf("|-\033[1m\033[40;33mLDAP Type\033[0m:\t%-26s  \033[1m\033[40;33mMessageID\033[0m: \t%d\n",LdapOptStr,msgid);checkSearchDone(ber);break;
			case LDAP_RES_DELETE:		   	LdapOptStr = LdapOptTag[18];printf("|-\033[1m\033[40;33mLDAP Type\033[0m:\t%-26s  \033[1m\033[40;33mMessageID\033[0m: \t%d\n",LdapOptStr,msgid);checkSearchDone(ber);break;
			case LDAP_RES_MODDN:		 	LdapOptStr = LdapOptTag[19];break;
			//case LDAP_RES_MODRDN:		   	LdapOptStr = LdapOptTag[20];break;
			//case LDAP_RES_RENAME:		   	LdapOptStr = LdapOptTag[21];break;
			case LDAP_RES_COMPARE:		   	LdapOptStr = LdapOptTag[22];break;
			case LDAP_RES_EXTENDED:		   	LdapOptStr = LdapOptTag[23];break;
			case LDAP_RES_INTERMEDIATE:	   	LdapOptStr = LdapOptTag[24];break;
			default:break;
		}
		printf("|_____________________________________________________________________________\n");	
}
