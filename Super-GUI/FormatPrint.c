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
		printf("|- Peer:%s - Package:%d-\n", PEER.PeerAddr, PCAP.GetPackageNumber);
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
