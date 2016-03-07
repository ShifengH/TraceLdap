/*---------------------------------------------
 Decoding BER format is the mainly task of those funcs
 Parse ecah LDAP operation, was a Crazy thing
 becasue I know nothing of BER encode.
 Read the OpenLdap code, and modify it...
 
----------------------------------------------*/
#include "portable.h"
#include <stdio.h>
#include <netinet/in.h>    // for sockaddr_in
#include <sys/types.h>    // for socket
#include <sys/socket.h>    // for socket
#include <stdlib.h>        // for exit
#include <string.h>        // for bzero
#include <ctype.h>
#include <errno.h>
#include <arpa/inet.h>
#include <ldap.h>
#include <lber-int.h>
#include <slap.h>
#include "systemPara.h"

	
void decomposeDN(BerElement *ber,Trace *GetSubs)
	{
	/*
	 * Parse the search request.  It looks like this:
	 *
	 *	SearchRequest := [APPLICATION 3] SEQUENCE {
	 *		baseObject	DistinguishedName,
	 *		scope		ENUMERATED {
	 *			baseObject	(0),
	 *			singleLevel	(1),
	 *			wholeSubtree (2),
	 *          subordinate (3)  -- OpenLDAP extension
	 *		},
	 *		derefAliases	ENUMERATED {
	 *			neverDerefaliases	(0),
	 *			derefInSearching	(1),
	 *			derefFindingBaseObj	(2),
	 *			alwaysDerefAliases	(3)
	 *		},
	 *		sizelimit	INTEGER (0 .. 65535),
	 *		timelimit	INTEGER (0 .. 65535),
	 *		attrsOnly	BOOLEAN,
	 *		filter		Filter,
	 *		attributes	SEQUENCE OF AttributeType
	 *	}
	 */		
		ber_tag_t tag;
		ber_len_t len;
		ber_int_t scope=0;
		ber_int_t ali=0;
		ber_int_t size=0;
		ber_int_t time=0; 
		ber_int_t filter=0;
		ber_int_t attrsonly=0;
		ber_len_t	siz,  i;
		struct berval dn = BER_BVNULL;
		
		ber_len_t cnt = sizeof(struct berval);
		ber_len_t off = 0;
		char *p,*q,*j,*m,*n;
		int type=0;
		GetSubs->value[0]=NULL;
		GetSubs->value[1]=NULL;
		GetSubs->value[2]=NULL;
		
		
#ifdef DEBUG
	    int ival = -1;
        ber_set_option( NULL, LBER_OPT_DEBUG_LEVEL, &ival );
#endif

		if ( ber_scanf( ber, "{miiiib" /*}*/,
			&dn, &scope, &ali, &size, &time, &attrsonly ) == LBER_ERROR )
		{
                   printf(">>Error<< SRCH decode Error! Ber_Scanf return tag:%d.\n", tag);
					return -1;
		}
			/* success */
			/*m: CPU=12434,MSISDN=1234567890123,dc=msisdn,ou=identities,dc=telcel */
			//printf("BaseDN:%s\n", dn.bv_val);
			m=dn.bv_val;
			do 
				{
				p=strtok(m, ",");	//CPU=12434,
				if(p)
				{
				n=strtok(NULL,","); //MSISDN=1234567890123,dc=msisdn,ou=identities,dc=telcel
					
				q=strtok(p,"=");//CPU
				j=strtok(NULL,"=");//1234
				//printfc("---------Strtok:%s=%s\n----------",q,j);
				if(strcasecmp(q,"IMSI")==0) 	GetSubs->type=T_IMSI; 		//IMSI case;
				if(strcasecmp(q,"MSISDN")==0) 	GetSubs->type=T_MSISDN;		//MSISDN case;
				if(strcasecmp(q,"mscid")==0) 	GetSubs->type=T_mscID;		//MSCID case;
				
				GetSubs->value[GetSubs->type]=j;
					//if(strcasecmp(q,"associd")==0) type=4;//IMS case;
				m=n;
				}
				}
				while(p != NULL);
				//return type;
}

int SendOrNot(char *FrameBuff, Trace *InputSubs)
{
	int rc = 1;
	ber_tag_t       tag;
	ber_int_t		msgid;
	ber_int_t		msgid_before;
	ber_len_t       len;
    BerElement      *ber;
    Sockbuf         *sb;
    ber_len_t max = 409600;
	ber_tag_t LdapOpt;
	Trace GetSubs;
	memset(&GetSubs,0 sizeof(Trace));
	
	if(InputSubs->TraceFlag != TRUE)
		return 1;
	
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
	
		write(PPfd[1],FrameBuff,size_payload+FrameBuffOffset);
		ber_sockbuf_add_io( sb, &ber_sockbuf_io_fd, LBER_SBIOD_LEVEL_PROVIDER, (void *)&PPfd[0] );
  		
		ber = ber_alloc_t(LBER_USE_DER);
    	if( ber == NULL ) {
    			perror( "ber_alloc_t" );
    			return( EXIT_FAILURE );
			}
		for (;;) {
			
				tag = ber_get_next( sb, &len, ber);
				if( tag != LBER_ERROR ) break;
				if( errno == EWOULDBLOCK ) continue;
				if( errno == EAGAIN ) continue;
				return( EXIT_FAILURE );
			}
    		
    		//determine the Ldap option kind 
    		LdapOpt=checkLDAPoption(ber, &msgid);
			GetSubs.msgid=msgid;
	
    		if(LdapOpt==LBER_ERROR){
    			printf("|-Error:LDAP option decode failed.\n");
    			
    		}
			decomposeDN(ber,  &GetSubs);
			rc=compare(InputSubs, &GetSubs);
		return rc;
}
int compare(Trace *InputSubs, Trace *GetSubs)
{
	if(InputSubs->value[InputSubs->type]==GetSubs->value[GetSubs->value]
		|| InputSubs->msgID== GetSubs->msgID)
		InputSubs.msgid=msgid;
		
		
	return 1;
	else
	return 0;
}
