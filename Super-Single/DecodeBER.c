/*---------------------------------------------
 Decoding BER format is the mainly task of those funcs
 Parse ecah LDAP operation, was a Crazy thing
 becasue I know nothing of BER encode.
 Read the OpenLdap code, and modify it...
 
----------------------------------------------*/
#include "portable.h"
#include <string.h>
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


char *
first_attribute(BerElement *ber );

char *
next_attribute(BerElement *ber );

struct berval **
get_values_len( BerElement	*ber, LDAP_CONST char *target );

int
Ldap_get_filter_list( BerElement *ber, char *text);


/* ---------------------------------------------------------
  Return the Ldap Option value.
  and get the LDAP's msgid of this package
 ---------------------------------------------------------*/
ber_tag_t  checkLDAPoption(BerElement *ber, ber_int_t *msgid)
{
	//Decode the tag and output the Hex dump
		ber_int_t	tag;
		ber_len_t   len;
	
	
		if ( (tag = ber_get_int( ber, msgid )) != LDAP_TAG_MSGID ) {
		/* log, close and send error */
			printf(">>Error<<  Get_int failed, msgID:%d\n", msgid);
			ber_free( ber, 1 );
			return LBER_ERROR;
		}
	
    	if ( (tag = ber_peek_tag( ber, &len )) == LBER_ERROR ) {
		/* log, close and send error*/
			printf(">>Error<<  PeeK failed, tag;%d\n", tag);
			ber_free( ber, 1 );
			return LBER_ERROR;
		}
	
#ifdef DEBUG
    		printf(">>DEBUG<< Check MSGID=%d\n", *msgid);
			printf(">>DEBUG<< Tag=%d\n", tag);		
    		printf("-------------------BER DUMP LOG---------------------\n");
    		ber_log_dump( LDAP_DEBUG_BER, ber->ber_debug, ber, 1 );
#endif
		return tag; /* Ldap operation type will be return 
					LDAP_REQ_XXX
					LDAP_RES_XXX
					*/
}


/* ---------------------------------------------------------
  Return OK or NOK. 
  Put the Bind Infor into 2nd Parameter.
   ---------------------------------------------------------*/
int checkbind(BerElement *ber, PBIND *Pbind)
{
	BerElement *ber1 = ber;
	ber_int_t version;
	ber_tag_t method;
	struct berval mech = BER_BVNULL;
	struct berval dn = BER_BVNULL;
	struct berval Passwd = BER_BVNULL;
	ber_tag_t tag;
	
	
	/*
	 * Parse the bind request.  It looks like this:
	 *
	 *	BindRequest ::= SEQUENCE {
	 *		version		INTEGER,		 -- version
	 *		name		DistinguishedName,	 -- dn
	 *		authentication	CHOICE {
	 *			simple		[0] OCTET STRING -- passwd
	 *			krbv42ldap	[1] OCTET STRING -- OBSOLETE
	 *			krbv42dsa	[2] OCTET STRING -- OBSOLETE
	 *			SASL		[3] SaslCredentials
	 *		}
	 *	}
	 *
	 *	SaslCredentials ::= SEQUENCE {
	 *		mechanism	    LDAPString,
	 *		credentials	    OCTET STRING OPTIONAL
	 *	}
	 */

	tag = ber_scanf( ber, /*{*/ "{imt" /*}*/, &version, &dn, &method );

	if ( tag == LBER_ERROR ) {
		printf(">>Error<< Bind Decode DN return tag:%d.\n", tag);
	}

	if( method != LDAP_AUTH_SASL ) {
		tag = ber_scanf( ber, /*{*/ "m}", &Passwd );

	} else {
		tag = ber_scanf( ber, "{m" /*}*/, &mech );

		if ( tag != LBER_ERROR ) {
			ber_len_t len;
			tag = ber_peek_tag( ber, &len );

			if ( tag == LDAP_TAG_LDAPCRED ) { 
				tag = ber_scanf( ber, "m", Passwd );
			} else {
				tag = LDAP_TAG_LDAPCRED;
				//BER_BVZERO( Passwd );
			}

			if ( tag != LBER_ERROR ) {
				tag = ber_scanf( ber, /*{{*/ "}}" );
			}
		}
	}
	
	Pbind->dn = dn.bv_val;
	Pbind->version = version;
	Pbind->method = method;
	Pbind->Passwd = Passwd.bv_val;
	
	return 0;
}
	
/*-------------------------------------------------
  Return the result code
	OK
	ERROR
-------------------------------------------------*/
	
int checkBindRes(BerElement *ber)
	{
		ber_tag_t tag;
		ber_int_t resultCode;
		ber_len_t len;
#ifdef DEBUG		
		int ival = -1;
        ber_set_option( NULL, LBER_OPT_DEBUG_LEVEL, &ival );
#endif
		if ( (tag = ber_peek_tag( ber, &len )) == LBER_ERROR ) {
			/* log, close and send error */
			printf(">>Error<< PeeK failed, tag;%d\n", tag);
			ber_free( ber, 1 );
			return LBER_ERROR;
		}

		
		tag = ber_scanf( ber, "{i}" , &resultCode );
		if ( tag == LBER_ERROR ) {
			return LBER_ERROR;
			//printf("BER decode Error! Ber_Scanf return tag:%d.\n", tag);
		}
		return resultCode;
	}

/*-------------------------------------------------------
	The most complex package, there might be below infor
	need to be parsed:
		BaseDN			:already parsed
		Scope			:already parsed
		DerefAlias		:already parsed
		sizelimit		:already parsed
		timelimit		:already parsed
		attributes only	:already parsed
		Filter			:Partly parsed
						AND,OR,NOT,Substring, Present,GE,LE,APPROX,Equal
						
		Attributes		:un-parsed yet
----------------------------------------------------------*/
	
	
int  checkSearchReq(BerElement *ber,PREQ *preq)
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
		Filter f;
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
		//BerVarray  Attri;
		AttributeName *Attri;
		//BerVarray AttributeDescriptionList = NULL;
		BerElement Ber_Bkp = *ber;
		ber_len_t cnt = sizeof(struct berval);
		ber_len_t off = 0;
		
		char text[128]={} ; // storing the filter
		
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
		
		
		
		if(Ldap_get_filter(ber, text) == LBER_ERROR)
		{
			printf(">>Error<< Filter Decode Error\n");
		}
		strcat(text, "\n");
		//tag = ber_skip_tag( ber, &len );
		/* attributes */
		siz = sizeof(AttributeName);
		off = offsetof(AttributeName,an_name);
		
		//printf("Attribute Decode DEBUG: siz-%d,  off-%d\n", siz, off);
		
			if ( ber_scanf( ber, "{M}}", &Attri, &siz, off) == LBER_ERROR )
			{
              	     printf(">>Error<< Attir decode Error! Ber_Scanf return tag:%d.\n", tag);
					//return -1;
			}
			i=0;
		 	/* success */
			printf("|-\033[1m\033[40;35mBaseDN\033[0m:\t%s\n", dn.bv_val);
			printf("|-scope:\t%s\n", ScopeString[scope]);
			printf("|-ali:\t%s\n", AliasString[ali]);
			printf("|-size:\t%d\n", size);
			printf("|-time:\t%d\n", time);
			printf("|-attrsonly:\t%d\n", attrsonly);
			printf("|-Filter:\t%s", text);
			for ( i=0; i<siz; i++ )  {
				printf("|-Attribute(%d):\t%s\n",i, Attri[i].an_name.bv_val );
			}
	
			preq->dn = dn.bv_val;
			preq->scope     = scope; 
			preq->ali       = ali;
			preq->size      = size;
			preq->time      = time;
			preq->attrsonly = attrsonly;
				
			Trace Subs, GetSubs;
			char *p,*q,*j,*m,*n;
		int type=0;
		GetSubs.IMSI=NULL;
		GetSubs.MSISDN=NULL;
		GetSubs.mscID=NULL;
		m=dn.bv_val;
		do 
			{
			p=strtok(m, ",");	//CPU=12434,
			if(p)
			{
			n=strtok(NULL,","); //MSISDN=1234567890123,dc=msisdn,ou=identities,dc=telcel
				
			q=strtok(p,"=");//CPU
			j=strtok(NULL,"=");//1234
			printf("---------Strtok:%s=%s\n----------",q,j);
			if(strcasecmp(q,"IMSI")==0) {type=1;  GetSubs.IMSI=j;}//IMSI case;
			if(strcasecmp(q,"MSISDN")==0) {type=2;GetSubs.MSISDN=j;}//MSISDN case;
			if(strcasecmp(q,"mscid")==0) {type=3; GetSubs.mscID=j;}//MSCID case;
				//if(strcasecmp(q,"associd")==0) type=4;//IMS case;
			m=n;
			}
			}
			while(p != NULL);
	printf("The fetch DATA(type:%d): \n-->IMSI-%s\n-->MSISDN-%s\n-->mscID-%s\n",type, GetSubs.IMSI, GetSubs.MSISDN, GetSubs.mscID);
			return 0;
	}

/*-------------------------------------------------------
	 Get the type and value of attribute
	even the len when enable the debug mode
--------------------------------------------------------*/
struct berval **
get_values_len( BerElement	*ber, LDAP_CONST char *target )
	{
	
	char		*attr;
	int		found = 0;
	struct berval	**vals;

	/* skip sequence, dn, sequence of, and snag the first attr */
	if ( ber_scanf( ber, "{x{{a" /* }}} */, &attr ) == LBER_ERROR ) {
		return( NULL );
	}

	if ( strcasecmp( target, attr ) == 0 )
		found = 1;

	/* break out on success, return out on error */
	while ( ! found ) {
		//LDAP_FREE( attr );
		attr = NULL;

		if ( ber_scanf( ber, /*{*/ "x}{a" /*}*/, &attr ) == LBER_ERROR ) {
			return( NULL );
		}

		if ( strcasecmp( target, attr ) == 0 )
			break;
	}

	//LDAP_FREE( attr );
	attr = NULL;

	/* 
	 * if we get this far, we've found the attribute and are sitting
	 * just before the set of values.
	 */

	if ( ber_scanf( ber, "[V]", &vals ) == LBER_ERROR ) {
		
		return( NULL );
	}

	return( vals );
}	

/*-------------------------------------------------------------------------------
	 Parse the first attribute in the BER
	
----------------------------------------------------------------------------------*/
	
char *
first_attribute(BerElement *ber )
{
	int rc;
	ber_tag_t tag;
	ber_len_t len = 0;
	char *attr;
	
	/* 
	 * Skip past the sequence, dn, sequence of sequence leaving
	 * us at the first attribute.
	 */

	tag = ber_scanf( ber, "{xl{" /*}}*/, &len );
	if( tag == LBER_ERROR ) {
		
		ber_free( ber, 0 );
		return NULL;
	}

	/* set the length to avoid overrun */
	rc = ber_set_option( ber, LBER_OPT_REMAINING_BYTES, &len );
	if( rc != LBER_OPT_SUCCESS ) {
		printf(">>Error<< Avoid overrun failed!\n");
		ber_free( ber, 0 );
		return NULL;
	}

	if ( ber_pvt_ber_remaining( ber ) == 0 ) {
		assert( len == 0 );
		ber_free( ber, 0 );
		return NULL;
	}
	

	/* snatch the first attribute */
	tag = ber_scanf( ber, "{ax}", &attr );
	if( tag == LBER_ERROR ) {
		printf(">>Error<< Snatch first Attr failed!\n");
		ber_free( ber, 0 );
		return NULL;
	}
	
	return attr;

}


/* Parse the next attribute */
char * next_attribute( BerElement *ber )
{
	ber_tag_t tag;
	char *attr;

	
	if ( ber_pvt_ber_remaining( ber ) == 0 ) {
		return NULL;
	}

	/* skip sequence, snarf attribute type, skip values */
	tag = ber_scanf( ber, "{ax}", &attr ); 
	if( tag == LBER_ERROR ) {
		printf("| Attribute end\n");
		return NULL;
	}

	return attr;
}	

	
int checkSearchEntry(BerElement *ber)
{
	int rc = LDAP_SUCCESS;
	ber_tag_t tag;
	ber_len_t len =0;
	BerValue attr;
	BerVarray vals;
	attr.bv_val = NULL;
	attr.bv_len = 0;
	char *a;
	int n;
	struct berval dn = BER_BVNULL;
	BerElement ber_value, ber_backup;
	ber_value = ber_backup= *ber;
		
	
#ifdef DEBUG 
	    int ival = -1;
        ber_set_option( NULL, LBER_OPT_DEBUG_LEVEL, &ival );
#endif
	
	 n=0;
	for ( a = first_attribute( ber ); a != NULL; a = next_attribute(  ber ) )
		{
			struct berval	**vals;
			//printf( "| | ATTR: %s\n", a );
			if ( (vals = get_values_len( &ber_value, a )) == NULL )
			{
				printf( "| | %s:\t(no values)\n" , a);
			}else {
				int i;
				for ( i = 0; vals[i] != NULL; i++ ) {
					int	j, nonascii;

					nonascii = 0;
					for ( j = 0; (ber_len_t) j < vals[i]->bv_len; j++ )
					//Non-display ASCII will be shown as HEX, It is Control code before 33 in ASCII Table
						if ( !isascii( vals[i]->bv_val[j] ) || vals[i]->bv_val[j] < 33 ) {
							nonascii = 1;
							break;
						}
					
					if ( nonascii ) {
						printf( "|-%s(not ascii):\tlen (%ld) \n",a, vals[i]->bv_len );
					
						ber_bprint( vals[i]->bv_val, vals[i]->bv_len );
					
						continue;
					}
				
#ifdef DETAIL
					printf( "|-%s:\tlen (%ld) \t%s\n",a, vals[i]->bv_len, vals[i]->bv_val );
#else					
					printf( "|-%s:\t\t%s\n",a, vals[i]->bv_val );
					
#endif					
				}
				
				ber_bvecfree( vals );
			}
			ber_value = ber_backup;
			n++;
		}
		
	
	return n;
}


int checkSearchDone(BerElement *ber)
{
		ber_tag_t tag;
		ber_int_t resultCode;
		ber_len_t len;
		
		if ( (tag = ber_peek_tag( ber, &len )) == LBER_ERROR ) {
		/* log, close and send error */
			printf(">>Error<< PeeK failed, tag;%d\n", tag);
			ber_free( ber, 1 );
			return -1;
		}

		
		tag = ber_scanf( ber, "{i}" , &resultCode );
		if ( tag == LBER_ERROR ) {
			printf(">>Error<< Respone Decode Error. Ber_Scanf return tag:%d.\n", tag);
		}
			printf("|-\033[1m\033[40;31mLDAP result\033[0m:\t%s (%d)\n", LdapResultCode[resultCode],resultCode );
}
	
int checkADDReq(BerElement *ber)
{
	/*
	 * Parse the add request.  It looks like this:
	 *
	 *	AddRequest := [APPLICATION 14] SEQUENCE {
	 *		name	DistinguishedName,
	 *		attrs	SEQUENCE OF SEQUENCE {
	 *			type	AttributeType,
	 *			values	SET OF AttributeValue
	 *		}
	 *	}
	 */
	BerElement	*ber1 = ber;
	char		*last;
	struct berval	dn = BER_BVNULL;
	ber_len_t	len;
	ber_tag_t	tag;
	Modifications	*modlist = NULL;
	Modifications	**modtail = &modlist;
	Modifications	tmp;
	char		textbuf[ SLAP_TEXT_BUFLEN ];
	size_t		textlen = sizeof( textbuf );	
	int		rc = 0;
	int		freevals = 1;
	
		/* get the name */
	if ( ber_scanf( ber, "{m", /*}*/ &dn ) == LBER_ERROR ) {
		printf(">>Error<< ADD DN Decode Error.\n");
		return -1;
	}
	printf("|-ADD DN:\t%s\n", dn.bv_val);
	printf("|-ADD Attributes list:\n");
	/* get the attrs */
	for ( tag = ber_first_element( ber, &len, &last ); tag != LBER_DEFAULT;
	    tag = ber_next_element( ber, &len, last ) )
		{
			Modifications *mod;
			ber_tag_t rtag;

			tmp.sml_nvalues = NULL;
			
			rtag = ber_scanf( ber, "{m{W}}", &tmp.sml_type, &tmp.sml_values );

			if ( rtag == LBER_ERROR ) {
				printf(">>Error<< ADD Attribute Decode Error.\n");
				return -1;
				
			}

			if ( tmp.sml_values == NULL ) {
				printf("Ber decode ADD opt No value found.\n");
				return -1;
			}
			if(tmp.sml_values == NULL){
					printf("|---%s\n", tmp.sml_type.bv_val);
				}else{
					printf("|--%s:\t%s\n", tmp.sml_type.bv_val, tmp.sml_values->bv_val );
				}
		}
}
	
	/*--------------------------------------------
	 Decoding the Modify operation, and show all
	 Attributes that want to modity
	--------------------------------------------*/
	
	
	int  checkModReq(BerElement *ber)
	{
		/*
	 * Parse the modify request.  It looks like this:
	 *
	 *	ModifyRequest := [APPLICATION 6] SEQUENCE {
	 *		name	DistinguishedName,
	 *		mods	SEQUENCE OF SEQUENCE {
	 *			operation	ENUMERATED {
	 *				add	(0),
	 *				delete	(1),
	 *				replace	(2)
	 *			},
	 *			modification	SEQUENCE {
	 *				type	AttributeType,
	 *				values	SET OF AttributeValue
	 *			}
	 *		}
	 *	}
	 */
	
		struct berval dn = BER_BVNULL;
		char		textbuf[ SLAP_TEXT_BUFLEN ];
		size_t		textlen = sizeof( textbuf );
		ber_tag_t	tag;
		ber_len_t	len;
		char		*last;
		int rc;

		rc = LDAP_SUCCESS;
		
		
				/* get the name */
		if ( ber_scanf( ber, "{m", /*}*/ &dn ) == LBER_ERROR ) {
			printf(">>Error<< MOD DN Decode Error.\n");
			return -1;
		}
	
		printf("|-MOD DN:\t%s\n", dn.bv_val);
		
		for ( tag = ber_first_element( ber, &len, &last );
			tag != LBER_DEFAULT;
			tag = ber_next_element( ber, &len, last ) ){
			
			ber_int_t mop;
			Modifications tmp, *mod;

			tmp.sml_nvalues = NULL;

			if ( ber_scanf( ber, "{e{m[W]}}", &mop,
			    &tmp.sml_type, &tmp.sml_values ) == LBER_ERROR )
				{
					printf(">>Error<< MOD Attr list Decode Error\n");
					return -1;
				}
				
			printf("|--Mod Type:\t%s\n", LdapModTypeStr[mop]);
				if(tmp.sml_values == NULL){
					//Delete would be with a value
					printf("|---%s\n", tmp.sml_type.bv_val);
				}else{
					printf("|---%s:\t%s\n", tmp.sml_type.bv_val, tmp.sml_values->bv_val);
				}
		}
		return rc;
	}
	
	
	
	int checkDelReq (BerElement *ber)
	{
		struct berval dn = BER_BVNULL;
	/*
	 * Parse the delete request.  It looks like this:
	 *
	 *	DelRequest := DistinguishedName
	 */
				/* get the name */
		if ( ber_scanf( ber, "m",  &dn ) == LBER_ERROR ) {
			printf(">>Error<< DELE DN Decode Error.\n");
			return -1;
		}
		printf("|-Delete DN:%s\n", dn.bv_val);
		return 0;
	}
	
int
Ldap_get_ava( BerElement *ber, struct berval *type, struct berval *value )
{
	ber_tag_t rtag;

	rtag = ber_scanf( ber, "{mm}", type, value );

	if( rtag == LBER_ERROR ) {
		printf(">>Error<< Get ava tag error\n");
		return LBER_ERROR;
	}

	return LDAP_SUCCESS;
}
	
int
Ldap_get_filter_list( BerElement *ber, char *text )
{
	//Filter		**new;
	int		err;
	ber_tag_t	tag;
	ber_len_t	len;
	char		*last;
	char 		textbuf[128];
	//new=f;
	for ( tag = ber_first_element( ber, &len, &last );
		tag != LBER_DEFAULT;
		tag = ber_next_element( ber, &len, last ) )
			{
				err = Ldap_get_filter( ber, text);
				if ( err != LDAP_SUCCESS )
				{
					printf("Ldap_get_Filter_list Error \n\n");
					//new = &(*new)->f_next;
					return( err );
				}	
			}
	//printf("Debug: 1 time get_list OK!\n");
	return( LDAP_SUCCESS );
}	
	
int Ldap_get_filter(BerElement *ber, char *text)
	{
		ber_tag_t	tag;
		ber_len_t	len;
		struct berval type, value;
		int		err;
		Filter		f;
		char textbuf[128];
	/*
	 * A filter looks like this coming in:
	 *	Filter ::= CHOICE {
	 *		and		[0]	SET OF Filter,
	 *		or		[1]	SET OF Filter,
	 *		not		[2]	Filter,
	 *		equalityMatch	[3]	AttributeValueAssertion,
	 *		substrings	[4]	SubstringFilter,
	 *		greaterOrEqual	[5]	AttributeValueAssertion,
	 *		lessOrEqual	[6]	AttributeValueAssertion,
	 *		present		[7]	AttributeType,
	 *		approxMatch	[8]	AttributeValueAssertion,
	 *		extensibleMatch [9]	MatchingRuleAssertion
	 *	}
	 *
	 *	SubstringFilter ::= SEQUENCE {
	 *		type		   AttributeType,
	 *		SEQUENCE OF CHOICE {
	 *			initial		 [0] IA5String,
	 *			any		 [1] IA5String,
	 *			final		 [2] IA5String
	 *		}
	 *	}
	 *
	 *	MatchingRuleAssertion ::= SEQUENCE {
	 *		matchingRule	[1] MatchingRuleId OPTIONAL,
	 *		type		[2] AttributeDescription OPTIONAL,
	 *		matchValue	[3] AssertionValue,
	 *		dnAttributes	[4] BOOLEAN DEFAULT FALSE
	 *	}
	 *
	 */

	tag = ber_peek_tag( ber, &len );

	if( tag == LBER_ERROR ) {
		printf("Debug: PeeK tag error in filter\n");
		return LBER_ERROR;
	}
	//printf("| - Filter tag:%d\n", tag);
		

	f.f_next = NULL;
	f.f_choice = tag; 
	switch ( f.f_choice ) {
			case LDAP_FILTER_EQUALITY:
				//printf("Debug: Case of EQUALITY\n");		
				err = Ldap_get_ava(ber, &type, &value );
				if ( err != LDAP_SUCCESS ) {
					break;
				}
				//printf( "|-Filter:choice:%d type:%s, vlaue:%s\n", tag, type.bv_val, value.bv_val);
				//printf( "|-Filter:(%s=%s)\n", type.bv_val, value.bv_val);
				sprintf(textbuf, "(%s=%s)", type.bv_val, value.bv_val);
				strcat(text, textbuf);
				break;
			
			case LDAP_FILTER_PRESENT: {
				//printf("Debug:Case of Present\n");
				if ( ber_scanf( ber, "m", &type ) == LBER_ERROR ) {
					printf("filter Decode Present error\n");
					break;
				}
				sprintf(textbuf, "(%s=*)", type.bv_val);
				strcat(text, textbuf);
				//printf( "|-Filter:(%s=*)\n",type.bv_val);
				break;
				}
			case LDAP_FILTER_OR:
				//printf("Debug:Case of OR\n\n");
				strcat(text, "(|");
				err = Ldap_get_filter_list(ber, text);
				if ( err != LDAP_SUCCESS ) {
					printf("| OR error!\n");
					break;
				}
				strcat(text,")");	
				/* no assert - list could be empty */
				break;
			case LDAP_FILTER_AND:
				strcat(text, "(&");
				err = Ldap_get_filter_list( ber, text );
				if ( err != LDAP_SUCCESS ) {
					printf("| AND error!\n");
					break;
				}
				strcat(text,")");
				/* no assert - list could be empty */
				break;
			case LDAP_FILTER_GE:
		
				err = Ldap_get_ava(ber, &type, &value );
				if ( err != LDAP_SUCCESS ) {
					break;
				}
				sprintf(textbuf, "(%s>=%s)", type.bv_val, value.bv_val);
				strcat(text, textbuf);
				break;
				
			case LDAP_FILTER_LE:
				
				err = Ldap_get_ava(ber, &type, &value );
				if ( err != LDAP_SUCCESS ) {
					break;
				}
				sprintf(textbuf, "(%s<=%s)", type.bv_val, value.bv_val);
				strcat(text, textbuf);
				break;
		
			case LDAP_FILTER_SUBSTRINGS:
				
				err = Ldap_get_ssa( ber, &type, &value );
				if( err==LBER_ERROR ) {
					printf("Debug: SUBSTRING Decode Error, err=%X\n", err);
					break;
				}
				switch(err){
					case LDAP_SUBSTRING_INITIAL:
					sprintf(textbuf, "(%s=%s*)", type.bv_val, value.bv_val);
					strcat(text, textbuf);
					break;

					case LDAP_SUBSTRING_ANY:
					sprintf(textbuf, "(%s=*%s*)", type.bv_val, value.bv_val);
					strcat(text, textbuf);
					break;

					case LDAP_SUBSTRING_FINAL:
					sprintf(textbuf, "(%s=*%s)", type.bv_val, value.bv_val);
					strcat(text, textbuf);
					break;
					default:printf("|-SUBSTRING ERROR, ERR:%X\n", err);
				}
				break;
		case LDAP_FILTER_NOT:
		
				(void) ber_skip_tag( ber, &len );
				strcat(text, "(!");
				err = Ldap_get_filter( ber,  text );
				if ( err != LDAP_SUCCESS ) {
					break;
				}
				strcat(text, ")");
				break;
		case LDAP_FILTER_APPROX:

				err = Ldap_get_ava(ber, &type, &value );
				if ( err != LDAP_SUCCESS ) {
					break;
				}
				sprintf(textbuf, "(%s~=%s)", type.bv_val, value.bv_val);
				strcat(text, textbuf);
				break;
		default:
				printf("| - Filter tag:%x\n", tag);
				break;
				}
	return (LDAP_SUCCESS);
}


int
Ldap_get_ssa(BerElement *ber,struct berval *type, struct berval *value )
{
	ber_tag_t	tag;
	ber_len_t	len;
	char		*last;
	int	rc;
	struct berval desc, nvalue;
	

	if ( ber_scanf( ber, "{m" /*}*/, type ) == LBER_ERROR ) {
		return LBER_ERROR;
	}

	for ( tag = ber_first_element( ber, &len, &last );
		tag != LBER_DEFAULT;
		tag = ber_next_element( ber, &len, last ) )
		{

			if ( ber_scanf( ber, "m", value ) == LBER_ERROR ) {
				printf("| Filter-Decode Substring Error\n");
				return LBER_ERROR;
			
			}

			if ( value->bv_val == NULL || value->bv_len == 0 ) {
				rc = LBER_ERROR;
				printf("| Filter-Decode Substring Error\n");
				return rc;
			
			} 
#ifdef DEBUG			
			printf("Debug: tag =%X\n");
#endif
			switch ( tag ) {
				case LDAP_SUBSTRING_INITIAL:
#ifdef DEBUG				
					printf("Filter- Initial:value-%s\n", value->bv_val);
#endif				
					rc=LDAP_SUBSTRING_INITIAL;
					break;

				case LDAP_SUBSTRING_ANY:
#ifdef DEBUG
					printf("Filter- ANY:value-%s\n", value->bv_val);
#endif				
					rc=LDAP_SUBSTRING_ANY;
					break;

				case LDAP_SUBSTRING_FINAL:
#ifdef DEBUG
					printf("Filter- FINAL:value-%s\n", value->bv_val);
#endif				
					rc=LDAP_SUBSTRING_FINAL;
					break;

				default:
					rc = LBER_ERROR;
					printf("| Filter-Decode Substring Error\n");
					return rc;
			
			}
		}
		return rc /* LDAP_SUBSTR OPT : ANY INITIAL FINAL ERROR */ ;				
}

