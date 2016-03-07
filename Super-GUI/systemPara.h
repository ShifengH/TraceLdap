#ifndef _SYSTEMPARA_H_

#define _SYSTEMPARA_H_

#include <sys/time.h>
#include <semaphore.h>   //êMçÜó ìØ?
/*---------------------------------
 Server Socket Related Defination
 ---------------------------------*/

#define VERSION "0.0.3"

#define SERVER_BINDIP "192.168.0.1"
#define SERVER_PORT    6666
#define SERVER_PORT_GUI    6677  
#define LENGTH_OF_LISTEN_QUEUE 20
#define BUFFER_SIZE 1024
#define FILE_NAME_MAX_SIZE 512
#define MAX_THREAD_NUM 100
#define IP_SERVER "192.168.0.1"

#define FILTER_EXP "port 389 and (((ip[2:2]-((ip[0]&0xf)<<2))-((tcp[12]&0xf0)>>2))!=0)"
#define BOND0 "bond0"



#define MIN_COLUMN_WIN 70
#define MAX_THREAD_NUM 100

//#define VM  1
//#define DEBUG 1

#define LDAP_MOD_ADD		(0x0000)
#define LDAP_MOD_DELETE		(0x0001)
#define LDAP_MOD_REPLACE	(0x0002)

#define OK 0
#define HOST_SC 0
#define HOST_PL 1


typedef struct dispopt {
	int hex;
	int dtl;
	int msisdn;
	int imsi;
	int bind;
	int type;
} DISPOPT;

typedef struct threadinfo {
	int threadnum;
	ber_int_t msgid;
	int packagenum;
} ThreadInfo;	


static char *ScopeString[4] = {
	
	"baseObject",	
	"singleLevel",	
	"wholeSubtree",
	"subordinate" 
};

static char *AliasString[4] = {
	
	"neverDerefaliases",	
	"derefInSearching",	
	"derefFindingBaseObj",	
	"alwaysDerefAliases",	
};


static char *PeerHost[34]={"PL_2_3", "PL_2_4", "PL_2_5", "PL_2_6", "PL_2_7", "PL_2_8", "PL_2_9",
							"PL_2_10", "PL_2_11", "PL_2_12", "PL_2_13", "PL_2_14", "PL_2_15", "PL_2_16",
							"PL_2_17", "PL_2_18", "PL_2_19", "PL_2_20", "PL_2_21", "PL_2_22", "PL_2_23",
							"PL_2_24", "PL_2_25", "PL_2_26", "PL_2_27", "PL_2_28", "PL_2_29", "PL_2_30",
							"PL_2_31", "PL_2_32", "PL_2_33", "PL_2_34", "PL_2_35", "PL_2_36"};
		
static char *LdapOptTag[25]={	 "LDAP_REQ_BIND", "LDAP_REQ_UNBIND", "LDAP_REQ_SEARCH", "LDAP_REQ_MODIFY", "LDAP_REQ_ADD", "LDAP_REQ_DELETE",
			    				 "LDAP_REQ_MODDN", "LDAP_REQ_MODRDN", "LDAP_REQ_RENAME", "LDAP_REQ_COMPARE", "LDAP_REQ_ABANDON", "LDAP_REQ_EXTENDED",
							    "LDAP_RES_BIND", "LDAP_RES_SEARCH_ENTRY", "LDAP_RES_SEARCH_REFERENCE", "LDAP_RES_SEARCH_RESULT", "LDAP_RES_MODIFY",
								"LDAP_RES_ADD", "LDAP_RES_DELETE", "LDAP_RES_MODDN", "LDAP_RES_MODRDN", "LDAP_RES_RENAME", "LDAP_RES_COMPARE", 
								"LDAP_RES_EXTENDED", "LDAP_RES_INTERMEDIATE"
								};

static char *Method[5] = {"NONE", "SIMPLE", "KRBV","UNDEFINE","SASL" };

static char *LdapModTypeStr[3] = {"ADD", "DELETE", "REPLACE"};

static char *LdapResultCode[81] ={
								"LDAP_SUCCESS", "LDAP_OPERATIONS_ERROR", "LDAP_PROTOCOL_ERROR", "LDAP_TIMELIMIT_EXCEEDED",
								"LDAP_SIZELIMIT_EXCEEDED", "LDAP_COMPARE_FALSE", "LDAP_COMPARE_TRUE", "LDAP_AUTH_METHOD_NOT_SUPPORTED",
								"LDAP_STRONG_AUTH_REQUIRED", "LDAP_PARTIAL_RESULTS", "LDAP_REFERRAL", "LDAP_ADMINLIMIT_EXCEEDED",
								"LDAP_UNAVAILABLE_CRITICAL_EXTENSION", "LDAP_CONFIDENTIALITY_REQUIRED", "LDAP_SASL_BIND_IN_PROGRESS", "undefine error", 	
								"LDAP_NO_SUCH_ATTRIBUTE", "LDAP_UNDEFINED_TYPE", "LDAP_INAPPROPRIATE_MATCHING", "LDAP_CONSTRAINT_VIOLATION",
								"LDAP_TYPE_OR_VALUE_EXISTS", "LDAP_INVALID_SYNTAX", "undefine", "undefine", "undefine", "undefine", "undefine", "undefine",
								"undefine", "undefine", "undefine", "undefine", "LDAP_NO_SUCH_OBJECT", "LDAP_ALIAS_PROBLEM", "LDAP_INVALID_DN_SYNTAX",
								"LDAP_IS_LEAF", "LDAP_ALIAS_DEREF_PROBLEM", "undefine", 	"undefine", "undefine", "undefine", "undefine", "undefine",
								"undefine", "undefine", "undefine", "undefine", "LDAP_X_PROXY_AUTHZ_FAILURE", "LDAP_INAPPROPRIATE_AUTH", 
								"LDAP_INVALID_CREDENTIALS", "LDAP_INSUFFICIENT_ACCESS", "LDAP_BUSY", "LDAP_UNAVAILABLE", "LDAP_UNWILLING_TO_PERFORM",
								"LDAP_LOOP_DETECT",	"undefine", "undefine", "undefine", "undefine", "undefine", "undefine", "undefine", "undefine", "undefine",	
								"LDAP_NAMING_VIOLATION", "LDAP_OBJECT_CLASS_VIOLATION", "LDAP_NOT_ALLOWED_ON_NONLEAF", "LDAP_NOT_ALLOWED_ON_RDN", "LDAP_ALREADY_EXISTS",
								"LDAP_NO_OBJECT_CLASS_MODS", "LDAP_RESULTS_TOO_LARGE", "LDAP_AFFECTS_MULTIPLE_DSAS", "undefine", "undefine", "undefine", "undefine",
								"LDAP_VLV_ERROR", "undefine", "undefine", "undefine", "LDAP_OTHER"
								};

#ifdef VM
/* ethernet headers are always exactly 14 bytes [1] */
	#define SIZE_ETHERNET 14
#else
/* Real NOde of CUDB */
	#define SIZE_ETHERNET 16  //For linux cooked head
#endif


typedef struct pbind {
	char * dn;
	ber_int_t version;
	ber_tag_t method;
	char * Passwd;
} PBIND;

typedef struct prequest { 
	char * dn;
	ber_int_t scope;
	ber_int_t ali;
	ber_int_t size;
	ber_int_t time;
	ber_int_t filter;
	ber_int_t attrsonly;
	ber_tag_t method;
	char * Attr;
} PREQ;


typedef struct peerclient { 
	char *PeerAddr;
	int PeerPort;
	int client_conn;  /* socket id*/
	int client_conn_GUI;  /* socket id*/
} PeerClient;

	
typedef struct tcpheader{
	int GetPackageNumber;
	struct timeval TimeStmap;
	int size_ip;
	int size_tcp;
	char ipSrc[16];
	char ipDst[16];
	int Prctl;
	int portSrc;
	int portDst;
	int Payload_size;
	char ReassembleFlag;
	char ReassemblePakNum[10];
} TcpHeadInfo;


typedef struct printcap {
	struct peerclient peer;
	struct tcpheader PackageHead;

#define  PEER	capInfor.peer
#define  PCAP	capInfor.PackageHead 

	BerElement	*ber;
} PrintCap;	

/*---------------------------------------*/

/* default snap length (maximum bytes per packet to capture) */
#define SNAP_LEN 1518

/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN    6

/* Ethernet header */
struct sniff_ethernet {
        u_char ether_dhost[ETHER_ADDR_LEN]; /* destination host address */
        u_char ether_shost[ETHER_ADDR_LEN]; /* source host address */
        u_short ether_type; /* IP? ARP? RARP? etc */
};

/* IP header */
struct sniff_ip {
        u_char ip_vhl; /* version << 4 | header length >> 2 */
        u_char ip_tos; /* type of service */
        u_short ip_len; /* total length */
        u_short ip_id; /* identification */
        u_short ip_off; /* fragment offset field */
        #define IP_RF 0x8000 /* reserved fragment flag */
        #define IP_DF 0x4000 /* dont fragment flag */
        #define IP_MF 0x2000 /* more fragments flag */
        #define IP_OFFMASK 0x1fff /* mask for fragmenting bits */
        u_char ip_ttl; /* time to live */
        u_char ip_p; /* protocol */
        u_short ip_sum; /* checksum */
        struct in_addr ip_src,ip_dst; /* source and dest address */
};

#define IP_HL(ip) (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip) (((ip)->ip_vhl) >> 4)

/* TCP header */
typedef u_int tcp_seq;

struct sniff_tcp {
        u_short th_sport; /* source port */
        u_short th_dport; /* destination port */
        tcp_seq th_seq; /* sequence number */
        tcp_seq th_ack; /* acknowledgement number */
        u_char th_offx2; /* data offset, rsvd */
#define TH_OFF(th) (((th)->th_offx2 & 0xf0) >> 4)
        u_char th_flags;
        #define TH_FIN 0x01
        #define TH_SYN 0x02
        #define TH_RST 0x04
        #define TH_PUSH 0x08
        #define TH_ACK 0x10
        #define TH_URG 0x20
        #define TH_ECE 0x40
        #define TH_CWR 0x80
        #define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
        u_short th_win; /* window */
        u_short th_sum; /* checksum */
        u_short th_urp; /* urgent pointer */
};
/*--------------------------------------------------*/
char FrameBuff[40960];
int FrameBuffOffset;
int ReassembleSize;
sem_t bin_sem; //êMçÜó 
/*--------------------------------------------------*/

int
 whatHostis();

int
 StartClient(char *BindIP, char *ServIP, char *targetdev, char *Filter);
 
int
 StartServer(char *BindIP, DISPOPT *dispOpt);
 
int
 checkbind(BerElement *ber, PBIND *Pbind);
 
int
 newthread_start(PeerClient *client_info);
 
int
 TrafficHandlingThread(PeerClient *client_info);
 
void 
 FormatPrintLdap(ber_tag_t LdapOpt, ber_int_t msgid, BerElement *ber,  PrintCap capInfor);

int
 checkBindRes(BerElement *ber);

int
 checkSearchReq(BerElement *ber,PREQ *preq);
 
int
 checkSearchEntry(BerElement *ber);
 
int 
 checkSearchDone(BerElement *ber); 
  
int 
 checkADDReq(BerElement *ber);

int
 checkDelReq (BerElement *ber);
 
int Ldap_get_filter(BerElement *ber,char *text);

int
Ldap_get_ava( BerElement *ber, struct berval *type, struct berval *value );

int
Ldap_get_ssa( BerElement *ber, struct berval *type, struct berval *value );

#endif
