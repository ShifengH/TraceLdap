
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
#include <semaphore.h>   //M†—Ê

int parseLength(u_char *offset);
u_char parseByte(u_char *offset);
char *parseString(char *offset);
int parseIntWithTag(int paramInt, u_char *offset);
char *parseStringWithTag(int paramInt, char *offset);
  

void main(int argc, char *argv[])
{	
	char buf[5]={0x84,0x11,0x22,0x0c,0x10};
	char Int1[3]={0x02,0x01,0x0A};
	char Int2[4]={0x02,0x02,0x01,0x12};
	char Str[5]={0x04,0x03,0x31,0x32,0x33};
	
	//printf("The length :%d\n", parseLength(buf));
	printf("The Int1 :%d\n", parseIntWithTag(2,Int1));
	printf("The Int2 :%d\n", parseIntWithTag(2,Int2));
	printf("The String :%s\n", parseString(Str));
}
 
u_char parseByte(u_char *offset)
  {
  	u_char r=*offset;
  	offset+=1;
  	return r;
  }  



int parseLength(u_char *offset)
  {
  	//u_char *p=offset;
  	u_char i = parseByte(offset);
  	printf("The i = %d\n", i);
    if ((i & 0x80) == 128)
    {
      i &= 127;
      
      if (i == 0) {
		printf("Error decoding Length supposed to be not 0 @FILE:%s,line:%d\n", __FILE__,__LINE__);
		return -1;
      }
      
      if (i > 4) {
		printf("Not support too long @FILE:%s,line:%d\n", __FILE__,__LINE__);
		return -1;
      }
      
      offset+=1;
      unsigned int j=0,k= 0;
      //i now = 1,2,3,4. no more.
      for ( k = 0; k < i; k++) {
      	j = (j << 8) + (*offset++);
      	printf("J value:%X\n",j);
      }
    return j;
    }
    return i;
  }
  

int parseIntWithTag(int paramInt, u_char *offset)
{
	/* ---E.G.----
	 1. 0x02 0x01 0x2E     01
     2. 0x02 0x02 0x03 0x2E  02
	 3. 0x64 0x82 0x0a 0x1B  0x04 0x45 0x73 
	*/
    if ( paramInt != parseByte(offset)) {
    	printf("Not wanted Tag\n");
    	return -1;
    }
    
    int i = parseLength(offset); 
    
    if (i > 4)
  	{
  		printf("INTEGER too long\n");
    	return -1;
  	}
    
	int j = *(offset++);
    int k = 0,m=1;
	printf("J value:%X\n",j);
    
    k = j & 0x7F;
    for (m = 1; m < i; m++) {
      k <<= 8;
    	k |= (*offset++) & 0xFF;
    }
    
    if ((j & 0x80) == 128) {
      k = -k;
    }
    
    return k;
 }
 
  char *parseString(char *offset)   
  {
    return parseStringWithTag(4, offset);
  }
  
  
   char *parseStringWithTag(int paramInt, char *offset)
   {
    int i;
    
   	if ( paramInt != parseByte(offset)) {
    	printf("Not wanted Tag, in case of String Tag should be 0x04\n");
    	return -1;
    }
    
   	int k = parseLength(offset);

   	if (k == 0) {
      return NULL;
    }
   	else 
   	{
      	char Str[k];
    	memset(Str,0,k);
    	memcpy(Str, offset, k);
    	return Str;
      

      offset += k;
    }
    
  }