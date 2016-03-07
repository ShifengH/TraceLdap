#
# makefile 
#

#SRC = mainTraceLdap.c StartServer.c StartClient.c DecodeBER.c thread_connect.c FormatPrint.c
SRC = proxyServer.c TrafficHandlingThread.c
OBJ = $(SRC:.c=.o)
TARGET = GUIserver
CC = gcc
LIB_LINK = -pthread -lpcap -lldap


$(TARGET):$(OBJ)
	$(CC) -o $(TARGET) $(OBJ) $(LIB_LINK)
	
.SUFFIXES:.c
.c.o:
	$(CC) $(LIB_LINK) -c $<
clean :
	rm *.o $(TARGET)
	
