#
# makefile 
#

SRC = mainTraceLdap.c  StartClient.c DecodeBER.c  FormatPrint.c
OBJ = $(SRC:.c=.o)
TARGET = SingleTraceLdap
CC = gcc
LIB_LINK = -pthread -lpcap -lldap


$(TARGET):$(OBJ)
	$(CC) -g -o $(TARGET) $(OBJ) $(LIB_LINK)
	
.SUFFIXES:.c
.c.o:
	$(CC) $(LIB_LINK) -c $<
clean :
	rm *.o $(TARGET)
	
