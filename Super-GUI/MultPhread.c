#include <stdio.h>        // for printf
#include <stdlib.h>        // for exit
#include <string.h>        // for bzero
#include <fcntl.h>
#include <unistd.h>
#include <netinet/in.h>    // for sockaddr_in
#include <sys/types.h>    // for socket
#include <sys/socket.h>    // for socket
#include <sys/stat.h>
#include <pthread.h>
#include "systemPara.h"

#define SERVER_PORT 8090
#define LISTEN_QUEUE_LENGTH 20
#define BUFFER_SIZE 1024
#define MAX_THREAD_NUM 100

int thread_count = 0;
pthread_t threads[MAX_THREAD_NUM];

/**
 * 接收数据的?行函数
 * @param conn_socket
 */
void recv_data(int conn_socket);


/*
 * 主方法
 */
int main(int argc, char** argv)
{
	// 建立Socket
	int server_socket = socket(PF_INET, SOCK_STREAM, 0);
	if (server_socket < 0) {
		printf("Socket create failed.\n");
		return EXIT_FAILURE;
	}

	{
		int opt = 1;
		setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof (opt));
	}

	// ?置服?器端?听套接字参数
	struct sockaddr_in server_addr;
	bzero(&server_addr, sizeof (server_addr));

	server_addr.sin_family = AF_INET;
	server_addr.sin_addr.s_addr = htons(INADDR_ANY);
	server_addr.sin_port = htons(SERVER_PORT);
	// ?定端口
	if (bind(server_socket, (struct sockaddr*) &server_addr, sizeof (server_addr)))
	{
		printf("Bind port %d failed.\n", SERVER_PORT);
		return EXIT_FAILURE;
	}
	
	// ?始?听
	if (listen(server_socket, LISTEN_QUEUE_LENGTH))
	{
		 printf("Server Listen Failed!");
		 return EXIT_FAILURE;
	}
	
	// ?始?理客?端?接
	bzero(&threads, sizeof(pthread_t) * MAX_THREAD_NUM);
	while (1)
	{
		struct sockaddr_in client_addr;
		socklen_t length = sizeof(client_addr);
		
		// 建立客?端?接
		int client_conn = accept(server_socket, (struct sockaddr*) &client_addr, &length);
		if (client_conn < 0)
		{
			printf("Server Accept Failed!\n");
			return EXIT_FAILURE;
		}
		
		// 新建?程, 使用新?程与客?端交互
		int pthread_err = pthread_create(threads + (thread_count++), NULL, (void *)recv_data, (void *)client_conn);
		if (pthread_err != 0)
		{
			printf("Create thread Failed!\n");
			return EXIT_FAILURE;
		}
		
	}
	close(server_socket);
	return (EXIT_SUCCESS);
}

void recv_data(int conn_socket)
{
	char buffer[BUFFER_SIZE];
	bzero(buffer, BUFFER_SIZE);

	int length = 0;
	while (length = recv(conn_socket, buffer, BUFFER_SIZE, MSG_WAITALL))
	{
		if (length < 0)
		{
			printf("Server Recieve Data Failed! code %d\n", length);
		}
		printf("%s", buffer);
		bzero(buffer, BUFFER_SIZE);
	}
	close(conn_socket);
}