#include <errno.h>
#include <unistd.h>
#include <malloc.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <resolv.h>
#include "openssl/ssl.h"
#include "openssl/err.h"
#include "tcp.h"
#include "tcp_hash.h"
#include "tcp_sock.h"
#include "tcp_timer.h"
#include "ip.h"
#include "rtable.h"
#include "log.h"

void handle_https_request(SSL* ssl);
void handle_http_request(struct tcp_sock *sock);
// void * https_server() {
	// // init SSL Library
	// SSL_library_init();
	// OpenSSL_add_all_algorithms();
	// SSL_load_error_strings();

	// // enable TLS method
	// const SSL_METHOD *method = TLS_server_method();
	// SSL_CTX *ctx = SSL_CTX_new(method);

	// // load certificate and private key
	// if (SSL_CTX_use_certificate_file(ctx, "./keys/cnlab.cert", SSL_FILETYPE_PEM) <= 0) {
	// 	perror("load cert failed");
	// 	exit(1);
	// }
	// if (SSL_CTX_use_PrivateKey_file(ctx, "./keys/cnlab.prikey", SSL_FILETYPE_PEM) <= 0) {
	// 	perror("load prikey failed");
	// 	exit(1);
	// }
	// // init socket, listening to port 443
	// int sock = socket(AF_INET, SOCK_STREAM, 0);
	// if (sock < 0) {
	// 	perror("Opening socket failed");
	// 	exit(1);
	// }
	// int enable = 1;
	// if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int)) < 0) {
	// 	perror("setsockopt(SO_REUSEADDR) failed");
	// 	exit(1);
	// }

	// struct sockaddr_in addr;
	// bzero(&addr, sizeof(addr));
	// addr.sin_family = AF_INET;
	// addr.sin_addr.s_addr = INADDR_ANY;
	// addr.sin_port = htons(443);

	// if (bind(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
	// 	perror("Bind failed");
	// 	exit(1);
	// }
	// listen(sock, 10);

	// while (1) {
	// 	struct sockaddr_in caddr;
	// 	socklen_t len;
	// 	int csock = accept(sock, (struct sockaddr*)&caddr, &len);
	// 	if (csock < 0) {
	// 		perror("Accept failed");
	// 		exit(1);
	// 	}
	// 	SSL *ssl = SSL_new(ctx); 
	// 	SSL_set_fd(ssl, csock);
	// 	handle_https_request(ssl);
	// }

	// close(sock);
	// SSL_CTX_free(ctx);
// }

// void handle_https_request(SSL* ssl)
// {
	// char* response = (char*)malloc(70000);
	// if (SSL_accept(ssl) == -1){
	// 	perror("SSL_accept failed");
	// 	exit(1);
	// } else {
	// 	char buf[1024] = {0};
	// 	int bytes = SSL_read(ssl, buf, sizeof(buf));
	// 	if (bytes < 0) {
	// 		perror("SSL_read failed");
	// 		exit(1);
	// 	}
	// 	int i = 0,crlfCount = 0,j = 0;
	// 	char url[50]={0};
		
	// 	//ignore method
	// 	while (buf[i] != ' ') i++;
		
	// 	//get url
	// 	i++;// '/'
	// 	for (i = i+1; buf[i] != ' ';i++) {
	// 		url[j++] = buf[i]; 
	// 	}
	// 	//check url
	// 	FILE* fd;
	// 	if ( !(fd = fopen(url,"r")) ){
	// 		const char* response = "HTTP/1.0 404 Not Found\r\n\r\nCNLab 2: Socket programming";
	// 		SSL_write(ssl,response, strlen(response));
	// 		int sock = SSL_get_fd(ssl);
    // 		SSL_free(ssl);
    // 		close(sock);
	// 		return;
	// 	}	
	// 	//ignore version
	// 	while(buf[i] != '\r' || buf[i+1] != '\n') i++;
	
	// 	// headers
	// 	int from = -1, to = 0;
	// 	while (crlfCount != 2) {
	// 		if (buf[i] == '\r' && buf[i+1] == '\n') {
	// 			i += 2;
	// 			crlfCount ++;
	// 		}else {
	// 			if (crlfCount) crlfCount = 0; 
	// 			// chek Range
	// 			char name[20] = {0};
	// 			strncpy(name,buf+i,13);
	// 			if (!strcmp("Range: bytes=", name)) {
	// 				from = 0;					
	// 				i = i + 13;
	// 				//from
	// 				while (buf[i] != '-') {
	// 					from *= 10;
	// 					from += buf[i] - '0';
	// 					i++;
	// 				}
	// 				i++; 
	// 				//to
	// 				if(buf[i] == '\r') to = -1;
	// 				else {
	// 					while(buf[i] != '\r') {
	// 						to *= 10;
	// 						to += buf[i]-'0';
	// 						i++;							
	// 					}
	// 				}  
	// 			}else {
	// 				while(buf[i] != '\r' || buf[i+1] != '\n') i++;
	// 			}			
	// 		}	
	// 	}
	// 	//get file context
	// 	fseek(fd,0,SEEK_END);
	// 	long size = ftell(fd);
	// 	if (from == -1) {
	// 		from = 0;
	// 		to = size-1;
	// 		strcpy(response,"HTTP/1.0 200 OK\r\n\r\n");
	// 	}else {
	// 		if (to == -1) to = size-1;
	// 		strcpy(response,"HTTP/1.0 206 Partial Content\r\n\r\n");
	// 	}
	// 	fseek(fd,from,SEEK_SET);
	// 	char* context = (char*)malloc(to-from+1);
	// 	memset(context,0,to-from+2);
	// 	fread(context,1,to-from+1,fd);

	// 	// get final response
	// 	strcat(response,context);
	// 	// if (to-from < 110) printf("%s\n",context);
	// 	// else printf("%s\n",context+size-100);
	// 	// printf("end:%x\n",*(context+to-from));
	// 	// printf("afterEnd:%x\n",*(context+to-from+1));
	// 	SSL_write(ssl,response, strlen(response));
    // 	}

    // int sock = SSL_get_fd(ssl);
    // SSL_free(ssl);
    // close(sock);
// }

void * http_server(){
	
	// init socket, listening to port 80
	// int sock = alloc_tcp_sock();
	// if (sock < 0) {
	// 	perror("Opening socket failed");
	// 	exit(1);
	// }
	// int enable = 1;
	// if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int)) < 0) {
	// 	perror("setsockopt(SO_REUSEADDR) failed");
	// 	exit(1);
	// }
	struct tcp_sock *tsk = alloc_tcp_sock();
	struct sock_addr addr;
	addr.ip = htonl(0);
	addr.port = htons(80);

	if (tcp_sock_bind(tsk, &addr) < 0) {
		log(ERROR, "tcp_sock bind to port 80 failed");
		exit(1);
	}

	if (tcp_sock_listen(tsk, 3) < 0) {
		log(ERROR, "tcp_sock listen failed");
		exit(1);
	}

	log(DEBUG, "listen to port 80.");



	while (1) {
		// struct sockaddr_in caddr;
		// socklen_t len;
		// int csock = accept(sock, (struct sockaddr*)&caddr, &len);
		// if (csock < 0) {
		// 	perror("Accept failed");
		// 	exit(1);
		// }
		struct tcp_sock *csk = tcp_sock_accept(tsk);
		log(DEBUG, "accept a connection.");
		handle_http_request(csk);
		tcp_sock_close(csk);
	}
	// sleep(5);

	// tcp_sock_close(csk);
}
void handle_http_request(struct tcp_sock *csock) {
	char* response = (char*)malloc(4500000);

	// FILE *f = fopen("server-output.dat", "w");

	// #define MAX_LEN 10000
	// char *buf = malloc(MAX_LEN);
	// int i, len;
	// while (!tcp_sock_read(csk, (char*)&len, 4)) ;

	// printf("server: will recv %d bytes.\n", len);

	// while (len) {
	// 	int ret = tcp_sock_read(csk, buf, min(MAX_LEN, len));
	// 	for (i = 0; i < ret; i++) fprintf(f, "%c", buf[i]);
	// 	len -= ret;
	// }

	// fclose(f);

	char buf[1024] = {0};
	int bytes = tcp_sock_read(csock, buf, sizeof(buf));
	if (bytes < 0) {
		perror("SSL_read failed");
		exit(1);
	}
	int i = 0,crlfCount = 0,j = 0;
	char url[50]={0};

	printf("request = %s\n",buf);
	//ignore method
	while (buf[i] != ' ') i++;
	
	//get url
	i++;// '/'
	for (i = i+1; buf[i] != ' ';i++) {
		url[j++] = buf[i]; 
	}
	//check url
	FILE* fd;
	if ( !(fd = fopen(url,"r")) ){
		char* response = "HTTP/1.0 404 Not Found\r\n\r\nCNLab 2: Socket programming";
		// SSL_write(ssl,response, strlen(response));
		tcp_sock_write(csock, response, strlen(response));
		return;
	}	
	//ignore version
	while(buf[i] != '\r' || buf[i+1] != '\n') i++;

	// headers
	int from = -1, to = 0;
	while (crlfCount != 2) {
		if (buf[i] == '\r' && buf[i+1] == '\n') {
			i += 2;
			crlfCount ++;
		}else {
			if (crlfCount) crlfCount = 0; 
			// chek Range
			char name[20] = {0};
			strncpy(name,buf+i,13);
			if (!strcmp("Range: bytes=", name)) {
				from = 0;					
				i = i + 13;
				//from
				while (buf[i] != '-') {
					from *= 10;
					from += buf[i] - '0';
					i++;
				}
				i++; 
				//to
				if(buf[i] == '\r') to = -1;
				else {
					while(buf[i] != '\r') {
						to *= 10;
						to += buf[i]-'0';
						i++;							
					}
				}  
			}else {
				while(buf[i] != '\r' || buf[i+1] != '\n') i++;
			}			
		}	
	}
	//get file context
	fseek(fd,0,SEEK_END);
	long size = ftell(fd);
	if (from == -1) {
		from = 0;
		to = size-1;
		strcpy(response,"HTTP/1.0 200 OK\r\n\r\n");
	}else {
		if (to == -1) to = size-1;
		strcpy(response,"HTTP/1.0 206 Partial Content\r\n\r\n");
	}
	printf("*****begin get context of file*******\n");
	printf("from = %d, to = %d\n", from, to);
	fseek(fd,from,SEEK_SET);
	char* context = (char*)malloc(to-from+2);
	printf("1\n");
	memset(context,0,to-from+2);
	fread(context,1,to-from+1,fd);
	printf("2\n");
	// get final response
	strcat(response,context);
	printf("3\n");
	// if (to-from < 110) printf("%s\n",context);
	// else printf("%s\n",context+size-100);
	// printf("end:%x\n",*(context+to-from));
	// printf("afterEnd:%x\n",*(context+to-from+1));
	tcp_sock_write(csock, response, strlen(response));
	
}

// int main_bypass()
// {
// 	pthread_t https,http;
// 	int ret1,ret2;

	// char* argv0 = malloc(20);
	// memset(argv0,0,20);
	// strcpy(argv0, "http_server");
	
	// char* argv1 = malloc(10);
	// memset(argv1,0,10);
	// strcpy(argv1, "server");
	
	// char* argv2 = malloc(10);
	// memset(argv2,0,10);
	// strcpy(argv2, "80");

	// char* *argv = malloc(3*sizeof(char*));
	// argv[0] = argv0;
	// argv[1] = argv1;
	// argv[2] = argv2;

	// init_server(3, argv);	
	// printf("return from init main\n");
	// ret1 = pthread_create(&https,NULL,https_server,NULL);
	// if (ret1) {
	// 	printf("pthread create 1 error!");
	// 	return 0;
	// }
// 	ret2 = pthread_create(&http,NULL,http_server,NULL);
// 	if (ret2) {
// 		printf("pthread create 2 error!");
// 		return 0;
// 	}
// 	pthread_join(https,NULL);
// 	pthread_join(http,NULL);
// 	return 0;
// }
