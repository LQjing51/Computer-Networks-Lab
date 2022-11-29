#include "tcp_sock.h"

#include "log.h"

#include <unistd.h>

const char *data = "I Love Compute Network.";

// tcp server application, listens to port (specified by arg) and serves only one
// connection request
void *tcp_server(void *arg)
{
	u16 port = *(u16 *)arg;
	struct tcp_sock *tsk = alloc_tcp_sock();

	struct sock_addr addr;
	addr.ip = htonl(0);
	addr.port = port;
	if (tcp_sock_bind(tsk, &addr) < 0) {
		log(ERROR, "tcp_sock bind to port %hu failed", ntohs(port));
		exit(1);
	}

	if (tcp_sock_listen(tsk, 3) < 0) {
		log(ERROR, "tcp_sock listen failed");
		exit(1);
	}

	log(DEBUG, "listen to port %hu.", ntohs(port));

	struct tcp_sock *csk = tcp_sock_accept(tsk);

	log(DEBUG, "accept a connection.");

	/* expr 2 */
	// int len = strlen(data);
	// char *buffer = (char*)malloc(len+1);
	// int ret = tcp_sock_read(csk, buffer, len);
	// buffer[ret] = '\0';
	// printf("server recv: %s\n", buffer);

	// tcp_sock_write(csk, buffer, len);

	/* expr 3 */
	FILE *f = fopen("server-output.dat", "w");

	#define MAX_LEN 10000
	char *buf = malloc(MAX_LEN);
	int i, len;
	while (!tcp_sock_read(csk, &len, 4)) ;

	printf("server: will recv %d bytes.\n", len);

	while (len) {
		int ret = tcp_sock_read(csk, buf, min(MAX_LEN, len));
		for (i = 0; i < ret; i++) fprintf(f, "%c", buf[i]);
		len -= ret;
	}

	fclose(f);

	sleep(5);
	tcp_sock_close(csk);
	
	return NULL;
}

// tcp client application, connects to server (ip:port specified by arg), each
// time sends one bulk of data and receives one bulk of data 
void *tcp_client(void *arg)
{
	struct sock_addr *skaddr = arg;

	struct tcp_sock *tsk = alloc_tcp_sock();

	if (tcp_sock_connect(tsk, skaddr) < 0) {
		log(ERROR, "tcp_sock connect to server ("IP_FMT":%hu)failed.", \
				NET_IP_FMT_STR(skaddr->ip), ntohs(skaddr->port));
		exit(1);
	}

	// /* expr 2 */
	// int len = strlen(data);
	// tcp_sock_write(tsk, data, len);

	// printf("client send: %s\n", data);

	// char *buf = malloc(len+1);
	// int ret = tcp_sock_read(tsk, buf, len);
	// buf[ret] = '\0';
	// printf("client recv: %s\n", buf);

	/* expr 3 */
	FILE *f = fopen("client-input.dat", "r");
	fseek(f, 0, SEEK_END);
	int len = ftell(f);
	fseek(f, 0, SEEK_SET);

	printf("client: will send %d bytes.\n", len);

	char *buf = malloc(len);
	int i = 0;
	char c;
	while (fscanf(f,"%c",&c) != EOF) {
		buf[i++] = c;
		// if (!(i%100)) printf("%d\n",i);
	}
	// printf("begin send data\n");
	tcp_sock_write(tsk, &len, 4);	//send length first
	tcp_sock_write(tsk, buf, len);

	fclose(f);

	sleep(1);
	tcp_sock_close(tsk);

	return NULL;
}
/*
#include "tcp_sock.h"

#include "log.h"

#include <stdlib.h>
#include <unistd.h>

// tcp server application, listens to port (specified by arg) and serves only one
// connection request
void *tcp_server(void *arg)
{
	u16 port = *(u16 *)arg;
	struct tcp_sock *tsk = alloc_tcp_sock();

	struct sock_addr addr;
	addr.ip = htonl(0);
	addr.port = port;
	if (tcp_sock_bind(tsk, &addr) < 0) {
		log(ERROR, "tcp_sock bind to port %hu failed", ntohs(port));
		exit(1);
	}

	if (tcp_sock_listen(tsk, 3) < 0) {
		log(ERROR, "tcp_sock listen failed");
		exit(1);
	}

	log(DEBUG, "listen to port %hu.", ntohs(port));

	struct tcp_sock *csk = tcp_sock_accept(tsk);

	log(DEBUG, "accept a connection.");

	char rbuf[1001];
	char wbuf[1024];
	int rlen = 0;
	while (1) {
		rlen = tcp_sock_read(csk, rbuf, 1000);
		if (rlen == 0) {
			log(DEBUG, "tcp_sock_read return 0, finish transmission.");
			break;
		} 
		else if (rlen > 0) {
			rbuf[rlen] = '\0';
			sprintf(wbuf, "server echoes: %s", rbuf);
			if (tcp_sock_write(csk, wbuf, strlen(wbuf)) < 0) {
				log(DEBUG, "tcp_sock_write return negative value, something goes wrong.");
				exit(1);
			}
		}
		else {
			log(DEBUG, "tcp_sock_read return negative value, something goes wrong.");
			exit(1);
		}
	}

	log(DEBUG, "close this connection.");

	tcp_sock_close(csk);
	
	return NULL;
}

// tcp client application, connects to server (ip:port specified by arg), each
// time sends one bulk of data and receives one bulk of data 
void *tcp_client(void *arg)
{
	struct sock_addr *skaddr = arg;

	struct tcp_sock *tsk = alloc_tcp_sock();

	if (tcp_sock_connect(tsk, skaddr) < 0) {
		log(ERROR, "tcp_sock connect to server ("IP_FMT":%hu)failed.", \
				NET_IP_FMT_STR(skaddr->ip), ntohs(skaddr->port));
		exit(1);
	}

	char *wbuf = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
	int wlen = strlen(wbuf);
	char rbuf[1001];
	int rlen = 0;

	int n = 10;
	for (int i = 0; i < n; i++) {
		if (tcp_sock_write(tsk, wbuf + i, wlen - n) < 0)
			break;
		// printf("client finish write, i = %d\n",i);
		rlen = tcp_sock_read(tsk, rbuf, 1000);
		if (rlen == 0) {
			log(DEBUG, "tcp_sock_read return 0, finish transmission.");
			break;
		}
		else if (rlen > 0) {
			rbuf[rlen] = '\0';
			fprintf(stdout, "%s\n", rbuf);
			//log(DEBUG, "%s\n", rbuf);
		}
		else {
			log(DEBUG, "tcp_sock_read return negative value, something goes wrong.");
			exit(1);
		}
		sleep(1);
	}

	tcp_sock_close(tsk);

	return NULL;
}
//*/