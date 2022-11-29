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
	int len = strlen(data);
	tcp_sock_read(tsk, data, len);

	printf("server recv: %s\n", data);

	tcp_sock_write(tsk, data, len);

	/* expr 3 */
	// FILE *f = fopen("server-output.dat", "w");

	// #define MAX_LEN 10000
	// char *buf = malloc(MAX_LEN);
	// int i, len;
	// while (!tcp_sock_read(tsk, &len, 4)) ;

	// printf("server: will recv %d bytes.\n", len);

	// while (len) {
	// 	int ret = tcp_sock_read(tsk, buf, min(MAX_LEN, len));
	// 	for (i = 0; i < ret; i++) fprintf(f, "%c", buf[i]);
	// 	len -= ret;
	// }

	// fclose(f);

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

	/* expr 2 */
	int len = strlen(data);
	tcp_sock_write(tsk, data, len);

	printf("client send: %s\n", data);

	char *buf = malloc(len);
	tcp_sock_read(tsk, buf, len);

	printf("client recv: %s\n", buf);

	/* expr 3 */
	// FILE *f = fopen("client-input.dat", "r");
	// fseek(f, 0, SEEK_END);
	// int len = ftell(f);
	// fseek(f, 0, SEEK_SET);

	// printf("client: will send %d bytes.\n", len);

	// char *buf = malloc(len);
	// int i = 0;
	// char c;
	// while ((c = getchar()) != EOF) buf[i++] = c;

	// tcp_sock_write(tsk, &len, 4);	//send length first
	// tcp_sock_write(tsk, buf, len);

	// fclose(f);

	sleep(1);
	tcp_sock_close(tsk);

	return NULL;
}
