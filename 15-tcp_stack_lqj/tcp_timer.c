#include "tcp.h"
#include "tcp_timer.h"
#include "tcp_sock.h"

#include <stdio.h>
#include <unistd.h>

static struct list_head timer_list;

pthread_mutex_t timer_lock;

// scan the timer_list, find the tcp sock which stays for at 2*MSL, release it
void tcp_scan_timer_list()
{
	pthread_mutex_lock(&timer_lock);
	struct tcp_timer *timer, *timer_;
	list_for_each_entry_safe(timer, timer_, &timer_list, list)
		if (timer->enable) {
			timer->elapse += TCP_TIMER_SCAN_INTERVAL;
			if (timer->elapse >= timer->timeout) {
				if (timer->type == 1) {
					struct tcp_sock *tsk = list_entry(timer, struct tcp_sock, timewait);
					if (++timer->retries == 3) {
						// close socket
						tcp_send_control_packet(tsk, TCP_RST);
						tcp_unhash(tsk);
						tcp_bind_unhash(tsk);
						tcp_set_state(tsk, TCP_CLOSED);
						list_delete_entry(&timer->list);
					} else {
						// reset timer
						timer->elapse = 0;
						timer->timeout *= 2;
						// retransmit packets
						struct retrans_packet *pkt;
						list_for_each_entry(pkt, &tsk->send_buf, list) {
							ip_send_packet(pkt->packet, pkt->length);
						}
					}
				} else {
					struct tcp_sock *tsk = list_entry(timer, struct tcp_sock, timewait);
					tcp_unhash(tsk);
					tcp_bind_unhash(tsk);
					tcp_set_state(tsk, TCP_CLOSED);
					list_delete_entry(&timer->list);
				}
			}
		}
	pthread_mutex_unlock(&timer_lock);
}

// set the timewait timer of a tcp sock, by adding the timer into timer_list
void tcp_set_timewait_timer(struct tcp_sock *tsk)
{
	tsk->timewait.type = 0;
	tsk->timewait.timeout = TCP_TIMEWAIT_TIMEOUT;
	tsk->timewait.elapse = 0;
	tsk->timewait.enable = 1;
	list_add_head(&tsk->timewait.list, &timer_list);
}

void tcp_set_retrans_timer(struct tcp_sock *tsk) {
	if (tsk->retrans_timer.enable) {
		tsk->retrans_timer.timeout = TCP_RETRANS_INTERVAL_INITIAL;
		tsk->retrans_timer.elapse = 0;
		tsk->retrans_timer.retries = 0;
	} else {
		tsk->retrans_timer.type = 1;
		tsk->retrans_timer.timeout = TCP_RETRANS_INTERVAL_INITIAL;
		tsk->retrans_timer.elapse = 0;
		tsk->retrans_timer.retries = 0;
		tsk->retrans_timer.enable = 1;
		list_add_head(&tsk->retrans_timer.list, &timer_list);
	}
}

void tcp_unset_retrans_timer(struct tcp_sock *tsk) {
	tsk->retrans_timer.enable = 0;
	list_delete_entry(&tsk->retrans_timer.list);
}

// scan the timer_list periodically by calling tcp_scan_timer_list
void *tcp_timer_thread(void *arg)
{
	init_list_head(&timer_list);
	pthread_mutex_init(&timer_lock);
	while (1) {
		usleep(TCP_TIMER_SCAN_INTERVAL);
		tcp_scan_timer_list();
	}

	return NULL;
}
