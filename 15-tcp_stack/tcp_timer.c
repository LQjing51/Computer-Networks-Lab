#include "tcp.h"
#include "tcp_timer.h"
#include "tcp_sock.h"
#include "log.h"

#include <stdio.h>
#include <unistd.h>

static struct list_head timer_list;

static pthread_mutex_t timer_lock;

// scan the timer_list, find the tcp sock which stays for at 2*MSL, release it
void tcp_scan_timer_list()
{
	pthread_mutex_lock(&timer_lock);
	struct tcp_timer *timer, *timer_;
	list_for_each_entry_safe(timer, timer_, &timer_list, list) {
		timer->timeout -= TCP_TIMER_SCAN_INTERVAL;
		if (timer->enable && timer->timeout <= 0) {
			if (timer->type == 0) {
				// time-wait
				struct tcp_sock *tsk = list_entry(timer, struct tcp_sock, timewait);
				tcp_unhash(tsk);
				tcp_bind_unhash(tsk);
				tcp_set_state(tsk, TCP_CLOSED);
				list_delete_entry(&timer->list);
			} else {
				struct tcp_sock *tsk = list_entry(timer, struct tcp_sock, retrans_timer);
				if (++tsk->send_retries == SEND_MAX_RETRY) {
					log(ERROR, "Retransmit packet 3 times, close socket");
					tcp_send_control_packet(tsk, TCP_RST);
					tcp_unhash(tsk);
					tcp_bind_unhash(tsk);
					tcp_set_state(tsk, TCP_CLOSED);
					timer->enable = 0;
					continue;
				} 
				pthread_mutex_lock(&tsk->send_buf_lock);
				if (list_empty(&tsk->send_buf)) {
					timer->enable = 0;
				} else {
					struct tcp_cached_pkt *cpkt;
					list_for_each_entry(cpkt, &tsk->send_buf, list) {
						char *new_packet = malloc(cpkt->len);
						memcpy(new_packet, cpkt->packet, cpkt->len);
						ip_send_packet(new_packet, cpkt->len);
					}
					timer->timeout = TCP_RETRANS_INTERVAL_INITIAL << tsk->send_retries;
				}
				pthread_mutex_unlock(&tsk->send_buf_lock);
			}
		}
	}
	pthread_mutex_unlock(&timer_lock);
}

// set the timewait timer of a tcp sock, by adding the timer into timer_list
void tcp_set_timewait_timer(struct tcp_sock *tsk)
{
	tsk->timewait.enable = 1;
	tsk->timewait.type = 0;
	tsk->timewait.timeout = TCP_TIMEWAIT_TIMEOUT;

	pthread_mutex_lock(&timer_lock);
	list_add_head(&tsk->timewait.list, &timer_list);
	pthread_mutex_unlock(&timer_lock);
}

void tcp_set_retrans_timer(struct tcp_sock *tsk)
{
	pthread_mutex_lock(&timer_lock);
	tsk->retrans_timer.enable = 1;
	tsk->retrans_timer.type = 1;
	tsk->retrans_timer.timeout = TCP_RETRANS_INTERVAL_INITIAL;
	tsk->send_retries = 0;

	if (!tsk->retrans_timer.list.next)
		list_add_head(&tsk->retrans_timer.list, &timer_list);
	pthread_mutex_unlock(&timer_lock);
}

void tcp_unset_retrans_timer(struct tcp_sock *tsk)
{
	pthread_mutex_lock(&timer_lock);
	tsk->retrans_timer.enable = 0;
	pthread_mutex_unlock(&timer_lock);
}

// scan the timer_list periodically by calling tcp_scan_timer_list
void *tcp_timer_thread(void *arg)
{
	init_list_head(&timer_list);
	pthread_mutex_init(&timer_lock, NULL);
	while (1) {
		usleep(TCP_TIMER_SCAN_INTERVAL);
		tcp_scan_timer_list();
	}

	return NULL;
}
