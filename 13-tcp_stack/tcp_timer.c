#include "tcp.h"
#include "tcp_timer.h"
#include "tcp_sock.h"

#include <stdio.h>
#include <unistd.h>

static struct list_head timer_list;

// scan the timer_list, find the tcp sock which stays for at 2*MSL, release it
void tcp_scan_timer_list()
{
	struct tcp_timer *timer, *timer_;
	list_for_each_entry_safe(timer, timer_, &timer_list, list) {
		timer->timeout -= TCP_TIMER_SCAN_INTERVAL;
		if (timer->enable && timer->timeout <= 0) {
			struct tcp_sock *tsk = list_entry(timer, struct tcp_sock, timewait);
			tcp_unhash(tsk);
			tcp_bind_unhash(tsk);
			tcp_set_state(tsk, TCP_CLOSED);
			list_delete_entry(&timer->list);
		}
	}
}

// set the timewait timer of a tcp sock, by adding the timer into timer_list
void tcp_set_timewait_timer(struct tcp_sock *tsk)
{
	tsk->timewait.type = 0;
	tsk->timewait.timeout = TCP_TIMEWAIT_TIMEOUT;
	tsk->timewait.enable = 1;
	list_add_head(&tsk->timewait.list, &timer_list);
}

// scan the timer_list periodically by calling tcp_scan_timer_list
void *tcp_timer_thread(void *arg)
{
	init_list_head(&timer_list);
	while (1) {
		usleep(TCP_TIMER_SCAN_INTERVAL);
		tcp_scan_timer_list();
	}

	return NULL;
}
