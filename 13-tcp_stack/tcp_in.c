#include "tcp.h"
#include "tcp_sock.h"
#include "tcp_timer.h"

#include "log.h"
#include "ring_buffer.h"

#include <stdlib.h>
// update the snd_wnd of tcp_sock
//
// if the snd_wnd before updating is zero, notify tcp_sock_send (wait_send)
static inline void tcp_update_window(struct tcp_sock *tsk, struct tcp_cb *cb)
{
	// u16 old_snd_wnd = tsk->snd_wnd;
	tsk->snd_wnd = cb->rwnd;
	// if (old_snd_wnd == 0)
	// 	wake_up(tsk->wait_send);
}

// update the snd_wnd safely: cb->ack should be between snd_una and snd_nxt
static inline void tcp_update_window_safe(struct tcp_sock *tsk, struct tcp_cb *cb)
{
	if (less_or_equal_32b(tsk->snd_una, cb->ack) && less_or_equal_32b(cb->ack, tsk->snd_nxt)){
		// tcp_update_window(tsk, cb);
		tsk->snd_una = cb->ack;
		tcp_update_window(tsk, cb);
		wake_up(tsk->wait_send);
	}
}

#ifndef max
#	define max(x,y) ((x)>(y) ? (x) : (y))
#endif

// check whether the sequence number of the incoming packet is in the receiving
// window
static inline int is_tcp_seq_valid(struct tcp_sock *tsk, struct tcp_cb *cb)
{
	u32 rcv_end = tsk->rcv_nxt + max(tsk->rcv_wnd, 1);
	// printf("cb->seq = %u,rcv_end = %u,rev_nxt = %u,cb->seq_end = %u\n",cb->seq,rcv_end,tsk->rcv_nxt,cb->seq_end);
	if (less_than_32b(cb->seq, rcv_end) && less_or_equal_32b(tsk->rcv_nxt, cb->seq_end)) {
		return 1;
	}
	else {
		log(ERROR, "received packet with invalid seq, drop it.");
		return 0;
	}
}

// Process the incoming packet according to TCP state machine. 
void tcp_process(struct tcp_sock *tsk, struct tcp_cb *cb, char *packet)
{
	// printf("flags = %d\n",cb->flags);
	if (tsk->state == TCP_LISTEN) {
		if (cb->flags & TCP_SYN) {
			/* new SYN request */
			// alloc a new socket
			struct tcp_sock *csk = alloc_tcp_sock();
			csk->parent = tsk;
			csk->sk_dip = cb->saddr;
			csk->sk_dport = cb->sport;
			csk->sk_sip = cb->daddr;
			csk->sk_sport = tsk->sk_sport;
			// set iss
			csk->iss = csk->snd_nxt = csk->snd_una = tcp_new_iss();
			// printf("send_nxt = %u\n",csk->snd_nxt);
			// set rcv_nxt
			csk->rcv_nxt = cb->seq + 1;

			// add csk into listen_queue
			list_add_head(&csk->list, &tsk->listen_queue);

			// send SYN
			// printf("send SYN|ACK\n");
			tcp_send_control_packet(csk, TCP_SYN | TCP_ACK);
			tcp_set_state(csk, TCP_SYN_RECV);
			return;
		}
		if (cb->flags & TCP_ACK) {
			/* response to my SYN */
			// printf("father receives ack\n");
			struct tcp_sock *csk, *csk_;
			list_for_each_entry_safe(csk, csk_, &tsk->listen_queue, list) {
				if (csk->sk_dip == cb->saddr && csk->sk_dport == cb->sport) {
					tcp_update_window_safe(csk, cb);

					// add csk into parent's accept queue
					tcp_sock_accept_enqueue(csk);

					// connection established
					tcp_set_state(csk, TCP_ESTABLISHED);

					// wake up tcp_sock_accept
					wake_up(tsk->wait_accept);
					break;
				}
			}
			return;
		}
	}

	if (tsk->state == TCP_SYN_SENT) {
		if (cb->flags & TCP_ACK) {
			tcp_update_window_safe(tsk, cb);
		}
		if (cb->flags & TCP_SYN) {
			// set rcv_nxt
			tsk->rcv_nxt = cb->seq + 1;

			// send ACK
			// printf("send ACK\n");
			tcp_send_control_packet(tsk, TCP_ACK);

			// connection established
			tcp_set_state(tsk, TCP_ESTABLISHED);

			// wake up tcp_sock_connect
			wake_up(tsk->wait_connect);
		}
		return;
	}

		// As connection is established, we should check seq
	if (!is_tcp_seq_valid(tsk, cb)) return;
	tsk->rcv_nxt = cb->seq_end;

	if (tsk->state == TCP_FIN_WAIT_1) {
		if (cb->flags & TCP_ACK) {
			tcp_update_window_safe(tsk, cb);

			tcp_set_state(tsk, TCP_FIN_WAIT_2);

			// do not return, check TCP_FIN
		}
	}

	if (tsk->state == TCP_FIN_WAIT_2) {
		if (cb->flags & TCP_FIN) {
			// send ACK
			tcp_send_control_packet(tsk, TCP_ACK);

			// set timer
			tcp_set_timewait_timer(tsk);

			tcp_set_state(tsk, TCP_TIME_WAIT);
			return;
		}
	}

	if (tsk->state == TCP_LAST_ACK) {
		if (!(cb->flags & TCP_ACK)) {
			log(ERROR, "TCP_LAST_ACK can only recv TCP_ACK packet.");
			return;
		}
		// release source
		tcp_unhash(tsk);
		tcp_bind_unhash(tsk);

		tcp_set_state(tsk, TCP_CLOSED);
		return;
	}

	if (tsk->state == TCP_ESTABLISHED) {
		if (cb->flags & TCP_ACK) {
			tcp_update_window_safe(tsk, cb);
		}
		if (cb->flags & TCP_FIN) {
			// send ACK
			tcp_send_control_packet(tsk, TCP_ACK);

			tcp_set_state(tsk, TCP_CLOSE_WAIT);

			return;
		}
	}

	// handle payload
	if (cb->pl_len) {
		pthread_mutex_lock(&tsk->lock);
		write_ring_buffer(tsk->rcv_buf, cb->payload, cb->pl_len);
		pthread_mutex_unlock(&tsk->lock);

		// send ACK
		tcp_send_control_packet(tsk, TCP_ACK);

		// wake up wait_recv
		wake_up(tsk->wait_recv);
	}
}
