#include "tcp.h"
#include "tcp_sock.h"
#include "tcp_timer.h"

#include "log.h"
#include "ring_buffer.h"

#include <stdlib.h>

#ifndef max
#	define max(x,y) ((x)>(y) ? (x) : (y))
#endif

static inline void tcp_update_rcv_buffer(struct tcp_sock *tsk, struct tcp_cb *cb) {
	pthread_mutex_lock(&tsk->rcv_buf_lock);
	// if (cb->seq == tsk->rcv_nxt) {
	// 	write_ring_buffer(tsk->rcv_buf, cb->payload, cb->pl_len);
	// 	tsk->rcv_nxt = cb->seq_end;
	// } else {
		char *data = malloc(cb->pl_len);
		memcpy(data, cb->payload, cb->pl_len);
		struct tcp_ofo_data *ofo_data = malloc(sizeof(struct tcp_ofo_data));
		ofo_data->data = data;
		ofo_data->len = cb->pl_len;
		ofo_data->seq = cb->seq;

		// find a right place to insert
		if (list_empty(&tsk->rcv_ofo_buf)) {
			list_add_head(&ofo_data->list, &tsk->rcv_ofo_buf);
		} else {
			struct tcp_ofo_data *first_entry = list_entry(tsk->rcv_ofo_buf.next, struct tcp_ofo_data, list);
			if (ofo_data->seq < first_entry->seq) list_add_head(&ofo_data->list, &tsk->rcv_ofo_buf);
			else {
				int flag = 0;
				struct tcp_ofo_data *ptr, *ptr_, *lst = NULL;
				list_for_each_entry_safe(ptr, ptr_, &tsk->rcv_ofo_buf, list) {
					if (ofo_data->seq == ptr->seq) {
						// packet has received
						// pthread_mutex_unlock(&tsk->rcv_buf_lock);
						// return;
						goto CHECK_OFO;
					}
					if (ofo_data->seq < ptr->seq) {
						list_insert(&ofo_data->list, &lst->list, &ptr->list);
						flag = 1;
						break;
					}
					lst = ptr;
				}
				if (!flag) list_add_tail(&ofo_data->list, &tsk->rcv_ofo_buf);
			}
		}
	// }
CHECK_OFO:
	if (!list_empty(&tsk->rcv_ofo_buf)) {
		// check continuous data
		struct tcp_ofo_data *ptr, *ptr_;
		list_for_each_entry_safe(ptr, ptr_, &tsk->rcv_ofo_buf, list) {
			if (ptr->seq != tsk->rcv_nxt || ring_buffer_free(tsk->rcv_buf) < ptr->len) {
				printf("\nrcv_nxt = %u, ptr->seq = %u\n", tsk->rcv_nxt, ptr->seq);
				break;
			}
			write_ring_buffer(tsk->rcv_buf, ptr->data, ptr->len);
			tsk->rcv_nxt += ptr->len;
			list_delete_entry(&ptr->list);
			free(ptr->data);
		}
	}

	tsk->rcv_wnd = ring_buffer_free(tsk->rcv_buf);//min(ring_buffer_free(tsk->rcv_buf) + MSS, TCP_DEFAULT_WINDOW);
	pthread_mutex_unlock(&tsk->rcv_buf_lock);
}


// update the send_buf of tcp_sock
static inline void tcp_update_send_buf(struct tcp_sock *tsk) {
	int flag = 0;

	pthread_mutex_lock(&tsk->send_buf_lock);
	struct tcp_cached_pkt *cpkt, *cpkt_;
	list_for_each_entry_safe(cpkt, cpkt_, &tsk->send_buf, list) {
		if (cpkt->end <= tsk->snd_una) {
			// this packet has been acked
			list_delete_entry(&cpkt->list);
			free(cpkt->packet);
			flag = 1;
		}
	}
	if (list_empty(&tsk->send_buf)) {
		tcp_unset_retrans_timer(tsk);
		flag = 0;
	}
	pthread_mutex_unlock(&tsk->send_buf_lock);

	if (flag) tcp_set_retrans_timer(tsk);
}

static inline void tcp_clear_send_buf(struct tcp_sock *tsk) {
	pthread_mutex_lock(&tsk->send_buf_lock);
	struct tcp_cached_pkt *cpkt, *cpkt_;
	list_for_each_entry_safe(cpkt, cpkt_, &tsk->send_buf, list) {
		list_delete_entry(&cpkt->list);
		free(cpkt->packet);
	}
	tcp_unset_retrans_timer(tsk);
	pthread_mutex_unlock(&tsk->send_buf_lock);
}
// update the snd_wnd of tcp_sock
//
// if the snd_wnd before updating is zero, notify tcp_sock_send (wait_send)
static inline void tcp_update_window(struct tcp_sock *tsk, struct tcp_cb *cb)
{
	tsk->snd_wnd = min(tsk->adv_wnd, tsk->cwnd * MSS);
	int in_flight = (int) (tsk->snd_nxt - tsk->snd_una) / MSS - tsk->dupacks;
	tsk->allow_snd = tsk->snd_wnd / MSS - max(in_flight,0);
	printf("adv_wnd = %d, snd_wnd = %d, in_flight = %d, allow_snd: %d\n",tsk->adv_wnd, tsk->snd_wnd, in_flight, tsk->allow_snd);
	wake_up(tsk->wait_send);
}

// update the snd_wnd safely: cb->ack should be between snd_una and snd_nxt
static inline void tcp_update_window_safe(struct tcp_sock *tsk, struct tcp_cb *cb)
{
	if (less_or_equal_32b(tsk->snd_una, cb->ack) && less_or_equal_32b(cb->ack, tsk->snd_nxt)){
		tsk->snd_una = cb->ack;
		tsk->adv_wnd = cb->rwnd;
		tcp_update_send_buf(tsk);
		tcp_update_window(tsk, cb);
	}
}

static inline void retrans_first_packet(struct tcp_sock *tsk) {
	pthread_mutex_lock(&tsk->send_buf_lock);
	if (list_empty(&tsk->send_buf)) {
		log(ERROR, "retrans_packet: no packet to retrans");
		return;
	}
	struct tcp_cached_pkt *cpkt = list_entry(tsk->send_buf.next, struct tcp_cached_pkt, list);
	char *new_packet = malloc(cpkt->len);
	memcpy(new_packet, cpkt->packet, cpkt->len);
	ip_send_packet(new_packet, cpkt->len);
	pthread_mutex_unlock(&tsk->send_buf_lock);
	printf("RETRANS: %u\n", cpkt->end);
}

// check whether the sequence number of the incoming packet is in the receiving
// window
static inline int is_tcp_seq_valid(struct tcp_sock *tsk, struct tcp_cb *cb)
{
	u32 rcv_end = tsk->rcv_nxt + max(tsk->rcv_wnd, 1);
	if (less_than_32b(cb->seq, rcv_end) && less_than_32b(tsk->rcv_nxt, cb->seq_end)) {
		return 1;
	}
	else {
		// log(ERROR, "received packet with invalid seq, drop it, seq = %u, seq_end = %u, rcv_nxt = %u, rcv_end = %u", cb->seq, cb->seq_end, tsk->rcv_nxt, rcv_end);
		return 0;
	}
}

// Process the incoming packet according to TCP state machine. 
void tcp_process(struct tcp_sock *tsk, struct tcp_cb *cb, char *packet)
{
	// Check LISTEN first
	if (tsk->state == TCP_LISTEN) {
		if (!(cb->flags & TCP_SYN)) {
			log(ERROR, "TCP_LISTEN can only recv TCP_SYN packet.");
			return;
		}
		// alloc a new socket
		struct tcp_sock *csk = alloc_tcp_sock();
		csk->parent = tsk;
		csk->sk_dip = cb->saddr;
		csk->sk_dport = cb->sport;
		csk->sk_sip = cb->daddr;
		csk->sk_sport = tsk->sk_sport;

		// set iss
		csk->iss = csk->snd_nxt = csk->snd_una = tcp_new_iss();

		// set rcv_nxt
		csk->rcv_nxt = cb->seq_end;

		// add csk into listen_queue
		list_add_head(&csk->list, &tsk->listen_queue);

		// send SYN
		tcp_send_control_packet(csk, TCP_SYN | TCP_ACK);

		tcp_set_state(csk, TCP_SYN_RECV);

		// add csk into establish table
		tcp_hash(csk);

		return;
	}

	/* Now incoming packet is aiming at tsk */

//	if (cb->flags & TCP_RST) {
//		// close socket
//		log(ERROR, "Receive RST packet, close socket, flags = %d", (int) cb->flags);
//		tcp_unhash(tsk);
//		tcp_bind_unhash(tsk);
//		tcp_set_state(tsk, TCP_CLOSED);
//		tcp_unset_retrans_timer(tsk);
//		return;
//	}

	if((cb->flags & TCP_PSH) && !is_tcp_seq_valid(tsk, cb)){
		return;
	}
	
	// handle ACK
	if(cb->flags & TCP_ACK){
		printf("cb->ack = %u, snd_una = %u\n", cb->ack, tsk->snd_una);
		if (cb->ack > tsk->snd_una) {
			// acked new data, update cwnd
			if (!tsk->ssthresh || tsk->cwnd < tsk->ssthresh) {
				tsk->cwnd++;
			} else {
				static int counter = 0;
				counter++;
				if (!(counter & 1)) tsk->cwnd++;
			}
		}
		// congestion control state transfer
		if (tsk->con_state == TCP_OPEN) {
			if (cb->ack == tsk->snd_una) {
				tsk->dupacks = 1;
				tcp_set_con_state(tsk, TCP_DISORDER);
			}
		} else if (tsk->con_state == TCP_DISORDER) {
			if (cb->ack == tsk->snd_nxt) {
				tsk->dupacks = 0;
				tcp_set_con_state(tsk, TCP_OPEN);
			} else if (cb->ack == tsk->snd_una && ++tsk->dupacks >= 3) {
				// retransmit first unacked packet
				retrans_first_packet(tsk);
				// set cwnd and ssthresh
				tsk->cwnd /= 2;
				tsk->ssthresh = tsk->cwnd / 2;
				// change state to RECOVERY
				tcp_set_con_state(tsk, TCP_RECOVERY);
				tsk->recovery_point = tsk->snd_nxt;
			}
		} else if (tsk->con_state == TCP_RECOVERY) {
			if (cb->ack >= tsk->recovery_point) {
				// full ack, back to OPEN
				tsk->dupacks = 0;
				// tcp_clear_send_buf(tsk);
				tcp_set_con_state(tsk, TCP_OPEN);
			} else if (cb->ack > tsk->snd_una) {
				// partial ack
				tsk->dupacks = 0;
				// retransmit
				tsk->snd_una = cb->ack;
				tcp_update_send_buf(tsk);
				retrans_first_packet(tsk);
			} else if (cb->ack == tsk->snd_una) {
				// no ack
				tsk->dupacks++;
			}
		} else if (tsk->con_state == TCP_LOSS) {
			// while(1);
			if (cb->ack > tsk->snd_una) {
				tsk->dupacks = 0;
				tcp_set_con_state(tsk, TCP_OPEN);
			}
		}

		tcp_update_window_safe(tsk, cb);

		log(DEBUG, "current cwnd = %d, dupacket = %d", tsk->cwnd, tsk->dupacks);
	}

	if (tsk->state == TCP_SYN_RECV) {
		if (!(cb->flags & TCP_ACK)) {
			log(ERROR, "TCP_SYN_RECV can only recv TCP_ACK packet.");
			return;
		}
		// add tsk into parent's accept queue
		tcp_sock_accept_enqueue(tsk);

		// connection established
		tcp_set_state(tsk, TCP_ESTABLISHED);
		tcp_set_con_state(tsk, TCP_OPEN);
		tsk->cwnd = 1;

		// wake up tcp_sock_accept
		wake_up(tsk->parent->wait_accept);

		// do not return, handle payload
	}

	if (tsk->state == TCP_SYN_SENT) {
		if (cb->flags & TCP_SYN) {
			tsk->rcv_nxt = cb->seq_end;
			
			// send ACK
			tcp_send_control_packet(tsk, TCP_ACK);

			// connection established
			tcp_set_state(tsk, TCP_ESTABLISHED);
			tcp_set_con_state(tsk, TCP_OPEN);
			tsk->cwnd = 1;

			// wake up tcp_sock_connect
			wake_up(tsk->wait_connect);
		}
		return;
	}

	if (tsk->state == TCP_FIN_WAIT_1) {
		if (cb->flags & TCP_ACK) {
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
			wake_up(tsk->wait_recv);
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
		if (cb->flags & TCP_FIN) {
			// send ACK
			tcp_send_control_packet(tsk, TCP_ACK);

			tcp_set_state(tsk, TCP_CLOSE_WAIT);
			wake_up(tsk->wait_recv);
		}
	}

	// handle payload
	if (cb->pl_len) {
		tcp_update_rcv_buffer(tsk, cb);

		// send ACK
		tcp_send_control_packet(tsk, TCP_ACK);
		printf("******send ACK = %u******\n", tsk->rcv_nxt);

		// wake up wait_recv
		wake_up(tsk->wait_recv);
	}
}
