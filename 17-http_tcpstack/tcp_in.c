#include "tcp.h"
#include "tcp_sock.h"
#include "tcp_timer.h"

#include "log.h"
#include "ring_buffer.h"

#include <stdlib.h>

static inline void tcp_check_send_buf(struct tcp_sock *tsk, struct tcp_cb *cb) {
	pthread_mutex_lock(&timer_lock);
	struct retrans_packet *pkt, *next_pkt;
	list_for_each_entry_safe(pkt, next_pkt, &tsk->send_buf, list) {
		// printf("check send buf: seq_end = %u, snd_una = %u\n",pkt->seq_end,tsk->snd_una);
		if (pkt->seq_end <= tsk->snd_una) {
			list_delete_entry(&pkt->list);
			tcp_set_retrans_timer(tsk);
			free(pkt->packet);
			free(pkt);
		}
	}
	if (list_empty(&tsk->send_buf)) {
		tcp_unset_retrans_timer(tsk);
	}
	pthread_mutex_unlock(&timer_lock);
}

static inline void insert_ofo_packet(struct ofo_packet *pkt, struct tcp_sock *tsk) {
	struct list_head *head = &tsk->rcv_ofo_buf;
	if (list_empty(head)) {
		list_add_head(&pkt->list, head);
		return;
	}
	struct ofo_packet *first = list_entry(head->next, struct ofo_packet, list);
	struct ofo_packet *last = list_entry(head->prev, struct ofo_packet, list);
	if (pkt->seq < first->seq) {
		list_add_head(&pkt->list, head);
		return;
	}
	if (pkt->seq > last->seq) {
		list_add_tail(&pkt->list, head);
		return;
	}
	struct ofo_packet *cur_pkt;
	list_for_each_entry(cur_pkt, head, list) {
		if (pkt->seq == cur_pkt->seq) return;
		if (pkt->seq < cur_pkt->seq) {
			list_insert(&pkt->list, cur_pkt->list.prev, &cur_pkt->list);
			break;
		}
	}
}

static inline void handle_payload(struct tcp_sock *tsk, struct tcp_cb *cb) {

	if (cb->seq_end <= tsk->rcv_nxt) return;
	// printf("handle payload: cb->seq = %u\n", cb->seq);
	struct ofo_packet *pkt = (struct ofo_packet *) malloc(sizeof(struct ofo_packet));
	pkt->payload = (char*)malloc(cb->pl_len);
	memcpy(pkt->payload, cb->payload, cb->pl_len);
	pkt->pl_len = cb->pl_len;
	pkt->seq = cb->seq;
	pkt->seq_end = cb->seq_end;
	
	insert_ofo_packet(pkt, tsk);

	// check sequence number
	pthread_mutex_lock(&tsk->rcv_buf->lock);
	struct ofo_packet *nxt_pkt;
	list_for_each_entry_safe(pkt, nxt_pkt, &tsk->rcv_ofo_buf, list) {
		// printf("handle_payload: pkt->seq = %u\n", pkt->seq);
		if (pkt->seq == tsk->rcv_nxt && ring_buffer_free(tsk->rcv_buf) >= pkt->pl_len) {
			write_ring_buffer(tsk->rcv_buf, pkt->payload, pkt->pl_len);
			tsk->rcv_wnd = ring_buffer_free(tsk->rcv_buf);
			tsk->rcv_nxt = pkt->seq_end;
			// printf("handle_payload: current->rcv_nxt = %u\n", tsk->rcv_nxt);
			list_delete_entry(&pkt->list);
		} else break;
	}
	pthread_mutex_unlock(&tsk->rcv_buf->lock);
	// printf("handle_payload: rcv_nxt = %u\n", tsk->rcv_nxt);
}

// update the snd_wnd of tcp_sock
//
// if the snd_wnd before updating is zero, notify tcp_sock_send (wait_send)
static inline void tcp_update_window(struct tcp_sock *tsk, struct tcp_cb *cb)
{
	tsk->snd_wnd = (int) cb->rwnd - (int) (tsk->snd_nxt - tsk->snd_una);
	wake_up(tsk->wait_send);
}

// update the snd_wnd safely: cb->ack should be between snd_una and snd_nxt
static inline void tcp_update_window_safe(struct tcp_sock *tsk, struct tcp_cb *cb)
{
	if (less_or_equal_32b(tsk->snd_una, cb->ack) && less_or_equal_32b(cb->ack, tsk->snd_nxt))
		tcp_update_window(tsk, cb);
}

#ifndef max
#	define max(x,y) ((x)>(y) ? (x) : (y))
#endif

// check whether the sequence number of the incoming packet is in the receiving
// window
static inline int is_tcp_seq_valid(struct tcp_sock *tsk, struct tcp_cb *cb)
{
	u32 rcv_end = tsk->rcv_nxt + max(tsk->rcv_wnd, 1);
	if (less_than_32b(cb->seq, rcv_end) && less_or_equal_32b(tsk->rcv_nxt, cb->seq_end)) {
		return 1;
	}
	else {
		// log(ERROR, "received packet with invalid seq, cb->seq=%u, tsk->rcv_nxt=%u", cb->seq,tsk->rcv_nxt);
		return 0;
	}
}

// Process the incoming packet according to TCP state machine. 
void tcp_process(struct tcp_sock *tsk, struct tcp_cb *cb, char *packet)
{
	// fprintf(stdout, "TODO: implement %s please.\n", __FUNCTION__);
	// printf("receive a packet, in tcp_process, flag = %d\n", cb->flags);
	if(tsk->state != TCP_LISTEN && tsk->state != TCP_SYN_RECV && tsk->state != TCP_SYN_SENT \
	&& !is_tcp_seq_valid(tsk,cb)){
		return;
	}
	if(cb->flags & TCP_RST){
		tcp_set_state(tsk,TCP_CLOSED);
		return;
	}

	//set rcv_nxt,(snd_wnd,snd_una)
	//if not parent sock: set those variables here
	//else set those variables later 
	//because parent sock needs set its child's variables
	if(tsk->state!=TCP_LISTEN){
		if(cb->flags & TCP_ACK){
			tsk->snd_una = cb->ack;
			tcp_update_window_safe(tsk,cb);
			// printf("before check send buf\n");
			tcp_check_send_buf(tsk, cb);
			// printf("finish check send buf\n");
		}
	}

	if(tsk->state == TCP_LISTEN){
		if(cb->flags & TCP_SYN){
			// printf("LISTEN receive SYN\n");
			struct tcp_sock *new_tsk = alloc_tcp_sock();
			new_tsk->parent = tsk;
			list_add_tail(&new_tsk->list, &new_tsk->parent->accept_queue);

			new_tsk->sk_dip = cb->saddr;
			new_tsk->sk_dport = cb->sport;
			new_tsk->sk_sip = cb->daddr;
			new_tsk->sk_sport = cb->dport;

			new_tsk->rcv_nxt = cb->seq_end;
			// new_tsk->snd_nxt = tcp_new_iss();
			// new_tsk->snd_una = new_tsk->snd_nxt;
	
			tcp_set_state(new_tsk,TCP_SYN_RECV);
			//do not hash to bind table as it using the same port as its parent
			//hash to establish table as its quadruple has been decided
			tcp_hash(new_tsk);
			tcp_send_control_packet(new_tsk,TCP_SYN | TCP_ACK);
		}
	}else if(tsk->state == TCP_SYN_SENT){
		if((cb->flags & TCP_ACK) && (cb->flags & TCP_SYN)){
			tsk->rcv_nxt = cb->seq_end;
			tcp_set_state(tsk,TCP_ESTABLISHED);
			tcp_send_control_packet(tsk,TCP_ACK);
			wake_up(tsk->wait_connect);
		}
	}else if(tsk->state == TCP_SYN_RECV){
		if(cb->flags & TCP_ACK){
			tcp_set_state(tsk,TCP_ESTABLISHED);
			tcp_sock_accept_enqueue(tsk);
			wake_up(tsk->parent->wait_accept);
		}
	}else if(tsk->state == TCP_FIN_WAIT_1){
		//maybe only ACK, maybe ACK|FIN
		if(cb->flags & TCP_ACK){
			// if(tsk->snd_una == tsk->snd_nxt)
				tcp_set_state(tsk,TCP_FIN_WAIT_2);
		}
		if(cb->flags & TCP_FIN){
			tcp_set_state(tsk,TCP_TIME_WAIT);
			tcp_send_control_packet(tsk,TCP_ACK);
			tcp_set_timewait_timer(tsk);
			wake_up(tsk->wait_recv);
		}
	}else if(tsk->state == TCP_FIN_WAIT_2){
		if(cb->flags & TCP_FIN){
			tcp_set_state(tsk,TCP_TIME_WAIT);
			tcp_send_control_packet(tsk,TCP_ACK);
			tcp_set_timewait_timer(tsk);
			wake_up(tsk->wait_recv);
		}
	}else if(tsk->state == TCP_LAST_ACK){
		if(cb->flags & TCP_ACK){
			// if(tsk->snd_una == tsk->snd_nxt)
			tcp_unhash(tsk);
			tcp_bind_unhash(tsk);
			tcp_set_state(tsk, TCP_CLOSED);
		}
	}else if(tsk->state == TCP_ESTABLISHED){
		if(cb->flags & TCP_FIN){
			tcp_set_state(tsk,TCP_CLOSE_WAIT);
			tcp_send_control_packet(tsk,TCP_ACK);
			wake_up(tsk->wait_recv);
			//wait for recv rest data
			//wake_up(tsk->wait_recv);

			// pthread_mutex_lock(&tsk->rcv_buf->lock);
			// if(ring_buffer_empty(tsk->rcv_buf) == 0){
			// 	pthread_mutex_unlock(&tsk->rcv_buf->lock);
			// 	sleep_on(tsk->wait_recv);
			// 	pthread_mutex_lock(&tsk->rcv_buf->lock);
			// }
			// pthread_mutex_unlock(&tsk->rcv_buf->lock);
			// //if no rest data need to recv
			// tcp_sock_close(tsk);
		}
	}
	if(cb->pl_len > 0){
		handle_payload(tsk, cb);
		tcp_send_control_packet(tsk, TCP_ACK);
		wake_up(tsk->wait_recv);
	}
}
