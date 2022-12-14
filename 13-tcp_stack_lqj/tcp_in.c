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
	//u16 old_snd_wnd = tsk->snd_wnd;
	// pthread_mutex_lock(&tsk->rcv_buf->lock);
	tsk->snd_wnd = cb->rwnd - (tsk->snd_nxt-tsk->snd_una);
	// printf("update get lock, tsk->snd_wnd = %d\n", tsk->snd_wnd);
	// pthread_mutex_unlock(&tsk->rcv_buf->lock);
	// printf("update unlock\n");
	//if (old_snd_wnd == 0)
	wake_up(tsk->wait_send);
	//tsk->snd_wnd = cb->rwnd - (tsk->snd_nxt - tsk->snd_una);
	//wake_up(tsk->wait_send);
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
		log(ERROR, "received packet with invalid seq, drop it.");
		return 0;
	}
}

// Process the incoming packet according to TCP state machine. 
void tcp_process(struct tcp_sock *tsk, struct tcp_cb *cb, char *packet)
{
	// fprintf(stdout, "TODO: implement %s please.\n", __FUNCTION__);
	// printf("in tcp_process\n");
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
		tsk->rcv_nxt = cb->seq_end;
		if(cb->flags & TCP_ACK){
			tsk->snd_una = cb->ack;
			tcp_update_window_safe(tsk,cb);
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
	// printf("cb->pl_len = %d\n", cb->pl_len);
	if(cb->pl_len>0){
			pthread_mutex_lock(&tsk->rcv_buf->lock);

			write_ring_buffer(tsk->rcv_buf,cb->payload,cb->pl_len);
			tsk->rcv_wnd = ring_buffer_free(tsk->rcv_buf);
			// printf("send ask: rcv_wnd = %d\n",tsk->rcv_wnd);
			pthread_mutex_unlock(&tsk->rcv_buf->lock);

			tcp_send_control_packet(tsk,TCP_ACK);
			wake_up(tsk->wait_recv);
	}


}
