#include "base.h"
#include <stdio.h>

extern ustack_t *instance;

void broadcast_packet(iface_info_t *iface, const char *packet, int len)
{
	// TODO: broadcast packet
	//fprintf(stdout, "TODO: broadcast packet.\n");
	iface_info_t *otherIface = NULL;
	list_for_each_entry(otherIface, &instance->iface_list, list) {
		if (otherIface-> fd != iface->fd)
			iface_send_packet(otherIface, packet, len);
	}

}
