#include "tree.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

int rt, num;
Node      a[MAX_NODE * 32];
int rt_ad, num_ad;
Node_ad_2 b[MAX_NODE * 16];

uint32_t str2ip(char *str) {
    int len = strlen(str);
    uint32_t sum = 0, tmp = 0;
    for (int j = 0; j < len; j++) {
        if (!isdigit(str[j])) {
            sum = (sum << 8) + tmp;
            tmp = 0;
        } else {
            tmp = tmp * 10 + str[j] - '0';
        }
    }
    sum = (sum << 8) + tmp;
    // do reversing
    uint32_t ret = 0;
    for (int i = 31; i >= 0; i--, sum >>= 1)
        ret = (ret << 1) + (sum & 1);
    return ret;
}

////////////////////////////////

void ins(int x, uint32_t val, int len, int port) {
    if (!len) {
        if (~a[x].port && a[x].port != port) {
            fprintf(stderr, "ERROR: conflict entries.");
            return;
        }
        a[x].port = port;
        return;
    }
    int nx = val & 1;
    if (!a[x].nxt[nx]) a[x].nxt[nx] = ++num, a[num].port = -1;
    ins(a[x].nxt[nx], val >> 1, len - 1, port);
}

int find(int x, uint32_t val) {
    if (!x) return -1;
    int tmp = find(a[x].nxt[val & 1], val >> 1);
    if (~tmp) return tmp;
    return a[x].port;
}

/***** ADVACE *****/

void ins_ad(int x, uint32_t val, int len, int port) {
    if (len <= 0) {
        if (~b[x].port) {
            if (!len) b[x].port = port;
        } else b[x].port = port;
        return;
    }
    int nx = val & 3;
    if (!b[x].nxt[nx]) b[x].nxt[nx] = ++num_ad, b[num_ad].port = -1;
    ins_ad(b[x].nxt[nx], val >> 2, len - 2, port);
    if (len == 1) {
        nx ^= 2;
        if (!b[x].nxt[nx]) b[x].nxt[nx] = ++num_ad, b[num_ad].port = -1;
        ins_ad(b[x].nxt[nx], val >> 2, len - 2, port);
    }
}
int find_ad(int x, uint32_t val) {
    if (!x) return -1;
    int tmp = find_ad(b[x].nxt[val & 3], val >> 2);
    if (~tmp) return tmp;
    return b[x].port;
}
int find_ad_no_rc(int x, uint32_t val) {
	int ans = -1;
	while (x) {
		if (~b[x].port) ans = b[x].port;
		x = b[x].nxt[val & 3];
		val >>= 2;
    }
	return ans;
}

/***** Compression *****/

void ins_ad_2(int x, uint32_t val, int len, int port) {
    if (len <= 0) {
        if (~b[x].port) {
            if (!len) b[x].port = port;
        } else b[x].port = port;
        return;
    }
    int nx = val & 3;
    if (!b[x].nxt[nx]) b[x].nxt[nx] = ++num_ad, b[x].val[nx] = nx, b[x].len[nx] = 2, b[num_ad].port = -1;
    ins_ad_2(b[x].nxt[nx], val >> 2, len - 2, port);
    if (len == 1) {
        nx ^= 2;
        if (!b[x].nxt[nx]) b[x].nxt[nx] = ++num_ad, b[x].val[nx] = nx, b[x].len[nx] = 2, b[num_ad].port = -1;
        ins_ad_2(b[x].nxt[nx], val >> 2, len - 2, port);
    }
}
Tri do_compression(int x) {
    Tri res[4];
    int count = 0, lst = 0;
    for (int nx = 0; nx < 4; nx++) {
        if (b[x].nxt[nx]) {
            res[nx] = do_compression(b[x].nxt[nx]);
            lst = nx;
            count++;
        }
    }
    Tri tmp;
    tmp.x = x; tmp.val = 0; tmp.len = 2;
    switch (count) {
        case (0):
            break;
        case (1):
            if (b[x].port == -1 && res[lst].x) {
                // merge
                tmp.x = res[lst].x; tmp.val = (res[lst].val << 2) + lst; tmp.len = res[len] + 2;
            }
            break;
        default:
            // handle compression
            for (int nx = 0; nx < 4; nx++) {
                if (b[x].nxt[nx] && res[nx].x && res[nx].len > 2) {
                    // do compression
                    b[x].nxt[nx] = res[nx].x;
                    b[x].val[nx] = (res[nx].val << 2) + nx;
                    b[x].len[nx] = res[nx].len;
                }
            }
    }
    return tmp;
}

int find_ad_2(int x, uint32_t val) {
    uint32_t nx = val & 3;
    if (b[x].nxt[nx] && !(b[x].val[nx] ^ (val & ((1 << b[x].len[nx]) - 1)))) {
        int tmp = find_ad_2(b[x].nxt[nx], val >> b[x].len[nx]);
        if (~tmp) return tmp;
    }
    return b[x].port;
}

// return an array of ip represented by an unsigned integer, size is TEST_SIZE
uint32_t* read_test_data(const char* lookup_file){
    uint32_t *ip_vec = (uint32_t *) malloc(TEST_SIZE * sizeof(uint32_t));
    char str[30];
    FILE *f = fopen(lookup_file, "r");
    if (!f) return NULL;
    for (int i = 0; i < TEST_SIZE; i++) {
        fscanf(f, "%s", str);
        ip_vec[i] = str2ip(str);
    }
    return ip_vec;
}

// Constructing an advanced trie-tree to lookup according to `forward_file`
void create_tree(const char* forward_file){
    char str[30];
    int length, port;
    FILE *f = fopen(forward_file, "r");
    if (!f) return;
    rt = num = 1; a[rt].port = -1;
    while (~fscanf(f, "%s%d%d", str, &length, &port)) {
        uint32_t ip = str2ip(str);
        ins(rt, ip, length, port);
    }
}

// Look up the ports of ip in file `lookup_file` using the basic tree
uint32_t *lookup_tree(uint32_t* ip_vec){
    uint32_t *port_vec = (uint32_t *) malloc(TEST_SIZE * sizeof(uint32_t));
    for (int i = 0; i < TEST_SIZE; i++) {
        port_vec[i] = find(rt, ip_vec[i]);
    }
    return port_vec;
}

// Constructing an advanced trie-tree to lookup according to `forwardingtable_filename`
void create_tree_advance(const char* forward_file){
    char str[30];
    int length, port;
    FILE *f = fopen(forward_file, "r");
    if (!f) return;
    rt_ad = num_ad = 1; b[rt_ad].port = -1;
    while (~fscanf(f, "%s", str)) {
        uint32_t ip = str2ip(str);
        fscanf(f, "%d%d", &length, &port);
        // ins_ad(rt_ad, ip, length, port);
        int remain = length % 8;
        int delta = !remain ? 0 : 8 - remain;
        for (int i = 0; i < (1 << delta); i++) {
            uint32_t new = (ip & ((1 << length) - 1)) | (i << length);
            ins_ad_2(rt, length + delta, port, 8 - delta);
        }
    }
    do_compress(rt);
}

// Look up the ports of ip in file `lookup_file` using the advanced tree
uint32_t *lookup_tree_advance(uint32_t* ip_vec){
    uint32_t *port_vec = (uint32_t *) malloc(TEST_SIZE * sizeof(uint32_t));
    for (int i = 0; i < TEST_SIZE; i++) {
        port_vec[i] = find_ad_2(rt_ad, ip_vec[i]);
    }
    return port_vec;
}

