#include "tree.h"
#include <stdio.h>
#include <stdlib.h>

int rt;
Node    a[MAX_NODE];
int rt_ad;
Node_ad b[MAX_NODE];

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

void ins(int &x, uint32_t val, int len, int port) {
    if (!x) x = ++num, a[x].port = -1;
    if (!len) {
        if (~a[x].port && a[x].port != port) {
            fprintf(stderr, "ERROR: conflict entries.");
            return;
        }
        a[x].port = port;
        return;
    }
    ins(a[x].nxt[val & 1], val >>= 1, len - 1, port);
}

int find(int x, uint32_t val) {
    if (!x) return -1;
    int tmp = find(a[x].nxt[val & 1], val >>= 2);
    if (~tmp) return tmp;
    return a[x].port;
}

void ins_ad(int &x, uint32_t val, int len, int port) {
    if (!x) x = ++num, a[x].port = -1;
    if (len <= 0) {
        if (~a[x].port) {
            if (!len) a[x].port = port;
        } else a[x].port = port;
        return;
    }
    ins_ad(a[x].nxt[val & 3], val >>= 2, len - 2, port);
}
int find_ad(int x, uint32_t val) {
    if (!x) return -1;
    int tmp = find(a[x].nxt[val & 3], val >>= 2);
    if (~tmp) return tmp;
    return a[x].port;
}

// return an array of ip represented by an unsigned integer, size is TEST_SIZE
uint32_t* read_test_data(const char* lookup_file){
    uint32_t ip_vec = (uint32_t *) malloc(TEST_SIZE * sizeof(uint32_t));
    char str[30];
    FILE *f = fopen(lookup_file, "r");
    if (!f) return NULL;
    for (int i = 0; i < TEST_SIZE; i++) {
        fscanf(f, "%s", str);
        ip_vec[i] = str2ip(str);
    }
    return NULL;
}

// Constructing an advanced trie-tree to lookup according to `forward_file`
void create_tree(const char* forward_file){
    char str[30];
    int length, port;
    FILE *f = fopen(forward_file, "r");
    if (!f) return;
    while (~fscanf(f, "%s", str)) {
        uint32_t ip = str2ip(str);
        fscanf(f, "%d%d", &length, &port);
        ins(rt, ip, length, port);
    }
}

// Look up the ports of ip in file `lookup_file` using the basic tree
uint32_t *lookup_tree(uint32_t* ip_vec){
    uint32_t port_vec = (uint32_t *) malloc(TEST_SIZE * sizeof(uint32_t));
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
    while (~fscanf(f, "%s", str)) {
        uint32_t ip = str2ip(str);
        fscanf(f, "%d%d", &length, &port);
        ins_ad(rt_ad, ip, length, port);
    }
}

// Look up the ports of ip in file `lookup_file` using the advanced tree
uint32_t *lookup_tree_advance(uint32_t* ip_vec){
    uint32_t port_vec = (uint32_t *) malloc(TEST_SIZE * sizeof(uint32_t));
    for (int i = 0; i < TEST_SIZE; i++) {
        port_vec[i] = find_ad(rt_ad, ip_vec[i]);
    }
    return port_vec;
}


