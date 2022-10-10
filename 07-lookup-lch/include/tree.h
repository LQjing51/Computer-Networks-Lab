#ifndef __TREE_H__
#define __TREE_H__

#include <stdint.h>
#include <stdio.h>

// do not change it
#define TEST_SIZE 100000
#define MAX_NODE 700000

typedef struct {
    int port;
    int nxt[2];
} Node;

typedef struct {
    int port;
    int nxt[4];
} Node_ad;

typedef struct {
    int port;
    int len[4], val[4];   //path compression
    int nxt[4];
} Node_ad_2;

typedef struct {
    int x;
    int len, val;
} Tri;

void create_tree(const char*);
uint32_t *lookup_tree(uint32_t *);
void create_tree_advance();
uint32_t *lookup_tree_advance(uint32_t *);

uint32_t* read_test_data(const char* lookup_file);

#endif
