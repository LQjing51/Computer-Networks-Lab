#include "tree.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct treeAd
{
    struct treeAd* children[4];//00 01 10 11
    int16_t matchNumber;
    int8_t port;
    uint8_t matchBits;
}TreeNodeAd;

TreeNodeAd* root_ad;
static long long mem_use = 0;
static char* mymalloc(int size) {
    mem_use += size;
    return malloc(size);
}
static TreeNodeAd* build_and_assign(int8_t port) {
    TreeNodeAd* newNode = (TreeNodeAd*)mymalloc(sizeof(TreeNodeAd));
    newNode->port = port;
    newNode->matchBits = 2;
    memset(newNode->children, 0, 4*sizeof(TreeNodeAd*));
    return newNode;
}
static void addToTree_advance(uint32_t ip, int mask, int8_t port) {
    TreeNodeAd* currentNode = root_ad;
    int flag = mask & 1;
    while(mask > 0) {
        int8_t TwoBits = ip>>30;
        int8_t couple = TwoBits^1;
        if (currentNode->children[TwoBits]){
            if (mask == 1) {
                if (!currentNode->children[couple])
                    currentNode->children[couple] = build_and_assign(port);
                else if (currentNode->children[couple]->port == -1)
                    currentNode->children[couple]->port = port;
            }
            currentNode = currentNode->children[TwoBits];
        }else{
            TreeNodeAd* newNode = (TreeNodeAd*)mymalloc(sizeof(TreeNodeAd));
            newNode->port = -1;
            newNode->matchBits = 2;
            memset(newNode->children, 0, 4*sizeof(TreeNodeAd*));
            if (mask == 1) {
                if (!currentNode->children[couple])
                    currentNode->children[couple] = build_and_assign(port);
                else if (currentNode->children[couple]->port == -1)
                    currentNode->children[couple]->port = port;
            }
            currentNode->children[TwoBits] = newNode;
            currentNode = newNode;
        }
        mask -= 2;
        ip = ip << 2;
    }
   if (!flag || currentNode->port == -1)
        currentNode->port = port;
}
static int checkNonChildren(TreeNodeAd* currentNode) {
    for (int i = 0; i < 4; i++) {
        if (currentNode->children[i]) return 0;
    }
    return 1;
}
static int countInnerChildren(TreeNodeAd* currentNode) {
    int count = 0;
    int child = -1;
    for (int i = 0; i < 4; i++) {
        if (currentNode->children[i]) {
            count++;
            child = i; 
        } 
        if (count > 1) return -1;
    }
    if (!count) return -1; 
    if (currentNode->children[child]->port == -1) return child;
    else return -1;
}
static int countMatchChildren(TreeNodeAd* currentNode) {
    int count = 0;
    int child = -1;
    for (int i = 0; i < 4; i++) {
        if (currentNode->children[i]) {
            count++;
            child = i; 
        } 
        if (count > 1) return -1;
    }
    if (!count) return -1; 
    if (currentNode->children[child]->port != -1) return child;
    else return -1;
}
static void arrAppend(char* pos,int num){
    switch(num){
        case 0:
            *pos = '0';*(pos+1) = '0';
            break;
        case 1:
            *pos = '0';*(pos+1) = '1';
            break;
        case 2:
            *pos = '1';*(pos+1) = '0';
            break;
        case 3:
            *pos = '1';*(pos+1) = '1';
            break;
    }       
}
static int ToInt(char* arr) {
    int res = 0;
    for (int i = 0; i < strlen(arr);i++){
        res*=2;
        res+= arr[i] - '0';
    }
    return res;
}
static void path_aggregation(TreeNodeAd* currentNode) {
    if (checkNonChildren(currentNode)){
        return;
    }
    TreeNodeAd* pre = currentNode;
    int child = countInnerChildren(currentNode);
    int match = 0, matchChild = 0;
    int firstChild = -1;
    char* matchArr = malloc(30);
    int arrIndex = 0;
    while (child != -1) {
        if (firstChild == -1) firstChild = child;
        match++;
        arrAppend(matchArr+arrIndex,child);
        arrIndex+=2;
        currentNode = currentNode->children[child];
        child = countInnerChildren(currentNode);
    }
    // last inner node has only one match node
    matchChild = countMatchChildren(currentNode);
    if (matchChild != -1) {
        match++;
        arrAppend(matchArr+arrIndex,matchChild);
        arrIndex+=2;
        currentNode = currentNode->children[matchChild];
    }
    matchArr[arrIndex] = 0;
    if (match >= 2) {
        pre->children[firstChild] = currentNode;
        currentNode->matchBits = 2*match;
        currentNode->matchNumber = ToInt(matchArr);
        path_aggregation(currentNode);
    }else {
        for (int i = 0; i < 4; i++) {
            if(pre->children[i]) path_aggregation(pre->children[i]);
        }
    }
}
// Constructing an advanced trie-tree to lookup according to `forwardingtable_filename`
void create_tree_advance_2bit_compress(const char* forward_file){
    FILE* fp = fopen(forward_file,"r");
    char* ipLine = malloc(16);
    if(NULL == fp){
        perror("Open forward file fails");
        exit(1);
    }
    uint32_t ip = 0; 
    int mask = 0;
    int port = 0;
    int ret = fscanf(fp,"%s%d%d",ipLine,&mask,&port);
    uint8_t tmp = 0;
    root_ad = (TreeNodeAd*)mymalloc(sizeof(TreeNodeAd));
    memset(root_ad->children, 0, 4*sizeof(TreeNodeAd*));
    root_ad->port = -1;
    root_ad->matchBits = 0;
    while(ret != -1){
	    ip = 0;
        int len = strlen(ipLine);
        for (int j = 0; j < len; j++) {
            if (ipLine[j] == '.') {
                ip = ip << 8;
                ip += tmp;
                tmp = 0;
            }else {
                tmp *= 10;
                tmp += ipLine[j]-'0';
            }
            if (j == len-1) {
                ip = ip << 8;
                ip += tmp;
		        tmp = 0;
            }
        }
        addToTree_advance(ip,mask,port);
        ret = fscanf(fp,"%s%d%d",ipLine,&mask,&port);
    }
    path_aggregation(root_ad);
    printf("compress mem use = %I64d\n",mem_use);  
    fclose(fp);
}
static uint32_t lookUp_advance(uint32_t ip) {
    TreeNodeAd* currentNode = root_ad;
    uint32_t lastMatch = -1;
    while(1) {
        if (~currentNode->port) {
            lastMatch = currentNode->port; 
        }
        uint8_t TwoBits = ip>>30;
        uint8_t matchNum = 0; 
        if (currentNode->children[TwoBits]){
             currentNode = currentNode->children[TwoBits];
            matchNum = currentNode->matchBits;
            if (!(matchNum ^ 2)) {
                ip = ip << 2;
                continue;
            }
            if ((ip>>(32-matchNum)) ^ currentNode->matchNumber) return lastMatch;
        }else{
            return lastMatch;
        }
        ip = ip << matchNum;
    }
    return lastMatch;
}
// Look up the ports of ip in file `lookup_file` using the advanced tree
uint32_t *lookup_tree_advance_2bit_compress(uint32_t* ip_vec){
    uint32_t* res = malloc(sizeof(uint32_t)*TEST_SIZE);
    uint32_t ip;
    for(int i = 0;i < TEST_SIZE;i++){
        ip = ip_vec[i]; 
        uint32_t port = lookUp_advance(ip);   
        res[i] = port;
    }
    return res;
}


