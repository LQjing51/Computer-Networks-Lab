#include "tree.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef struct tree
{
    int port;
    struct tree* right;
    struct tree* left;
}TreeNode;
TreeNode* root;
// return an array of ip represented by an unsigned integer, size is TEST_SIZE
uint32_t* read_test_data(const char* lookup_file){
    char* ip = malloc(16);
    uint32_t* res = malloc(sizeof(uint32_t)*TEST_SIZE);
    FILE* fp = fopen(lookup_file,"r");

    if(NULL == fp){
        perror("Open lookup file fails");
        exit(1);
    }
    for(int i = 0; i < TEST_SIZE; i++){
        fscanf(fp,"%s",ip);
        uint32_t IptoBi = 0;
        uint8_t tmp = 0;
        int len = strlen(ip);
        for (int j = 0; j < len; j++) {
            if (ip[j] == '.') {
                IptoBi = IptoBi << 8;
                IptoBi += tmp;
                tmp = 0;
            }else {
                tmp *= 10;
                tmp += ip[j]-'0';
            }
            if (j == len-1) {
                IptoBi = IptoBi << 8;
                IptoBi += tmp;
            }
        }
        res[i] =  IptoBi;
    }
    fclose(fp);
    return res;
}
void addToTree(uint32_t ip, int mask, int port) {
    TreeNode* currentNode = root;
    while(mask) {
        if ((ip & (1u<<31)) && currentNode->right){
            currentNode = currentNode->right;
        }else if (!(ip & (1u<<31)) && currentNode->left){
            currentNode = currentNode->left;
        }else if (ip & (1u<<31)) {
            TreeNode* newNode = malloc(sizeof(TreeNode));
            newNode->port = -1;
            newNode->right = NULL;
            newNode->left = NULL;
            currentNode->right = newNode;
            currentNode = newNode;
        }else {
            TreeNode* newNode = malloc(sizeof(TreeNode));
            newNode->port = -1;
            newNode->right = NULL;
            newNode->left = NULL;
            currentNode->left = newNode;
            currentNode = newNode;
        }
        mask--;
        ip = ip << 1;
    }
    currentNode->port = port;
}
// Constructing an advanced trie-tree to lookup according to `forward_file`
void create_tree(const char* forward_file){
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
    root = malloc(sizeof(TreeNode));
    root->right = NULL;
    root->left = NULL;
    root->port = -1;
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
        addToTree(ip,mask,port);
        ret = fscanf(fp,"%s%d%d",ipLine,&mask,&port);
    }  
    fclose(fp);
}
uint32_t lookUp(uint32_t ip) {
    TreeNode* currentNode = root;
    uint32_t lastMatch = -1;
    while(1) {
        if (currentNode->port != -1) {
            lastMatch = currentNode->port; 
        }
        if ((ip & (1u<<31)) && currentNode->right){
            currentNode = currentNode->right;
        }else if (!(ip & (1u<<31)) && currentNode->left){
            currentNode = currentNode->left;
        }else{
            return lastMatch;
        }
        ip = ip << 1;
    }
    return lastMatch;
}
// Look up the ports of ip in file `lookup_file` using the basic tree
uint32_t *lookup_tree(uint32_t* ip_vec){
    uint32_t* res = malloc(sizeof(uint32_t)*TEST_SIZE);
    uint32_t ip;
    for(int i = 0;i < TEST_SIZE;i++){
        ip = ip_vec[i]; 
        uint32_t port = lookUp(ip);   
        res[i] = port;
    }
    return res;
}

// Constructing an advanced trie-tree to lookup according to `forwardingtable_filename`
void create_tree_advance(const char* forward_file){

}

// Look up the ports of ip in file `lookup_file` using the advanced tree
uint32_t *lookup_tree_advance(uint32_t* ip_vec){
    uint32_t* res = malloc(sizeof(uint32_t)*TEST_SIZE);
    return res;
}


