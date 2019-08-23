#include <errno.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "rb_tree.h"

#define CUST_MODE 0
#define TRAF_MODE 1

#define CUSTID_SIZE 100
#define MAX_CUST_SIZE (45 + CUSTID_SIZE) // ipv6 max ascii len (39 bytes) + mask(3 bytes) + space + custId (100bytes) + newline + trailing NULL
#define MAX_TRAF_SIZE 61 // ipv6 max ascii len (39 bytes) + space + 2^64 takes 19 digits? + newline + trailing NULL

struct net {
	unsigned long int trafCount;
	unsigned int netMask;
	unsigned char *baseAddr;
	unsigned char *maxAddr;
	unsigned char *ID;
};

struct st {
	struct net *n;
	struct st *next;
} *stack = NULL;

int parseLine (unsigned char *l, unsigned int maxLineLen, struct net *new);

// starting from 8 till 32
unsigned int masks[] = {
	4278190080,
	4286578688,
	4290772992,
	4292870144,
	4293918720,
	4294443008,
	4294705152,
	4294836224,
	4294901760,
	4294934528,
	4294950912,
	4294959104,
	4294963200,
	4294965248,
	4294966272,
	4294966784,
	4294967040,
	4294967168,
	4294967232,
	4294967264,
	4294967280,
	4294967288,
	4294967292,
	4294967294,
	4294967291
};

int compareCb (struct rb_tree *self, struct rb_node *existingNode, struct rb_node *newNode, unsigned char mode) {
	int cmpRes = 0;
	unsigned int tmpNetMask = 0;
	unsigned char *tmpBaseAddr;
	unsigned char *tmpID;

	struct st *tmpStack;
	struct net *reInsert;
	struct net *ex = (struct net*) existingNode->value;
	struct net *new = (struct net*) newNode->value;
	unsigned int existingBase = *((unsigned int*) ex->baseAddr);
	unsigned int newBase = *((unsigned int*) new->baseAddr);
	unsigned int existingMax = *((unsigned int*) ex->maxAddr);
	unsigned int newMax = *((unsigned int*) new->maxAddr);

	cmpRes = (existingBase > newBase) - (existingBase < newBase);
	if (0 == mode) {
		tmpNetMask = ex->netMask;
		if (ex->netMask > new->netMask) tmpNetMask = new->netMask;
		if ( (existingBase & masks[tmpNetMask-8]) == (newBase & masks[tmpNetMask-8]) ) { // check that network is a sub-network of other
//1) 10.5.100.64/26 is there and 10.5.100.0/24 is new (smaller mask is being inserted) = update maxAddr of lower part of new and insert it as is and plan to insert upper part next
			if ( (existingBase > newBase) && (existingMax < newMax) ) { // check that borders differ
				reInsert = (struct net*) calloc(1, sizeof(struct net));
				reInsert->ID = new->ID;
				reInsert->netMask = new->netMask;
				reInsert->maxAddr = new->maxAddr;
				new->maxAddr = (unsigned char*) calloc(1, 4);
				memcpy(new->maxAddr, ex->baseAddr, 4);
				new->maxAddr[0]--;
				reInsert->baseAddr = (unsigned char*) calloc(1, 4);
				memcpy(reInsert->baseAddr, ex->maxAddr, 4);
				reInsert->baseAddr[0]++;
				existingBase = *((unsigned int*) ex->baseAddr);
				newBase = *((unsigned int*) new->baseAddr);

				// push to stack to insert as "another" network
				tmpStack = (struct st*) malloc(sizeof(struct st));
				tmpStack->n = reInsert;
				tmpStack->next = stack;
				stack = tmpStack;
			}

//2) 10.5.100.0 is there and 10.5.100.64 is new (bigger mask is being inserted) = update maxAddr of 10.5.100.0 to keep lower part, plan to insert upper part next and insert 10.5.100.64 as is
			else if ( (existingBase < newBase) && (existingMax > newMax) ) { // check that borders differ
				reInsert = (struct net*) calloc(1, sizeof(struct net));
				reInsert->ID = new->ID;
				reInsert->netMask = new->netMask;
				reInsert->maxAddr = ex->maxAddr;
				ex->maxAddr = (unsigned char*) calloc(1, 4);
				memcpy(ex->maxAddr, new->baseAddr, 4);
				ex->maxAddr[0]--;
				reInsert->baseAddr = (unsigned char*) calloc(1, 4);
				memcpy(reInsert->baseAddr, ex->maxAddr, 4);
				reInsert->baseAddr[0]++;

				// push to stack to insert as "another" network
				tmpStack = (struct st*) malloc(sizeof(struct st));
				tmpStack->n = reInsert;
				tmpStack->next = stack;
				stack = tmpStack;
			}
			else if ((existingBase == newBase) && (existingMax != newMax)) {
				// one net takes lower part of other
//1) /28 is there and /24 is new (smaller mask is being inserted) = keep lower part as is and plan to insert upper part with updated baseAddr
				if (new->netMask < ex->netMask) {
					reInsert = new;
					memcpy(reInsert->baseAddr, ex->maxAddr, 4);
					reInsert->baseAddr[0]++;
					// push to stack to insert as "another" network
					tmpStack = (struct st*) malloc(sizeof(struct st));
					tmpStack->n = reInsert;
					tmpStack->next = stack;
					stack = tmpStack;
				}

//1) /24 is there and /28 is new (bigger mask is being inserted) = swap existing /24 with /28 to keep lower part, update maxAddr of existing and baseAddr of new and plan to insert upper part next
				else if (new->netMask > ex->netMask) {
					reInsert = ex;
					ex = new;
					memcpy(reInsert->baseAddr, ex->maxAddr, 4);
					reInsert->baseAddr[0]++;
					// push to stack to insert as "another" network
					tmpStack = (struct st*) malloc(sizeof(struct st));
					tmpStack->n = reInsert;
					tmpStack->next = stack;
					stack = tmpStack;
				}
				else {
					printf("IMPOSSIBLE(?) situation 2\n");
					return 0;
				}
			}
			else if ((existingBase != newBase) && (existingMax == newMax)) {
				// one net takes upper part of other
//1) /27 is there and /24 is new (smaller mask is being inserted) = update maxAddr of /24 to /27's baseAddr-1 and proceed
				if (new->netMask < ex->netMask) {
					memcpy(new->maxAddr, ex->baseAddr, 4);
					new->maxAddr[0]--;
				}

//1) /24 is there and /27 is new (bigger mask is being inserted) = update maxAddr of /24 to /27's baseAddr-1 and proceed
				else if (new->netMask > ex->netMask) {
					memcpy(new->maxAddr, ex->baseAddr, 4);
					new->maxAddr[0]--;
				}
				else {
					printf("IMPOSSIBLE(?) situation 3\n");
					return 0;
				}
			}
			else if ( (existingBase == newBase) && (existingMax == newMax) ) {
				if (new->netMask > ex->netMask) {
					// subnet of existing upnet that was splitted before due to another subnet
					ex->netMask = new->netMask;
					unsigned char *tmp = ex->ID;
					ex->ID = new->ID;
					new->ID = tmp;
				}
			}
		}
		existingBase = *((unsigned int*) ex->baseAddr);
		newBase = *((unsigned int*) new->baseAddr);
		cmpRes = (existingBase > newBase) - (existingBase < newBase);
	}
	else {
		if ( (existingBase & masks[ex->netMask-8]) == (newBase & masks[ex->netMask-8]) ) {
			ex->trafCount += new->trafCount;
			cmpRes = 0;
		}
	}
	return cmpRes;
}

/*
INSERT
10.5.100.64/26 splits 10.5.100.0/24 into two 0-63 and 128-255
take the lower mask of the two to 
get network part of both addresses, 
if match:
a) if both baseAddr and maxAddr don't match (one net is somewhere inside of another):
1) 10.5.100.64 is there and 10.5.100.0 is new (smaller mask is being inserted) = insert lower part of 10.5.100.0 as is and plan to insert upper part next
2) 10.5.100.0 is there and 10.5.100.64 is new (bigger mask is being inserted) = update maxAddr of 10.5.100.0 to keep lower part, plan to insert upper part next and insert 10.5.100.64 as is

10.5.100.0/28 takes 0-15 from 10.5.100.0/24 and leaves 16-255 (lower part)
take the lower mask of the two to get network part of both addresses, if match:
b) baseAddrs match here (lower part split)
1) /28 is there and /24 is new (smaller mask is being inserted) = keep lower part as is and plan to insert upper part with updated baseAddr
1) /24 is there and /28 is new (bigger mask is being inserted) = swap existing /24 with /28 to keep lower part, update maxAddr of existing and baseAddr of new and plan to insert upper part next

10.5.100.224/27 takes 224-256 from 10.5.100.0/24 and leaves 0-223 (upper part)
take the lower mask of the two to get network part of both addresses, if match:
c) maxAddrs match here (upper part split)
1) /27 is there and /24 is new (smaller mask is being inserted) = update maxAddr of /24 to /27's baseAddr-1 and proceed
1) /24 is there and /27 is new (bigger mask is being inserted) = update maxAddr of /24 to /27's baseAddr-1 and proceed

SEARCH

*/

void dumpTree (struct rb_tree *cust) {
	struct rb_iter *iter = rb_iter_create();
	if (iter) {
		for (struct net *n = rb_iter_last(iter, cust); n; n = rb_iter_prev(iter)) {
			printf("ID: %s\n", n->ID);
			printf("\tbase  %d.%d.%d.%d/%d\n", n->baseAddr[3], n->baseAddr[2], n->baseAddr[1], n->baseAddr[0], n->netMask);
			printf("\tmax   %d.%d.%d.%d\n", n->maxAddr[3], n->maxAddr[2], n->maxAddr[1], n->maxAddr[0]);
			printf("\tcID   %s\n", n->ID);
			printf("\tbytes %ld\n\n", n->trafCount);
		}
		rb_iter_dealloc(iter);
	}
}

// mode=0 for insert; mode=1 for search
int workFile (char *fp, unsigned int maxLineLen, struct rb_tree *cust, unsigned char mode) {
	unsigned char line[maxLineLen];
	struct st *tmpStack;

	if (NULL == fp) {
		printf("NULL file path\n");
		return -1;
	}

	FILE *fs = fopen(fp, "r");
	if (NULL == fs) {
		printf("Unable to open file [%s]: %s\n", fp, strerror(errno));
		return -1;
	}

	while ( !feof(fs) ) {
		if (NULL == fgets(line, maxLineLen, fs)) {
			if (!feof(fs)) {
				printf("Unable to read file [%s]: %s\n", fp, strerror(errno));
				return -1;
			}
			// it is just an end of file otherwise
		}
		else {
			// line ready
			printf("Got line: %s", line);
			struct net *new = (struct net*) calloc(1, sizeof(struct net));
			new->baseAddr = (unsigned char*) calloc(1, 4);
			new->maxAddr = (unsigned char*) calloc(1, 4);
			new->ID = (unsigned char*) calloc(1, CUSTID_SIZE+1);
			if (0 > parseLine (line, maxLineLen, new)) {
				free(new->baseAddr);
				free(new->maxAddr);
				free(new->ID);
				free(new);
				return -1;
			}
			if (0 == mode) {
				rb_tree_insert(cust, new);
				while (NULL != stack) {
					tmpStack = stack;
					new = stack->n;
					stack = stack->next;
					free(tmpStack);
					rb_tree_insert(cust, new);
				}
			}
			else {
				struct net *owner = rb_tree_find(cust, new);
			}
		}
	}
	fclose(fs);
	return 0;
}

int parseLine (unsigned char *line, unsigned int maxLineLen, struct net *new) {
	unsigned int i = 0, octetNum = 3, startPos = 0;
	while (i < maxLineLen) {
		if (line[i] == '.') {
			// one of ipv4 octets ended
			line[i] = '\0';
			if (3 >= i-startPos) {
				new->baseAddr[octetNum] = atoi( &line[startPos] );
				octetNum--;
			}
			else printf("Wrong format of octet %d: %s\n", octetNum, &line[startPos]);
			startPos = i+1;
		}
		else if (line[i] == ':') {
			i == maxLineLen; // TODO for ipv6
		}
		else if (line[i] == '/') {
			// net mask start
			line[i] = '\0';
			if (3 >= i-startPos) {
				new->baseAddr[octetNum] = atoi( &line[startPos] );
			}
			else printf("Wrong format of octet %d: %s\n", octetNum, &line[startPos]);
			startPos = i+1;
		}
		else if (line[i] == ' ') {
			line[i] = '\0';
			if (MAX_CUST_SIZE == maxLineLen) { // get network mask
				if (2 >= i-startPos) {
					new->netMask = atoi( &line[startPos] );
					unsigned int bits = 32 - new->netMask;
					memcpy(new->maxAddr, new->baseAddr, 4);
					*( (unsigned int*) new->maxAddr) += pow(2, bits) - 1;
				}
				else printf("Wrong format of net mask: %s\n", &line[startPos]);
			}
			else { // parse last octet of address in traffic log mode
				if (3 >= i-startPos) {
					new->baseAddr[octetNum] = atoi( &line[startPos] );
				}
				else printf("Wrong format of octet %d: %s\n", octetNum, &line[startPos]);
			}
			i++;
			startPos = i;
			// parse customers file part with customer id
			if (MAX_CUST_SIZE == maxLineLen) { // one if()/else switch and two while() instead of one while() and number of if's equal to number of loops
				while ( (i < maxLineLen-startPos) && (line[i] != '\n') && (line[i] != '\0') ) { // -startPos to count already passed address, mask and space
					new->ID[i-startPos] = line[i];
					i++;
				}
				//cID[i] = '\0';
				new->ID[i] = '\0';
			}
			// parse traffic log part with bytes count
			else {
				while ( (i < maxLineLen-startPos) && (line[i] != '\n') && (line[i] != '\0') ) i++; // -startPos to count already passed address, mask and space
				line[i] = '\0';
				new->trafCount = atol( &line[startPos] );
			}
			i = maxLineLen; // just to end the loop
		}
		i++;
	}
	return 0;
}

int main (void) {
	struct rb_tree *customers = rb_tree_create(compareCb);
	if (NULL == customers) {
		printf("Unable to create customers tree\n");
		return -1;
	}
	workFile("/data/customers.txt", MAX_CUST_SIZE, customers, 0);
	printf("\nCustomers:\n");
	dumpTree(customers);
	workFile("/data/log.txt", MAX_TRAF_SIZE, customers, 1);
	printf("\nCounted traffic:\n");
	dumpTree(customers);
	return 0;
}
