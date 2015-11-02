//standard libs
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

//functions used across client/server
#include "rdputil.c"

//temp
#include <inttypes.h>

int match_RDP_header(RDP_packet *);

#define INIT_BUF_LEN 1024   


//global variables, unsafe and generally bad practice, but makes code a lot simpler/readable (avoids functions with unnessecarily large argument lists)
char * outbuffer;		int outbuffer_size;
char * inbuffer;		int inbuffer_size;

int main(int argc, char ** argv) {

	RDP_packet in_packet;

	outbuffer = (char *) verifyMemory(malloc(INIT_BUF_LEN * sizeof(char)));
	outbuffer_size = INIT_BUF_LEN;
	inbuffer = (char *) verifyMemory(malloc(INIT_BUF_LEN * sizeof(char)));
	inbuffer_size = INIT_BUF_LEN;

	strncpy(outbuffer, "RDP361 DAT 0 1 2 3", INIT_BUF_LEN);
	strncpy(inbuffer, "qwerty", INIT_BUF_LEN);
	memmove(inbuffer, outbuffer, 20);
	printf("(%d) out: %s\nin: %s\n", outbuffer_size, outbuffer, inbuffer);

	if(!RDPLoadPacket(inbuffer, &in_packet)) {
		printError("rdpserver : packet was rejected");
	} else {
		if(in_packet.header.intent == DAT) {
			printf("Header: DAT ");
		}
		printf("%"PRIu32" %"PRIu32" %"PRIu32" %"PRIu32" \n", in_packet.header.seqno, in_packet.header.ackno, in_packet.header.datlen, in_packet.header.winlen);
	}

    return 0;
}
