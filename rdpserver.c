//standard libs
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

//functions used across client/server
#include "rdputil.c"

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

	if(regcomp(&RDP_regex, RDP_REGEX_LITERAL, 0)) {
		printError("Regex failed to compile.");
	}

	strncpy(outbuffer, "RPD361 DAT 0 1 2 3\n", INIT_BUF_LEN);
	strncpy(inbuffer, "qwerty\n", INIT_BUF_LEN);
		printf(outbuffer);
		printf(inbuffer);

	outbuffer_size = growMemory((void **)&outbuffer, outbuffer_size);
	printf(outbuffer);
	memmove(inbuffer, outbuffer, 20);
	printf("out %d: %s - in: %s", outbuffer_size, outbuffer, inbuffer);
	printf("------------------");


    return 0;
}
