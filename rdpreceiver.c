//standard libs
#ifndef LIB_STD
#define LIB_STD	
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#endif

//inet libs
#ifndef LIB_INET
#define LIB_NET	
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif

//log/print format libs
#ifndef LIB_FORMAT
#define LIB_FORMAT
#include <errno.h>
#include <inttypes.h>
#include <time.h>
#endif

//functions used across client/server
#include "rdputil.c"

//at most 10 outgoing packets at once
#define OUT_BUF_LEN 10240
//number of packets we will remember, could be as low as 3
#define IN_PACKET_NUM 5

/********************************
		P2 spec mandatory: 			    
********************************/
#define MAX_PACKET_LEN 1024
//to ensure payload doesn't overflow to 4 digits (makes calculating total packet size simpler) <- all this stuff would be better if we could use packed data ...
#define MAX_RDP_PAYLOAD 999


//ECS360 specific vals
#define SERVER_ADDRESS "10.10.0.100"
#define CLIENT_ADDRESS "192.168.1.1"

int main(int argc, char ** argv) {

	RDP_packet in_packets[IN_PACKET_NUM];	//this is where we store the packed version of incoming information we read from inbuffer (cyclical queue : FIFO)
	int next_in_packet;						//index of the next RDP_packet in in_packet to which we can write (cyclical)

	byte_buffer outbuffer;					//our buffer where we store portions of packet payloads to transmit
	char * block;		int block_len;		//temp block with which we can read/write data

	outbuffer.mem = (char *) verifyMemory(malloc(OUT_BUF_LEN * sizeof(char)));
	outbuffer_size = OUT_BUF_LEN;
	block = (char *) verifyMemory(malloc(MAX_PACKET_LEN * sizeof(char)));
	block_len = MAX_PACKET_LEN;

	//open port and wait

	//WAIT FOR the handshake
	for(;;){
		break;
	}

	//transfer
	for(;;){
		if(1/*data on socket*/) {
			//read data
			//act on that data
		} 
			//timeout?
		break;
	}

	//close
	for(;;){
		break;
	}

	/*
	strncpy(outbuffer, "RDP361 DAT 0 1 2 3\n\nQQQ", IN_INIT_BUF_LEN);
	strncpy(inbuffer, "qwerty", IN_INIT_BUF_LEN);
	memmove(inbuffer, outbuffer, IN_INIT_BUF_LEN);
	printf("(%d) out: %s\nin: %s\n", outbuffer_size, outbuffer, inbuffer);

	if(!RDPLoadPacket(inbuffer, &in_packet)) {
		printError("rdpserver : packet was rejected");
	} else {
		if(in_packet.header.intent == DAT) {
			printf("Header: DAT ");
		} else {
			printf("Header: something that isn't DAT ");
		}
		printf("%"PRIu32" %"PRIu32" %"PRIu32" %"PRIu32" \n", in_packet.header.seqno, in_packet.header.ackno, in_packet.header.datlen, in_packet.header.winlen);
		printf("DATA (%"PRIu32") bytes: %s\n", in_packet.header.datlen, in_packet.payload);
	}
	*/


    return 0;
}
