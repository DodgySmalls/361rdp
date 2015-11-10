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

int main(int argc, char ** argv) {

	RDP_packet in_packets[IN_PACKET_NUM];	//this is where we store the packed version of incoming information we read from inbuffer (cyclical queue : FIFO)
	int next_in_packet;						//index of the next RDP_packet in in_packet to which we can write (cyclical)

	byte_buffer outbuffer;					//our buffer where we store payloads in sequence (the contents of the file we're trying to transmit)
	char * rw_block;						//temp block with which we can read/write data
	int rw_block_len; 

	FILE * infile;
	long file_len;

	struct sockaddr_in sender_addr;
	struct sockaddir_in recvr_addr;
	socklen_t recvr_addr_len;
	int sockfd;

	/********************************/						
	/*         *  INIT 	*           */						

	outbuffer.mem = (char *) verifyMemory(malloc(OUT_BUF_LEN * sizeof(char)));
	outbuffer.memlen = OUT_BUF_LEN;
	rw_block = (char *) verifyMemory(malloc((MAX_PACKET_LEN + 1)* sizeof(char)));
	rw_block_len = (MAX_PACKET_LEN + 1);											//1 extra byte for \0 char

	if(argc != 6) { 
		printError("Invalid invocation, expected: \"rdps <sender_ip> <sender_port> <receiver_ip> <receiver_port> <sender_file_name>\"");
		return 100;
	} 

	//verify the file exists
	infile = fopen(argv[5]);
	if(infile == NULL) {
		fprintf(stderr, "ERROR : Could not open file \"%s\"", argv[5]);
	} else {
		//store the length of the file
		fseek(infile, 0, SEEK_END);          
		file_len = ftell(infile);             
		rewind(infile); 
	}

    memset(&sender_addr, 0, sizeof(struct sockaddr_in)); //zero garbage memory
    sender_addr.sin_family = AF_INET; 					 //IPv4
    sender_addr.sin_addr.s_addr = inet_addr(argv[1]);    //The address we want incoming packets to be routed to, ie. the sender's local address
    sender_addr.sin_port = htons(atoi(argv[2]));         //the port we want to communicate on, htons converts int to big endian (if necessary) (htons is 'host to network short')
    
    memset(&recvr_addr, 0, sizeof(struct sockaddr_in));
    recvr_addr.sin_family = AF_INET; 
    recvr_addr.sin_addr.s_addr = inet_addr(argv[3]); 
    recvr_addr.sin_port = htons(atoi(argv[4]));
    recvr_addr_len = sizeof(receiver_addr);

    //get a IPv4 datagram socket without predefined protocol
    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) == -1){
        perror("ERROR : socket()");
        return 101;
    }
    uint socket_option = (uint)1;
    if(setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &socket_option, sizeof(uint)) < 0) {
        printError("Failed to set socket to reusable");
        close(sockfd);
        return 102;
    } else if (bind(sockfd, (struct sockaddr *) &sender_addr, sizeof(struct sockaddr_in)) < 0){ 
        close(sockfd);
        perror("ERROR : bind()");
        return 103;
    }

	//INITIATE the handshake with the given receiver (argv)
	for(;;){
		break;
	}

	//transfer the file
	for(;;){
		if(1/*data on socket*/) {
			//read data
			//act on that data
		} 
			//timeout?
		break;		//condition is that you receive an ACK for the end of the file
	}

	//send a fin and wait for an ACK
	for(;;){
	
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
