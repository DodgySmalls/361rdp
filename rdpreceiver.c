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

//initially we will account for 10 incoming packets at once that we remember, if more are needed (very unlikely to happen) then we will grow our memory
#define INIT_NUM_TRACKED_PACKETS 10
#define IN_BUF_LEN 10240

int main(int argc, char ** argv) {

	RDP_packet in_packets[INIT_NUM_TRACKED_PACKETS];	//this is where we store the packed version of incoming information we read from inbuffer (cyclical queue : FIFO)
	int next_in_packet;						//index of the next RDP_packet in in_packet to which we can write (cyclical)
	int in_packets_len;						//current number of packets we're tracking	<- this is a byproduct of using a header which is not packed

	byte_buffer inbuffer;					//our buffer where we store packet payloads in sequence (the contents of the file we're trying to receive)
	char * rw_block;						//temp block with which we can read/write data
	int rw_block_len;		

	FILE * outfile;

	struct sockaddr_in sender_addr;
	struct sockaddir_in recvr_addr;
	socklen_t sender_addr_len;
	int sockfd;

	/********************************/						
	/*         *  INIT 	*           */

	in_packets_len = INIT_NUM_TRACKED_PACKETS;

	inbuffer.mem = (char *) verifyMemory(malloc(IN_BUF_LEN * sizeof(char)));
	inbuffer.memlen = IN_BUF_LEN;
	rw_block = (char *) verifyMemory(malloc((MAX_PACKET_LEN + 1)* sizeof(char)));
	rw_block_len = (MAX_PACKET_LEN + 1);											//1 extra byte for \0 char

	if(argc != 4) { 
		printError("Invalid invocation, expected: \"rdpr <receiver_ip> <receiver_port> <file_name>\"");
		return 100;
	}

	//open port and wait
	memset(&recvr_addr, 0, sizeof(struct sockaddr_in)); //zero garbage memory
    recvr_addr.sin_family = AF_INET; 					 //IPv4
    recvr_addr.sin_addr.s_addr = inet_addr(argv[1]);    //The address we want incoming packets to be routed to, ie. the recvr's local address
    recvr_addr.sin_port = htons(atoi(argv[2]));         //the port we want to communicate on, htons converts int to big endian (if necessary) (htons is 'host to network short')
    
    memset(&sender_addr, 0, sizeof(struct sockaddr_in));
   	sender_addr_len = sizeof(sockaddr_in);

	//WAIT FOR the handshake, and acknowledge
	for(;;){
		break;
	}

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
    } else if (bind(sockfd, (struct sockaddr *) &recvr_addr, sizeof(struct sockaddr_in)) < 0){ 
        close(sockfd);
        perror("ERROR : bind()");
        return 103;
    }

	//ACK verified and completed segments (cumulative ACK)
	for(;;){
		if(1/*data on socket*/) {
			//read data
			//act on that data
		} 
			//timeout?
		break;
	}

	//Once the whole file has been completed, ask to close the connection
	for(;;){
		break;
	}

    return 0;
}
