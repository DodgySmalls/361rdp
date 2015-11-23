//standard libs
#ifndef LIB_STD
#define LIB_STD	
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
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

#define OUT_BUF_LEN 10240    //at most 10 outgoing packets at once
#define IN_PACKET_NUM 5      //number of packets we will remember, could be as low as 3

RDP_packet in_packets[IN_PACKET_NUM];	//this is where we store the packed version of incoming information we read from inbuffer (cyclical queue : FIFO)
RDP_packet out_packets[MAX_LIMBO_PACKETS];
int num_in_packets;
int num_out_packets;

bytebuffer32_t outbuffer;				//our buffer where we store payloads in sequence (the contents of the file we're trying to transmit)
char * rw_block;						//temp block with which we can read/write data

FILE * infile;
long file_len;
long file_read_head;

struct sockaddr_in sender_addr;
struct sockaddr_in recvr_addr;
socklen_t recvr_addr_len;
int sockfd;
fd_set fds;
int read_len;

uint32_t client_request;
double timeoutdur;

int outgoing_data;

uint32_t ssthresh;
uint32_t cwnd;

uint32_t reported_window_length;

time_t last_response;
time_t last_packetout;
time_t current_time;

RDP_state current_state;

struct timeval select_timeout = {0, 2500}; //0.00025 seconds

//clean way to send a unique packet for this line of code
void sendNewPacket(packet_intent pint, uint32_t s, uint32_t a, uint32_t d, uint32_t w) {
	if(current_state != TRANSFER) {
		num_out_packets = 0;
	}
	//track whenever we sent a packet out last
	time(&last_packetout);
	time(&(out_packets[num_out_packets].departure));
	//don't read past the end of the file
	if(s + d > file_len) {
		d = file_len - s;
	}
	RDPGeneratePacket(&out_packets[num_out_packets], pint, s, a, d, w);
	RDPWritePacket(rw_block, &out_packets[num_out_packets], &outbuffer);
	printf("SENDING: ");
    printPacket(&out_packets[num_out_packets]);
	if(sendto(sockfd, rw_block, strlen(rw_block), 0, (struct sockaddr *)&recvr_addr, recvr_addr_len) == -1) {
		perror("ERROR : sendto()");
		exit(172);
	}
	if(current_state == TRANSFER) {
		num_out_packets++;
	}
}

/* NOTE that if something goes wrong (interally) we currently don't exit gracefully */
long readPacket(RDP_packet * r) {
	long rl;
	if((rl = recvfrom(sockfd, rw_block, MAX_PACKET_LEN, 0, (struct sockaddr *)&recvr_addr, &recvr_addr_len)) == -1) {
    	perror("recvfrom()");
        exit(104);
    } else {
    	memset(r, 0, sizeof(RDP_packet));
        rw_block[rl] = '\0';
        if(RDPLoadPacket(rw_block, r) == NULL) {
       		printf("regex failed");
       	}
       	printf("RECEIVED: ");
        printPacket(r);
    	return rl;
    } 
}

void selectOnSockfd() {
	FD_ZERO(&fds);
    FD_SET(sockfd, &fds);
    if(select(sockfd+1, &fds, NULL, NULL, &select_timeout) == -1){
        perror("ERROR : select()");
        exit(110);
    }
}

int main(int argc, char ** argv) {				

	outbuffer.mem = (char *) verifyMemory(malloc(OUT_BUF_LEN * sizeof(char)));
	outbuffer.memlen = OUT_BUF_LEN;
	rw_block = (char *) verifyMemory(malloc((MAX_PACKET_LEN + 1)* sizeof(char)));		//1 extra byte for \0 char

	if(argc != 6) { 
		printError("Invalid invocation, expected: \"rdps <sender_ip> <sender_port> <receiver_ip> <receiver_port> <sender_file_name>\"");
		return 100;
	} 

	//verify the file exists
	infile = fopen(argv[5], "r");
	if(infile == NULL) {
		fprintf(stderr, "ERROR : Could not open file \"%s\"", argv[5]);
		return 142;
	} else {
		//store the length of the file
		fseek(infile, 0, SEEK_END);          
		file_len = ftell(infile);             
		rewind(infile); 
		printf("file len: %ld\n", file_len);
	}

    memset(&sender_addr, 0, sizeof(struct sockaddr_in)); //zero garbage memory
    sender_addr.sin_family = AF_INET; 					 //IPv4
    sender_addr.sin_addr.s_addr = inet_addr(argv[1]);    //The address we want incoming packets to be routed to, ie. the sender's local address
    sender_addr.sin_port = htons(atoi(argv[2]));         //the port we want to communicate on, htons converts int to big endian (if necessary) (htons is 'host to network short')
    
    memset(&recvr_addr, 0, sizeof(struct sockaddr_in));
    recvr_addr.sin_family = AF_INET; 
    recvr_addr.sin_addr.s_addr = inet_addr(argv[3]); 
    recvr_addr.sin_port = htons(atoi(argv[4]));
    recvr_addr_len = sizeof(recvr_addr);

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
        perror("ERROR : bind()");
        close(sockfd);
        return 103;
    }

    printf("NEW\n");
    //fill the buffer
    if(file_len > outbuffer.memlen) {
    	fread((void*)outbuffer.mem,1,outbuffer.memlen,infile);
    	file_read_head = outbuffer.memlen;
    } else {
    	fread((void*)outbuffer.mem,1,file_len,infile);
    	file_read_head = file_len;						
    }
    //the buffer's initial configuration is that buffer = window (same position and size)
    outbuffer.win = outbuffer.mem;
    outbuffer.winlen = outbuffer.memlen;
    //currently the window points to the first byte of the file
    outbuffer.win_seqno = 0;		

    /*srand(time(NULL));
    rnd_num = (uint32_t)rand();
    rnd_num = rnd_num % 1000; //prep our random base sequence number between 1-1000
    printf("I picked the random number: %"PRIu32"\n", rnd_num); */
    printf("I am %s\n", inet_ntoa(sender_addr.sin_addr));
    printf("sending to: %s\n", inet_ntoa(recvr_addr.sin_addr));
 
    timeoutdur = 3.00;
    time(&last_response);
    time(&last_packetout);

    current_state = HANDSHAKE;
    for(;;) {

	    if(current_state == HANDSHAKE) {

	    	sendNewPacket(SYN, 0, 0, 0, 0);
		  

		    for(;;) {
				selectOnSockfd();
		        if(FD_ISSET(sockfd, &fds)){
		        	printf("there was data on socket\n");
		        	read_len = readPacket(&(in_packets[0]));
		        	if(in_packets[0].intent == ACK && in_packets[0].ackno == 0) {
		        		printf("going to data transfer\n");
		        		client_request = 0;        		
		        		time(&last_response);
		        		current_state = TRANSFER;
		        		break;
		        	} else if (in_packets[0].intent == RST) {
		        		sendNewPacket(SYN, 0, 0, 0, 0);
		        	}
		        } else {
					time(&current_time);
					if(difftime(current_time, last_packetout) > timeoutdur && difftime(current_time, last_response) > timeoutdur) {
						sendNewPacket(SYN, 0, 0, 0, 0);
					}
				}			
			}
		}//HANDSHAKE

		if(current_state == TRANSFER) {
			num_out_packets=0;

			if(file_len < MAX_RDP_PAYLOAD) {
				sendNewPacket(DAT, 0, 1, file_len, MAX_PACKET_LEN);
			} else {
				sendNewPacket(DAT, 0, 1, MAX_PACKET_LEN, MAX_PACKET_LEN);
			}
			
			client_request = 0;
			outgoing_data = out_packets[0].datlen;

			for(;;){
				selectOnSockfd();
				if(FD_ISSET(sockfd, &fds)){
					read_len = readPacket(&(in_packets[0]));

					if(read_len > 0) {	//if the packet was accepted
						if(in_packets[0].ackno > client_request) {
							client_request = in_packets[0].ackno;
						}
						time(&last_response);
					}

					reported_window_length = in_packets[0].winlen;

					//if the client acked past the beginning of our buffer we know we can shrink the window
					if(client_request > outbuffer.win_seqno) {
						uint32_t dif = client_request - outbuffer.win_seqno;
						outbuffer.win += dif;
						outbuffer.win_seqno += dif;
						outbuffer.winlen -= dif;

						if(outbuffer.win > outbuffer.mem + outbuffer.memlen) {
							outbuffer.win -= outbuffer.memlen;
						}
					}
					file_read_head += bytebuffer32_ExpandFromFile(&outbuffer, infile, file_len - file_read_head);

					int q;
					int qwe;
					for(q=0;q<num_out_packets;q++){
						if(out_packets[q].seqno + out_packets[q].datlen <= client_request) {
							//modify timeoutdur

							outgoing_data -= out_packets[q].datlen;
							for(qwe=q;qwe<num_out_packets-1;qwe++) {
								memmove(&out_packets[qwe], &out_packets[qwe+1], sizeof(RDP_packet));
							}
							memset(&out_packets[qwe], 0, sizeof(RDP_packet));
							num_out_packets--;
						}
					}

					printf("client requested byte: %"PRIu32" -\n", client_request);
					if(client_request >= file_len) {
						current_state = FINISHED;
						break;				//break makes the loop condition redundant
					} else {
						if(num_out_packets == 0) {
							while(num_out_packets < MAX_LIMBO_PACKETS-1 && outgoing_data < reported_window_length) {
								sendNewPacket(DAT, client_request + outgoing_data, 1, MAX_PACKET_LEN, MAX_PACKET_LEN);
								outgoing_data += out_packets[num_out_packets-1].datlen;
							}
						}
					}
				} else {

					time(&current_time);
					//wait until no communication has been received between the two hosts for duration timeoutdur
					if(difftime(current_time, last_packetout) > timeoutdur && difftime(current_time, last_response) > timeoutdur) {
						num_out_packets = 0;
						outgoing_data = 0;
						sendNewPacket(DAT, outbuffer.win_seqno, 1, MAX_PACKET_LEN, MAX_PACKET_LEN);
					} else {
						file_read_head += bytebuffer32_ExpandFromFile(&outbuffer, infile, file_len - file_read_head);
					}
				}
			}
		}//TRANSFER

		if(current_state == FINISHED){
			
			sendNewPacket(FIN,0,0,0,0);

			for(;;) {
				selectOnSockfd();
		        if(FD_ISSET(sockfd, &fds)){
		        	read_len = readPacket(&(in_packets[0]));
		        	if(in_packets[0].intent == ACK && in_packets[0].seqno == 2) {
		        		current_state = COMPLETE;
		        		break;
		        	}
		        } else {
		        	time(&current_time);
		        	if(difftime(current_time, last_packetout) > timeoutdur && difftime(current_time, last_packetout) > timeoutdur) {
		        		sendNewPacket(FIN,0,0,0,0);
		        	}
		        }
		    }
		}//FIN

		if(current_state == COMPLETE){
			break;
		}
	}

	fclose(infile);
	close(sockfd);
    return 0;
}
