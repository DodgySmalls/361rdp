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

//initially we will account for 10 incoming packets at once that we remember, if more are needed (very unlikely to happen) then we will grow our memory
#define INIT_NUM_TRACKED_PACKETS 10
#define IN_BUF_LEN 10240
    
//using global variables to make the code more concise
RDP_packet in_packets[INIT_NUM_TRACKED_PACKETS];    //this is where we store the packed version of incoming information we read from inbuffer (cyclical queue : FIFO)
int next_in_packet;                     //index of the next RDP_packet in in_packet to which we can write (cyclical)
int in_packets_len;                     //current number of packets we're tracking  <- this is a byproduct of using a header which is not packed

bytebuffer32_t inbuffer;                   //our buffer where we store packet payloads in sequence (the contents of the file we're trying to receive)
char * rw_block;                        //temp block with which we can read/write data  

FILE * outfile;

struct sockaddr_in sender_addr;
struct sockaddr_in recvr_addr;
socklen_t sender_addr_len;
int sockfd;
fd_set fds;
int read_len;

time_t last_response;
time_t current_time;
time_t last_outpacket;
double timeoutdur;

RDP_state current_state;

struct timeval select_timeout = {1, 0}; // 1seconds

//clean way to send a unique packet for this line of code
void sendNewPacket(packet_intent pint, uint32_t s, uint32_t a, uint32_t d, uint32_t w) {
    RDP_packet outpacket;

    time(&last_outpacket);

    RDPGeneratePacket(&outpacket, pint, s, a, d, w);
    RDPWritePacket(rw_block, &outpacket, NULL);
    printf("SENT: ");
    printPacket(&outpacket);
    if(sendto(sockfd, rw_block, strlen(rw_block), 0, (struct sockaddr *)&sender_addr, sender_addr_len) == -1) {
        perror("ERROR : sendto()");
        exit(172);
    }
}

//clean way to send a packet we had already generated somewhere else
void sendParticularPacket(RDP_packet * r) {
    RDPWritePacket(rw_block, r, NULL);
    if(sendto(sockfd, rw_block, strlen(rw_block), 0, (struct sockaddr *)&sender_addr, sender_addr_len) == -1) {
        perror("ERROR : sendto()");
        exit(173);
    }
}

/* NOTE that if something goes wrong (interally) we currently don't exit gracefully */
long readPacket(RDP_packet * r) {
    long rl;
    char * payload;

    time(&last_response);

    if((rl = recvfrom(sockfd, rw_block, MAX_PACKET_LEN, 0, (struct sockaddr *)&sender_addr, &sender_addr_len)) == -1) {
        perror("recvfrom()");
        exit(104);
    } else {
        memset(r, 0, sizeof(RDP_packet));
        rw_block[rl] = '\0';
 
        if((payload = RDPLoadPacket(rw_block, r)) == NULL) {
            printf("regex failed\n");
        } else if (r->datlen > 0) {
            //printf(payload);
            bytebuffer32_WriteTo(payload, &inbuffer, r->seqno, r->datlen);
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
    /********************************/                      
    /*         *  INIT  *           */

    in_packets_len = INIT_NUM_TRACKED_PACKETS;
    next_in_packet = 0;

    inbuffer.mem = (char *) verifyMemory(malloc(IN_BUF_LEN * sizeof(char)));
    inbuffer.memlen = IN_BUF_LEN;
    rw_block = (char *) verifyMemory(malloc((MAX_PACKET_LEN + 1) * sizeof(char))); //1 extra byte for \0 char

    if(argc != 4) { 
        printError("Invalid invocation, expected: \"rdpr <receiver_ip> <receiver_port> <file_name>\"");
        return 100;
    }

    //verify the file exists
    outfile = fopen(argv[3], "w");
    if(outfile == NULL) {
        fprintf(stderr, "ERROR : Could not open file \"%s\"", argv[3]);
        return 142;
    } else {
        printf("opened: %s\n", argv[3]);
    }

    //open port and wait
    memset(&recvr_addr, 0, sizeof(struct sockaddr_in)); //zero garbage memory
    recvr_addr.sin_family = AF_INET;                    //IPv4
    recvr_addr.sin_addr.s_addr = inet_addr(argv[1]);    //The address we want incoming packets to be routed to, ie. the recvr's local address
    recvr_addr.sin_port = htons(atoi(argv[2]));         //the port we want to communicate on, htons converts int to big endian (if necessary) (htons is 'host to network short')
    
    memset(&sender_addr, 0, sizeof(struct sockaddr_in));
    sender_addr_len = sizeof(sender_addr);

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

    printf("I am identified as: %s before NAT\n", inet_ntoa(recvr_addr.sin_addr));

    inbuffer.win = inbuffer.mem;
    inbuffer.winlen = inbuffer.memlen;
    inbuffer.win_seqno = 0;
    current_state = HANDSHAKE;

    timeoutdur = 5.0;

    for(;;) {
        if(current_state == HANDSHAKE) {
            //WAIT FOR the handshake, and acknowledge
            for(;;){
                selectOnSockfd();
                if(FD_ISSET(sockfd, &fds)){
                    read_len = readPacket(&(in_packets[0]));
            
                    if(in_packets[0].intent == SYN) {
                        //printf("Received random number: %"PRIu32"\n", rnd_num);
                        printf("I am still %s\n", inet_ntoa(recvr_addr.sin_addr));
                        printf("sender is: %s\n", inet_ntoa(sender_addr.sin_addr));
                        //put a new ACK + SYN packet into rw_block and send it back
                        sendNewPacket(ACK, 1, 0, 0, IN_BUF_LEN);
                    } else if (in_packets[0].intent == DAT) {
                        current_state = TRANSFER;
                        break;
                    } else {
                        //try to RST connection (packet was malformed or damaged during transmission)
                        printf("RST");
                        sendNewPacket(RST, 0, 0, 0, IN_BUF_LEN);
                    } 
                }
            }//HANDSHAKE
        }

        if(current_state == TRANSFER) {
            if(in_packets[0].intent == DAT) {
                //handle extra packet we got in handshake state?
            }

            for(;;){
                selectOnSockfd();
                if(FD_ISSET(sockfd, &fds)){
                    read_len = readPacket(&(in_packets[0]));    //reads the header into in_packets[0] and the payload into the inbuffer

                    if(in_packets[0].intent == DAT) {
                        sendNewPacket(ACK, 1, in_packets[0].seqno + in_packets[0].datlen, 0, inbuffer.winlen);
                        
                        uint32_t s = inbuffer.win_seqno;
                        inbuffer.win_seqno = in_packets[0].seqno + in_packets[0].datlen;
                        inbuffer.win += inbuffer.win_seqno - s;
                        inbuffer.winlen -= inbuffer.win_seqno - s;

                        if(inbuffer.win > inbuffer.mem + inbuffer.memlen) {
                            inbuffer.win -= inbuffer.memlen;
                        }
                    } else if (in_packets[0].intent == FIN) {
                        sendNewPacket(ACK, 2, 0, 0, 0);
                        current_state = FINISHED;
                        break;
                    }
                } else {
                    bytebuffer32_FlushToFile(&inbuffer, outfile);
                }
            }
        }//TRANSFER

        if(current_state == FINISHED) {
              for(;;){
                selectOnSockfd();
                if(FD_ISSET(sockfd, &fds)){
                    sendNewPacket(ACK, 2, 0, 0, 0);
                } else {
                    time(&current_time);
                    if(difftime(current_time, last_response) > timeoutdur && difftime(current_time, last_outpacket) > timeoutdur) {
                        current_state = COMPLETE;
                        break;
                    }
                }
            }
        }

        if(current_state == COMPLETE) {
            bytebuffer32_FlushToFile(&inbuffer, outfile);
            break;
        }//COMPLETE

    }

    fclose(outfile);
    close(sockfd);
    return 0;
}



