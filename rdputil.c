/** this file contains all functions which do not use global variables in the RDP/client sender, as well as all typedefs **/

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

#include <regex.h>
#include <stdarg.h>

//                           magic      _type_                       _seqno_      _ackno_     _datalen_    _windowlen_
#define RDP_REGEX_LITERAL "^RDP361 \\([a-zA-Z][a-zA-Z][a-zA-Z]\\) \\([0-9]*\\) \\([0-9]*\\) \\([0-9]*\\) \\([0-9]*\\)\n\n"
#define RDP_NUMGROUPS 5 //const number of groups in the above regex, so we just define it manually rather than searching for it iteratively
#define MAX_PACKET_LEN 1024	//defined by p2 spec
#define MAX_RDP_PAYLOAD 999	//ensure datalength doesn't overflow to 4 digits. Unpacked structure zzz...
#define MAX_LIMBO_PACKETS 10

typedef enum {SYN, ACK, DAT, FIN, RST, INV} packet_intent;

typedef enum {HANDSHAKE, TRANSFER, FINISHED, COMPLETE} RDP_state;

typedef struct {packet_intent intent;
				uint32_t seqno;
				uint32_t ackno;
				uint32_t datlen; 
				uint32_t winlen;
				time_t departure;
			   } RDP_packet;

typedef struct { 
				uint32_t win_seqno;		    //the current offset of the start of the window from the beginning of whatever larger byte sequence this refers to (ie. a large file)
				char * mem;					//pointer to start of our memory block
				size_t memlen;		   		//total length of the buffer
				char * win;					//the location of the window
				uint32_t winlen;			//the length of the window
			  } bytebuffer32_t;				//name to remind us that the maximum buffer and windowsize is 2^32, I wrote no code to handle overflow (could be done though)


//A function to uniformly handly error messages
//TODO: modularity + functionality improvement
void printError(char * s) {
	fprintf(stderr, "ERROR : %s\n", s);
}
void printPacket(RDP_packet * r){
	if(r->intent == ACK){
		printf("< ACK > ");
	} else if(r->intent == DAT){
		printf("< DAT > ");
	} else if(r->intent == RST){
		printf("< RST > ");
	} else if(r->intent == FIN){
		printf("< FIN > ");
	} else if(r->intent == SYN){
		printf("< SYN > ");
	} if(r->intent == INV){
		printf("! INVALID !");
	}
	printf("SEQ:%"PRIu32" - ACK:%"PRIu32" - DATALENGTH:%"PRIu32" - WINDOWLENGTH:%"PRIu32" \n", r->seqno, r->ackno, r->datlen, r->winlen);
}

//writes the continuous memory m, which is located at 'seq' WRT some longer byte sequence, into the buffer in the correct position
uint32_t bytebuffer32_WriteTo(char * m, bytebuffer32_t * b, uint32_t seq, uint32_t datlen){
	//trim incoming data so we only handle whatever subset intersects with the window
	if(seq + datlen < b->win_seqno || seq > b->win_seqno + b->winlen){
		return 0;
	}
	if(seq < b->win_seqno) {
		datlen -= (b->win_seqno - seq);
		m+= (b->win_seqno - seq);
		seq = b->win_seqno;
	}
	if(seq + datlen > b->win_seqno + b->winlen) {
		datlen -= ((seq + datlen) - (b->win_seqno + b->winlen));
	}

	//write the valid bytes into the window byte by byte
	char * insert = b->win + (seq - b->win_seqno);
	int i;
	for(i=0;i<datlen;i++) {
		if(insert + i >= b->mem+b->memlen) {
			insert -= b->memlen;
		}
		memmove((void*)(insert + i), (void*)(m + i), 1);
	}
	return datlen;
}

//reads the possibly discontinuous data, which is located at 'seq' WRT some longer byte sequence, and writes it to * m
uint32_t bytebuffer32_ReadFrom(char * m, bytebuffer32_t * b, uint32_t seq, uint32_t datlen){
	//trim requested data so we only return the subset that exists within the window
	if(seq + datlen < b->win_seqno || seq > b->win_seqno + b->winlen){
		return 0;
	}
	if(seq < b->win_seqno) {
		datlen -= (b->win_seqno - seq);
		m+= (b->win_seqno - seq);		
		seq = b->win_seqno;						
	}
	if(seq + datlen > b->win_seqno + b->winlen) {
		datlen -= ((seq + datlen) - (b->win_seqno + b->winlen));
	}

	//read the valid bytes from the window byte by byte
	char * read = b->win + (seq - b->win_seqno);
	int i;
	for(i=0;i<datlen;i++) {
		if(read + i >= b->mem + b->memlen) {
			read -= b->memlen;
		}
		memmove((void*)(m + i), (void*)(read + i), 1);
	}
	return datlen;
}

//grows the window as much as possible by reading data from a file
//returns the number of bytes read
uint32_t bytebuffer32_ExpandFromFile(bytebuffer32_t * b, FILE * f, long remaining_bytes) {
	if(b->winlen == b->memlen || remaining_bytes < 1) {
		return 0;
	}

	int i;
	int j;
	char * insert = b->win;
	for(i=0;i<b->winlen;i++) {
		if(insert >= b->mem + b->memlen){
			insert -= b->memlen;
		}
		insert++;
	}
	for(j=i;j<b->memlen;j++){
		if(insert >= b->mem + b->memlen){
			insert -= b->memlen;
		}
		if(j-i >= (int)remaining_bytes) {
			b->winlen += (uint32_t)(j-i);
			return (uint32_t)(j-i);
		} else {
			fread(insert,1,1,f);
		}
		insert++;
	}

	b->winlen += (uint32_t)(j-i);
	return (uint32_t)(j-i);
}

//grows the window as much as possible by writing buffer data to a file
//returns the number of bytes written
uint32_t bytebuffer32_FlushToFile(bytebuffer32_t * b, FILE * f) {
	if(b->winlen >= b->memlen) {
		return 0;
	}
		int i;
	int j;
	char * insert = b->win;
	for(i=0;i<b->winlen;i++) {
		if(insert >= b->mem + b->memlen){
			insert -= b->memlen;
		}
		insert++;
	}
	for(j=i;j<b->memlen;j++){
		if(insert >= b->mem + b->memlen){
			insert -= b->memlen;
		}
		fwrite(insert,1,1,f);
		/*char asdf[2];
		asdf[1] = '\0';
		asdf[0] = *insert;
		printf("!%s", asdf);				print mode (safer) */
		insert++;
	}

	b->winlen += (uint32_t)(j-i);
	return (uint32_t)(j-i);
}


//Accepts a string and matches it to the set of different packet_intents
packet_intent parsePacketIntent(char * s) {
	packet_intent pint;
	if(strstr(s, "DAT") != NULL) {
		pint = DAT;
	} else if(strstr(s, "ACK") != NULL) {
		pint = ACK;
	} else if(strstr(s, "SYN") != NULL) {
		pint = SYN;
	} else if(strstr(s, "FIN") != NULL) {
		pint = FIN;
	} else if(strstr(s, "RST") != NULL) {
		pint = RST;
	} else {
		pint = INV;
	}
	return pint;
}

//tries to match a given string to the RDP_REGEX_LITERAL
// returns a NULL pointer if packet has been rejected
// returns a pointer to the payload in memory if the packet is accepted (NOTE: this pointer may be garbage if packet did not contain data)
char * RDPLoadPacket(char * s, RDP_packet * r) {
	int i;
	int regex_outcome;
	regex_t RDP_regex;
	regmatch_t groups[10]; //const size is fine because # of matched groups doesn't grow

	//we zero the packet to ensure that if the match fails no garbage data remains
	memset(r, 0, sizeof(RDP_packet));

	if(regcomp(&RDP_regex, RDP_REGEX_LITERAL, 0)) {
		printError("rdputil : Regex failed to compile.");
	}

	regex_outcome = regexec(&RDP_regex, s, RDP_regex.re_nsub+1, groups, 0);
    if(!regex_outcome) {
    	//block each group with \0 so we can trivially read them with pointers >groups[i].rm_so
    	for (i = 1; i <= RDP_NUMGROUPS; i++) {
			s[groups[i].rm_eo] = '\0';
		}

		r->intent = parsePacketIntent(&s[groups[1].rm_so]);
		//if the packet's intent was invalid we drop it
		if(r->intent == INV) {
			return NULL;
		}

		//TODO: Error checking for values outside 2^32? 
		r->seqno = (uint32_t) atoi(&s[groups[2].rm_so]);
		r->ackno = (uint32_t) atoi(&s[groups[3].rm_so]);
		r->datlen = (uint32_t) atoi(&s[groups[4].rm_so]);
		r->winlen = (uint32_t) atoi(&s[groups[5].rm_so]);

    	return (char *) &(s[groups[5].rm_eo+2]);
    } else {
    	//if the packet's header doesn't conform to our spec we drop it (either badly formed request or bits have been flipped)
    	return NULL;
    }
}

//puts a new packet into the memory located at *r
uint32_t RDPGeneratePacket(RDP_packet * r, packet_intent pint, uint32_t seq, uint32_t ack, uint32_t datl, uint32_t winl) {
	memset(r, 0, sizeof(RDP_packet)); //zero old memory
	r->intent = pint;
	r->seqno = seq;
	r->ackno = ack;
	r->winlen = winl;

	//Now we need to ensure that the payload + ASCII version of this header won't be longer than 1024
	//unpacked structure zzz...
	if(r->intent == DAT) {
		if(datl > MAX_RDP_PAYLOAD) {
			datl = MAX_RDP_PAYLOAD;
		}
		r->datlen = datl;

		char scratchspace[100];
		int ofst = RDPWritePacketHeader(&(scratchspace[0]), r);

		if(r->datlen > MAX_PACKET_LEN - (uint32_t) ofst) {
			r->datlen = MAX_PACKET_LEN - (uint32_t) ofst;
		}
	}

	return r->datlen;
}

//writes the contents of a given RDP packet into a block of memory (* s) from the buffer b
//note that if r is not a data packet we can simply supply a null pointer
void RDPWritePacket(char * s, RDP_packet * r, bytebuffer32_t * b) {
	char * payload = (s + RDPWritePacketHeader(s, r));
	if(r->datlen > 0) {
		bytebuffer32_ReadFrom(payload, b, r->seqno, r->datlen);
	}
}

//reads the continuous block of memory s and puts the rdp packet it contains into the buffer b
/*void RDPReadPacket(char * s, RDP_packet * r, bytebuffer32_t * b) {
	char * payload = RDPLoadPacket(s, r);
	if(r->datlen > 0) {
		bytebuffer32_WriteTo(payload, b, r->seqno, r->datlen);
	}
}
*/


//writes the header to a given string, returns the length of the header that it wrote
int RDPWritePacketHeader(char * s, RDP_packet * r) {
	char * ss = s;
	ss = ss + sprintf(ss, "RDP361 ");
	if(r->intent == DAT) {
		ss = ss + sprintf(ss, "DAT ");
	} else if(r->intent == SYN) {
		ss = ss + sprintf(ss, "SYN ");
	} else if(r->intent == ACK) {
		ss = ss + sprintf(ss, "ACK ");
	} else if(r->intent == FIN) {
		ss = ss + sprintf(ss, "FIN ");
	} else if(r->intent == RST) {
		ss = ss + sprintf(ss, "RST ");
	} else {
		ss = ss + sprintf(ss, "INV ");
	}
	ss = ss + sprintf(ss, "%"PRIu32" ", r->seqno);
	ss = ss + sprintf(ss, "%"PRIu32" ", r->ackno);
	ss = ss + sprintf(ss, "%"PRIu32" ", r->datlen);
	ss = ss + sprintf(ss, "%"PRIu32"", r->winlen);
	ss = ss + sprintf(ss, "\n\n");
	return (int) (ss - s);
}

//A function to smoothly ensure requested heap memory is obtained
//TODO: Graceful error handling?
void * verifyMemory(void * p) {
	if(p == NULL) {
		printError("rdputil : FATAL : MALLOC FAILED TO RETURN MEMORY");
		exit(77);
	} else {
		return(p);
	}
}

//doubles up the memory allocated by a given pointer
int growMemory(void ** p, int size) {
	void * new_pointer = verifyMemory(malloc(size * 2));
	memmove(new_pointer, *p, (size_t)size);
	free(*p);
	*p = new_pointer;
	return size*2;
}
