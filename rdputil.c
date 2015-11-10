/** this file contains all functions which do not use global variables in the RDP/client sender, as well as all typedefs **/

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

#include <regex.h>

typedef enum {SYN, ACK, DAT, FIN, RST, INV} packet_intent;

typedef struct {packet_intent intent;
				uint32_t seqno;
				uint32_t ackno;
				uint32_t datlen; 
				uint32_t winlen;
			   } RDP_header;

//a logical container for RDP_header,
typedef struct {RDP_header header;
				char * payload;
			   } RDP_packet;

typedef struct {char * mem;
				uint32_t next_byte;
				uint32_t winlen;		//maximum buffer and windowsize is 2^32
			   } byte_buffer;

//                           magic      _type_             _seqno_      _ackno_     _datalen_    _windowlen_
#define RDP_REGEX_LITERAL "^RDP361 \\([a-zA-Z][a-zA-Z][a-zA-Z]\\) \\([0-9]*\\) \\([0-9]*\\) \\([0-9]*\\) \\([0-9]*\\)\n\n"
#define RDP_NUMGROUPS 5 //const number of groups in the above regex, so we just define it manually rather than searching for it iteratively

void * verifyMemory(void *);
void printError(char *);
packet_intent parsePacketIntent(char *);
int RDPLoadPacket(char * s, RDP_packet *);
int growMemory(void **, int);

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
// if match is successful the string passed is destroyed, and data is pushed into the given RDP_packet, returns 1
// if match is unsuccessful returns 0
int RDPLoadPacket(char * s, RDP_packet * r) {
	int i;
	int regex_outcome;
	regex_t RDP_regex;
	regmatch_t groups[10]; //const size is fine because # of matched groups doesn't grow

	uint8_t * pdat;

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

		r->header.intent = parsePacketIntent(&s[groups[1].rm_so]);
		//if the packet's intent was invalid we drop it
		if(r->header.intent == INV) {
			return 0;
		}

		//TODO: Error checking for values outside 2^32? 
		r->header.seqno = (uint32_t) atoi(&s[groups[2].rm_so]);
		r->header.ackno = (uint32_t) atoi(&s[groups[3].rm_so]);
		r->header.datlen = (uint32_t) atoi(&s[groups[4].rm_so]);
		r->header.winlen = (uint32_t) atoi(&s[groups[5].rm_so]);

		//expressions are matched IFF 000\n\n is present, ' datlen ' bytes after are considered data.
		pdat = (uint8_t *) &(s[groups[5].rm_eo+2]);

		//right now ' pdat ' points to memory we will want to re-use for other packets (a buffer), so we malloc new memory to store the payload
		//' datlen ' is bytesize, but we need one extra byte for the string end character
		r->payload = (uint8_t *) verifyMemory(malloc(r->header.datlen + 1)); 
		memmove(r->payload, pdat, r->header.datlen);
		r->payload[r->header.datlen] = (uint8_t) '\0';

    	return 1;
    } else {
    	//if the packet's header doesn't conform to our spec we drop it (either badly formed request or bits have been flipped)
    	return 0;
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

//A function to uniformly handly error messages
//TODO: modularity + functionality improvement
void printError(char * s) {
	fprintf(stderr, "ERROR : %s\n", s);
}