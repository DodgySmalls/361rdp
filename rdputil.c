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
#include <stdarg.h>

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
				uint32_t memlen;
				uint32_t next_byte;
				uint32_t winlen;		//maximum buffer and windowsize is 2^32
			   } byte_buffer;

//                           magic      _type_             _seqno_      _ackno_     _datalen_    _windowlen_
#define RDP_REGEX_LITERAL "^RDP361 \\([a-zA-Z][a-zA-Z][a-zA-Z]\\) \\([0-9]*\\) \\([0-9]*\\) \\([0-9]*\\) \\([0-9]*\\)\n\n"
#define RDP_NUMGROUPS 5 //const number of groups in the above regex, so we just define it manually rather than searching for it iteratively

/********************************
		P2 spec mandatory: 			    
********************************/
#define MAX_PACKET_LEN 1024
//to ensure payload doesn't overflow to 4 digits (makes calculating total packet size simpler) <- all this stuff would be better if we could use packed data ...
#define MAX_RDP_PAYLOAD 999

void * verifyMemory(void *);
int growMemory(void **, int);

void printError(char *);

packet_intent parsePacketIntent(char *);
void RDPWritePacket(RDP_packet *, char *, byte_buffer *);
int RDPWritePacketHeader(RDP_packet *, char *);
int RDPLoadPacket(char * s, RDP_packet *);


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

//puts a new packet into the memory located at *r
//If you specify this as a DATA packet, the function expects a data pointer to be appended
uint32_t RDPGeneratePacket(RDP_packet * r, packet_intent pint, uint32_t seq, uint32_t ack, uint32_t datl, uint32_t winl, ...) {
	memset(r, 0, sizeof(RDP_packet)); //zero old memory
	r->header.intent = pint;
	r->header.seqno = seq;
	r->header.ackno = ack;
	r->header.winlen = winl;

	//Now we need to ensure that the payload + ASCII version of this header won't be longer than 1024
	//unpacked structure zzz...
	if(r->header.intent == DAT) {
		if(datl > MAX_RDP_PAYLOAD) {
			datl = MAX_RDP_PAYLOAD;
		}
		r->header.datlen = datl;

		char scratchspace[100];
		int ofst = RDPWritePacketHeader(r, &(scratchspace[0]));

		if(r->header.datlen > MAX_PACKET_LEN - (uint32_t) ofst) {
			r->header.datlen = MAX_PACKET_LEN - (uint32_t) ofst;
		}
	}

	//ensure that we received a pointer to some data
	if(r->header.intent == DAT) {
		va_list vl;
		va_start (vl, 1);
		r.payload = va_arg(vl, char *);
		va_end(vl);
	} else {
		r->payload = NULL;
	}
}

//writes the contents of a given RDP packet into a block of memory (* s)
//note that if r is not a data packet we can simply supply a null pointer
void RDPWritePacket(RDP_packet * r, char * s, byte_buffer * b) {
	char * payload = (s + RDPWritePacketHeader(r, s));

	//read the payload from the buffer
}

//writes the header to a given string, returns the length of the header that it wrote
int RDPWritePacketHeader(RDP_packet * r, char * s) {
	char * ss = s;
	*ss = "RDP361 ";
	ss = ss + 7;
	if(r->header.intent == DAT) {
		*ss = "DAT ";
	} else if(r->header.intent == SYN) {
		*ss = "SYN ";
	} else if(r->header.intent == ACK) {
		*ss = "ACK ";
	} else if(r->header.intent == FIN) {
		*ss = "FIN ";
	} else if(r->header.intent == RST) {
		*ss = "RST ";
	} else {
		*ss = "INV ";
	}
	ss = ss + 4;
	ss = ss + sprintf(ss, "&#37;u", r->header.seqno);
	*ss = " ";
	ss++;
	ss = ss + sprintf(ss, "&#37;u", r->header.ackno);
	*ss = " ";
	ss++;
	ss = ss + sprintf(ss, "&#37;u", r->header.datlen);
	*ss = " ";
	ss++;
	ss = ss + sprintf(ss, "&#37;u", r->header.winlen);
	*ss = "\n\n\0";
	ss = ss + 2;
	return (int) ss - s;
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