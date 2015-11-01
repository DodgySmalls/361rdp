/** this file contains all functions which do not use global variables in the RDP/client sender, as well as all typedefs **/

#include <regex.h>

typedef enum {SYN, ACK, DAT, FIN, RST, INV} packet_intent;

typedef struct {packet_intent intent, 
				uint32_t seqno, 
				uint32_t ackno, 
				uint32_t datlen, 
				uint32_t winlen} RDP_header;

typedef struct {RDP_header header, 
				void * payload} RDP_packet;

//                           magic         _type_          _seqno_      _ackno_     _datalen_   _windowlen_
#define RDP_REGEX_LITERAL "^RDP361 \\([A-Z][A-Z][A-Z]\\) \\([0-9]*\\) \\([0-9]*\\) \\([0-9]*\\) \\([0-9]*\\)"

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
	regmatch_t groups[10]; //static size is fine because # of matched groups doesn't grow   

	//we zero the packet to ensure that if the match fails no garbage data remains
	memset(r, 0, sizeof(RDP_packet));

	regex_outcome = regexec(&RDP_regex, s, RDP_regex.re_nsub+1, groups, 0);
    if(!regex_outcome) {
    	//block each group with \0 so we can trivially read them with pointers >groups[i].rm_so
    	for (i = 1; i <= numgroups; i++) {
			groups[i].rm_eo = '\0';
		}

		r->header.intent = parsePacketIntent(groups[1].rm_so);
		//if the packet's intent was invalid we drop it
		if(r->header.intent == INV) {
			return 0;
		}

		//TODO: Error checking for values outside 2^32? 
		r->header.seqno = (uint32_t) atoi(groups[2].rm_so);
		r->header.ackno = (uint32_t) atoi(groups[3].rm_so);
		r->header.datlen = (uint32_t) atoi(groups[4].rm_so);
		r->header.winlen = (uint32_t) atoi(groups[5].rm_so);

    	return 1;
    } else {
    	//if the packet's header doesn't conform to our spec we drop it (either bad request or bits have been flipped)
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
		printError("rdputil : MALLOC FAILED TO RETURN MEMORY");
		exit(77);
	} else {
		return(p);
	}
}

//A function to uniformly handly error messages
//TODO: modularity + functionality improvement
void printError(char * s) {
	fprintf(stderr, "ERROR : %s", s);
}