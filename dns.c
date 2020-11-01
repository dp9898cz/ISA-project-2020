/**
    @file   dns.c
    @author Daniel Pátek (xpatek08)
    @brief  VUT FIT 2020 / ISA Project variant DNS resolver
*/

// standart C stuff
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <errno.h>
// POSIX
#include <strings.h>			// bzero()
#include <signal.h>				// signal()
#include <poll.h>				// poll()
#include <netdb.h>				// gethostbyname()
// network stuff
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <linux/ip.h>
#include <netinet/udp.h>

// size for recvfrom() buffer
#define BUFFER_SIZE 1000

// verbose mode turned on/off
bool verbose = false;

//socket descriptors
int clientSocketDescritor = -1;
int serverSocketDescritor = -1;

// response from recvfrom() ->buffer ->length
struct response {
	char* buffer;
	int length;
};

// dynamicly allocated blacklist ->size ->allocated ->r
struct blacklist_s {
	unsigned long size;
	unsigned long allocated;
	char **r;
};

//global struct pointers
struct blacklist_s *blacklist;
struct response *resp;


/**
 * @fn printVerbose()
 * @brief Only print if verbose mode is turned on
 * @param string string to print
*/
void printVerbose(char * string) {
	if (verbose) {
		fprintf(stdout, "%s", string);
	}
}

/**
 * @fn clear()
 * @brief Handle for sigterm signal (for proper exiting server - free memory and close sockets)
*/
void clear() {
	printVerbose("\nClearing sockets...\n");
	//close all sockets
	if (clientSocketDescritor != -1) close(clientSocketDescritor);
	if (serverSocketDescritor != -1) close(serverSocketDescritor);
	// free blacklist
	printVerbose("Clearing blacklist...\n");
	if (blacklist != NULL) {	
		for (long unsigned i = 0; i < blacklist->size; i++) {
			free(blacklist->r[i]);
		}
		free(blacklist->r);
		free(blacklist);
	}
	//free response object
	if (resp != NULL) {
		if (resp->buffer != NULL) free(resp->buffer);
		free(resp);
	}
	exit(EXIT_SUCCESS);
}

/**
 * @fn getDnsFilter()
 * @brief Get all names from the filers file and store them to the dynamic array
 * @param name Name of the file
 * @return int 0 on success, 1 on error
*/
int getDnsFilter(char *name) {
	const unsigned ALLOC_SIZE = 20;
	const unsigned FILE_BUFFER_SIZE = 512;
	//initialize blacklist structure
	blacklist = (struct blacklist_s*)malloc(sizeof(struct blacklist_s));
	blacklist->r = malloc(ALLOC_SIZE * sizeof(char *));
	blacklist->allocated = ALLOC_SIZE;
	blacklist->size = 0;
	//initialize buffer
	char filebuf[FILE_BUFFER_SIZE], *bufPtr;
	for (unsigned int i = 0; i < FILE_BUFFER_SIZE; i++) {
		filebuf[i] = '\0';
	}
  	FILE *blacklistFile = fopen(name,"r");
	if (blacklistFile == NULL) {
		fprintf(stderr, "Error opening filter file: %s", name);
		return EXIT_FAILURE;
	}
	//start the loop
	bufPtr = fgets(filebuf, FILE_BUFFER_SIZE, blacklistFile);
	unsigned int k;
	while (bufPtr) {
		// check #
		if (bufPtr[0] == '#') {
			bufPtr = fgets(filebuf, FILE_BUFFER_SIZE, blacklistFile);
			continue;
		}
		// check the names
		for (k = 0; k < FILE_BUFFER_SIZE; k++) {
			if (filebuf[k] == '\n') { filebuf[k] = '\0';break; }
			if (filebuf[k] < ' ') { filebuf[k] = '\0'; }
			filebuf[k] &= 0x7f;
		}
		bufPtr[FILE_BUFFER_SIZE - 1] = '\0';
		if (blacklist->size == blacklist->allocated) {
			//allocate more memory
			char ** tmp;
			tmp = realloc(blacklist->r, (blacklist->allocated + ALLOC_SIZE) * sizeof(char*));
			if (!tmp) {
				fprintf(stderr, "Could not reallocate array of filer names. Not enough memory.\nProgram will continue with %lu filter names loaded.", blacklist->size);
				return EXIT_SUCCESS;
			} else {
				blacklist->r = tmp;
				blacklist->allocated += ALLOC_SIZE;
			}
		}
		// insert the name
		blacklist->r[blacklist->size++] = strdup(bufPtr);
		bufPtr = fgets(filebuf, FILE_BUFFER_SIZE, blacklistFile);
	}
	fclose(blacklistFile);
	return EXIT_SUCCESS;
}

/**
 * @fn isBlacklisted()
 * @brief Check if the given name is blacklisted.
 * @param name Address name to filter
 * @return int 1 if it is blacklisted, 0 if it in not blacklisted
*/
int isBlacklisted(char *name) {
	//search the list
	for(unsigned long i = 0; i < blacklist->size; i++) {
		if (strstr(name, blacklist->r[i])) {
			// found a match
			return 1;
		}
	}
	return 0;
}

/**
 * @fn printIp()
 * @brief Print IPv4 address in readable human-friendly form (dot notation) + print the port
 * @param ip Ip address (unsigned int)
 * @param port Port (int)
 */
void printIp(unsigned int ip, int port) {
    unsigned char bytes[4];
    bytes[0] = ip & 0xFF;
    bytes[1] = (ip >> 8) & 0xFF;
    bytes[2] = (ip >> 16) & 0xFF;
    bytes[3] = (ip >> 24) & 0xFF;   
    printf("%d.%d.%d.%d#%d\t", bytes[3], bytes[2], bytes[1], bytes[0], port);        
}

/**
 * @fn printVerboseEntry()
 * @brief Prints some packet data on new line
 * @param inIp Ip address of source
 * @param inPort Port of the source
 * @param type Form of the entry (string)
 * @param name Name of the DNS query
 * @param outIp Ip address of the destination
 * @param outPort Port of the destination
 * @param answer Bool whether to print query (0) or answer (1)
 */
void printVerboseEntry(unsigned int inIp, int inPort, char* type, char *name, unsigned int outIp, int outPort, bool answer) {
	if (answer) {
		printIp(outIp, outPort); printVerbose("\t<--\t"); printIp(inIp, inPort);
	} else {
		printIp(inIp, inPort); printVerbose("\t-->\t"); printIp(outIp, outPort);
	}
	printVerbose("\t");	printVerbose(type);	printVerbose(":\t"); printVerbose(name); printVerbose("\n");
}

/**
 * @fn getDnsRequestData()
 * @brief Get name, type and class from DNS packet
 * @param buffer DNS packet
 * @param urt Destination of the name
 * @param type Destination of the type (int)
 * @param class Destination of the class (int)
 */
void getDnsRequestData(char *buffer, char *url, int *type, int *class) {
	//first we have to skip header
	char *ptr = buffer + sizeof(HEADER);
	int sum = ptr[0];
	int offset = 0, counter = 1, counterDst = 0;
	// get name from the dns packet (according to RFC 1035)
	while(sum) {
		if(offset) url[counterDst++] = '.';
		while (counter <= offset + sum) {
			url[counterDst++] = ptr[counter++];
		}
		sum = ptr[counter];
		offset = counter++;
	}
	url[counterDst] = '\0';
	//now we can extract the type and the class (which are unsigned short number)
	unsigned short *typePtr = (unsigned short *) &(ptr[counter]);
	if (type) *type = ntohs(typePtr[0]);
	if (class) *class = ntohs(typePtr[1]);
}

/**
 * @fn printHelp()
 * @brief Prints help on stdout and exit the program
 */
void printHelp() {
	printf( "Usage: dns [options]\n"
			"	-s <ip> or <name>\n"
			"		(dns server ip)\n"
			"	-f <file>\n"
			"		(file with domains to filter)\n"
			"	[-p <port>]\n"
			"  		(local bind port, default 53)\n"
			"	[-h]\n"
			"		(print help and exit)\n"
			"	[-v]\n"
			"		(verbose mode, print status messages on stdout)\n");
	exit(EXIT_FAILURE);
}

/**
 * @fn processArgs()
 * @brief Processing command line arguments.
 * @param argc Number of arguments.
 * @param argv Array of arguments.
 * @param serverName String where to write the server name.
 * @param portNumber String to write the port number.
 * @return Integer 0 on successs, 1 on fail.
 */
int processArgs(int argc, char **argv, char *serverName, int *portNumber) {
	bool serverSelected = false, filterFileSelected = false;
	int c;
	//get the command line options
	while ((c =  getopt(argc, argv, "hvs:p:f:")) != -1) {
		switch (c) {
		case 'v':
			// verbose mode
			verbose = true;
			printVerbose("[-v] Verbose mode turned on.\n");
			break;
		case 's':;
			// server name
			//check ipv4 address (most likely to be)
			struct sockaddr_in sa;
			if (inet_pton(AF_INET, optarg, &(sa.sin_addr)) == 1) {
				//it is valid ipv4 address
				strcpy(serverName, optarg);
				serverSelected = true;
				printVerbose("[-s] Server ip selection: "); printVerbose(serverName); printVerbose("\n");
				break;
			}
			//now check the name server
			struct hostent *hp = gethostbyname(optarg);
			if (hp != NULL && hp->h_addrtype == AF_INET) {
				// found the address
				struct in_addr **address_list = (struct in_addr **)hp->h_addr_list;
				strcpy(serverName, inet_ntoa(*(address_list[0])));
				serverSelected = true;
				printVerbose("[-s] Server ip selection: "); printVerbose(serverName); printVerbose("\n");
				break;
			}
			//didnt find any valid server
			fprintf(stderr, "[-s] Server name must be valid (or valid IPv4 address).\n");
			return EXIT_FAILURE;
		case 'f':
			// filter file name
			if (getDnsFilter(optarg) == 1) {
				return EXIT_FAILURE;
			}
			filterFileSelected = true;
			if (verbose) fprintf(stderr, "[-f] Filter file name selection: %s\n", optarg);
			break;
		case 'p':;
			// port selection
			// check port number
			char* ptr = NULL;
			int port = strtol(optarg, &ptr, 10);
			if (*ptr != '\0' || ptr == optarg || port > 65535 || port < 0) {
				fprintf(stderr, "[-p] Incorrect port number (it has to be integer value from 0 to 65535).\n");
				return EXIT_FAILURE;
			}
			*portNumber = port;
			if (verbose) fprintf(stderr, "[-p] Port selection: %d\n", port);
			break;
		case 'h':
		default:
			//print help
			printHelp();
		}
	}
	if (!serverSelected) {
		fprintf(stderr, "[-s] You have to input server name.\n");
		return EXIT_FAILURE;
	}
	if (!filterFileSelected) {
		fprintf(stderr, "[-f] You have to input name of filter table.\n");
		return EXIT_FAILURE;
	}
	return EXIT_SUCCESS;
}


int main(int argc, char **argv) {
	char serverName[20] = "";
	int portNumber = 53;
	if (argc < 2) {
		printHelp();
	}
	//check and process params
	if (processArgs(argc, argv, serverName, &portNumber)) {
		return EXIT_FAILURE;
	}
	//bind signals to end properly (cleaning sockets)
	signal(SIGINT, clear);
    signal(SIGQUIT, clear);
    signal(SIGTERM, clear);

	//opening socket for client incoming questions and client answers
	clientSocketDescritor = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (clientSocketDescritor == -1) {
		fprintf(stderr, "Could not create a new client socket: %s\n", strerror(errno));
		return EXIT_FAILURE;
	}
	struct sockaddr_in clientListenAddress;
	bzero(&clientListenAddress, sizeof(struct sockaddr_in));
	clientListenAddress.sin_family = AF_INET;
	clientListenAddress.sin_port = htons(portNumber);
	clientListenAddress.sin_addr.s_addr = INADDR_ANY;
	if (bind(clientSocketDescritor, (const struct sockaddr *) &clientListenAddress, sizeof(clientListenAddress)) == -1) {
		fprintf(stderr, "Could not bind a client listen socket. %s\n", strerror(errno));
		close(clientSocketDescritor);
		return EXIT_FAILURE;
	}

	//opening socket for server incoming questions and server answers
	serverSocketDescritor = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (serverSocketDescritor == -1) {
		fprintf(stderr, "Could not create a new server socket: %s\n", strerror(errno));
		close(clientSocketDescritor);
		return EXIT_FAILURE;
	}
	struct sockaddr_in serverAddress;
	bzero(&serverAddress, sizeof(struct sockaddr_in));
	serverAddress.sin_family = AF_INET;
	serverAddress.sin_port = htons(0);
	serverAddress.sin_addr.s_addr = INADDR_ANY;
	if (bind(serverSocketDescritor, (const struct sockaddr *) &serverAddress, sizeof(serverAddress)) == -1) {
		fprintf(stderr, "Could not bind a server socket. %s\n", strerror(errno));
		close(serverSocketDescritor);
		close(clientSocketDescritor);
		return EXIT_FAILURE;
	}
	//change the server address in order to send correct queries
	serverAddress.sin_port = htons(53);
	serverAddress.sin_addr.s_addr = inet_addr(serverName);

	//create shared dns header
	HEADER dnsHeader;
	// shared dns response object (buffer and length)
	resp = (struct response *)malloc(sizeof(struct response));
	resp->buffer = malloc(BUFFER_SIZE);
	//temp address to find out client port
	struct sockaddr_in clientAddress;
	socklen_t clientAddressLength = sizeof(clientAddress);
	socklen_t serverAddressLength = sizeof(serverAddress);
	// counting the port numbers and IDs in order to manage more request at the same time
	unsigned short ports[32], ids[32], portsCounter = 0;
	unsigned int addresses[32];
	for(int i = 0; i<32;i++) {
		ports[i] = 0; ids[i] = 0; addresses[i] = 0;
	}

	//create structure for poll
	struct pollfd fds[2];
	fds[0].fd = serverSocketDescritor;
	fds[1].fd = clientSocketDescritor;
	fds[0].events = POLL_IN;
	fds[1].events = POLL_IN;

	while(1) {
		//first have to check both sockets for connection
		if (poll(fds, 2, -1) == -1) {
			fprintf(stderr, "Unable to poll descriptors. Poll: %s\n", strerror(errno));
			clear();
		}
		//client question
		if (fds[1].revents & POLLIN) {
			resp->length = recvfrom(clientSocketDescritor, resp->buffer, BUFFER_SIZE, MSG_WAITALL, (struct sockaddr *) &clientAddress, &clientAddressLength);
			if (resp->length < 0) {
				fprintf(stderr, "Not able to receive packet. Recvfrom: %s\n", strerror(errno));
				continue;
			}
			//get the DNS header
			memcpy(&dnsHeader, resp->buffer, 12);
			// check correct bits for query
			bool badPacket = false;
			if (dnsHeader.qr != 0 || dnsHeader.unused != 0 || dnsHeader.cd != 0 || dnsHeader.qdcount <= 0 || dnsHeader.ancount > 0) { 
				badPacket = true;
			}
			//get data from dns packet
			char name[512];
			int type = 0, class = 0;
			if (!badPacket) {
				getDnsRequestData(resp->buffer, &name[0], &type, &class);
			}
			//this is bad dns packet (format error)
			if (type <= 0 || class <= 0 || badPacket) {
				printVerboseEntry(ntohl(clientAddress.sin_addr.s_addr), ntohs(clientAddress.sin_port), "format error", "unknown name", 
					ntohl(clientAddress.sin_addr.s_addr), ntohs(clientAddress.sin_port), false);
				fprintf(stderr, "Wrong query received, sending RCODE=1 (format error).\n"); 
				//change the answer
				dnsHeader.qr = 1; // response flag
				dnsHeader.aa = 1; // authoritive answer
				dnsHeader.ra = 1; // recursion available
				dnsHeader.rcode = 1; // response code (FORMAT ERROR)
				dnsHeader.ancount = 0; // number of answer queries
				dnsHeader.nscount = 0; // number of authority entries
				memcpy(resp->buffer, &dnsHeader, 12);
				if (sendto(clientSocketDescritor, resp->buffer, resp->length, 0, (struct sockaddr *) &clientAddress, clientAddressLength) < 0) {
					fprintf(stderr, "Error sending packet.\n");
				}
				continue;
			}
			// this is not implemented
			if (type != 1 || class != 1) {
				printVerboseEntry(ntohl(clientAddress.sin_addr.s_addr), ntohs(clientAddress.sin_port), "not implemented", name, 
					ntohl(clientAddress.sin_addr.s_addr), ntohs(clientAddress.sin_port), false);
				fprintf(stderr, "Function not implemented, sending RCODE=4 (not implemented error).\n"); 
				//change the answer
				dnsHeader.qr = 1; // response flag
				dnsHeader.aa = 1; // authoritive answer
				dnsHeader.ra = 1; // recursion available
				dnsHeader.rcode = 4; // response code (NOT IMPLEMENTED)
				dnsHeader.ancount = 0; // number of answer queries
				dnsHeader.nscount = 0; // number of authority entries
				memcpy(resp->buffer, &dnsHeader, 12);
				if (sendto(clientSocketDescritor, resp->buffer, resp->length, 0, (struct sockaddr *) &clientAddress, clientAddressLength) < 0) {
					fprintf(stderr, "Error sending packet.\n");
				}
				continue;
			}
			//check blacklist
			if (isBlacklisted(name)) {
				printVerboseEntry(ntohl(clientAddress.sin_addr.s_addr), ntohs(clientAddress.sin_port), "blacklisted", name, 
					ntohl(clientAddress.sin_addr.s_addr), ntohs(clientAddress.sin_port), false);
				//change the answer
				dnsHeader.qr = 1; // response flag
				dnsHeader.aa = 1; // authoritive answer
				dnsHeader.ra = 1; // recursion available
				dnsHeader.rcode = 5; // response code (REFUSED)
				dnsHeader.ancount = 0; // number of answer queries
				dnsHeader.nscount = 0; // number of authority entries
				memcpy(resp->buffer, &dnsHeader, 12);
				if (sendto(clientSocketDescritor, resp->buffer, resp->length, 0, (struct sockaddr *) &clientAddress, clientAddressLength) < 0) {
					fprintf(stderr, "Error sending packet.\n");
				}
				continue;
			}
			//save port and id
			ports[portsCounter] = clientAddress.sin_port;
			ids[portsCounter] = ntohs(dnsHeader.id);
			addresses[portsCounter] = clientAddress.sin_addr.s_addr;
			//roll and again to first element
			portsCounter++;
			if (portsCounter == 31) portsCounter = 0;
			printVerboseEntry(ntohl(clientAddress.sin_addr.s_addr), ntohs(clientAddress.sin_port), "query", name, 
					ntohl(serverAddress.sin_addr.s_addr), ntohs(serverAddress.sin_port), false);
			if (sendto(serverSocketDescritor, resp->buffer, resp->length, 0, (struct sockaddr *) &serverAddress, serverAddressLength) < 0) {
					fprintf(stderr, "Error sending packet.\n");
			}
		}
		//server answer
		if (fds[0].revents & POLLIN) {
			//temp address to find out if its good answer
			struct sockaddr_in tmpAddress;
			bzero(&tmpAddress, sizeof(struct sockaddr_in));
			socklen_t tmpLen = sizeof(struct sockaddr_in);
			resp->length = recvfrom(serverSocketDescritor, resp->buffer, BUFFER_SIZE, MSG_WAITALL, (struct sockaddr *) &tmpAddress, &tmpLen);
			if (resp->length < 0) {
				fprintf(stderr, "Not able to receive packet. Recvfrom: %s\n", strerror(errno));
				continue;
			}
			//check the ip and port
			if (tmpAddress.sin_port != serverAddress.sin_port || tmpAddress.sin_addr.s_addr != serverAddress.sin_addr.s_addr) {
				fprintf(stderr, "Answer from unexpected source.\n");
			}
			memcpy(&dnsHeader, resp->buffer, 12);
			// get name (for verbose only)
			char tmpName[512];
			getDnsRequestData(resp->buffer, &tmpName[0], NULL, NULL);
			//check which port and address to send it (according to ID)
			for(int i = 0; i < 32; i++) {
				if (ids[i] == ntohs(dnsHeader.id)) {
					clientAddress.sin_port = ports[i];
					clientAddress.sin_addr.s_addr = addresses[i];
					printVerboseEntry(ntohl(tmpAddress.sin_addr.s_addr), ntohs(tmpAddress.sin_port), "answer", tmpName, 
						ntohl(clientAddress.sin_addr.s_addr), ntohs(clientAddress.sin_port), true);
					sendto(clientSocketDescritor, resp->buffer, resp->length, 0, (struct sockaddr *) &clientAddress, clientAddressLength);
					break;
				}
			}
			// if ID is not found -> throw it away
		}
	}
	return 0;
}