
/*
	Simple Sniffer in winsock
	Author : Silver Moon ( m00n.silv3r@gmail.com )
*/

#include "stdio.h"
#include "winsock2.h"

#pragma comment(lib,"ws2_32.lib") //For winsock

#define SIO_RCVALL _WSAIOW(IOC_VENDOR,1) //this removes the need of mstcpip.h

#define SCAN -1
#define OPEN 1
#define CLOSED 2
#define FILTERED 3

void StartSniffing (SOCKET Sock); //This will sniff here and there

void ProcessPacket (char* , int); //This will decide how to digest
void PrintIpHeader (char*);
void PrintIcmpPacket (char* , int);
void PrintUdpPacket (char* , int);
void PrintTcpPacket (char* , int);
void ConvertToHex (char* , unsigned int);
void PrintData (char* , int);

typedef struct ip_hdr
{
	unsigned char ip_header_len:4; // 4-bit header length (in 32-bit words) normally=5 (Means 20 Bytes may be 24 also)
	unsigned char ip_version :4; // 4-bit IPv4 version
	unsigned char ip_tos; // IP type of service
	unsigned short ip_total_length; // Total length
	unsigned short ip_id; // Unique identifier

	unsigned char ip_frag_offset :5; // Fragment offset field

	unsigned char ip_more_fragment :1;
	unsigned char ip_dont_fragment :1;
	unsigned char ip_reserved_zero :1;

	unsigned char ip_frag_offset1; //fragment offset

	unsigned char ip_ttl; // Time to live
	unsigned char ip_protocol; // Protocol(TCP,UDP etc)
	unsigned short ip_checksum; // IP checksum
	unsigned int ip_srcaddr; // Source address
	unsigned int ip_destaddr; // Source address
} IPV4_HDR;

// TCP header
typedef struct tcp_header
{
	unsigned short source_port; // source port
	unsigned short dest_port; // destination port
	unsigned int sequence; // sequence number - 32 bits
	unsigned int acknowledge; // acknowledgement number - 32 bits

	unsigned char ns :1; //Nonce Sum Flag Added in RFC 3540.
	unsigned char reserved_part1:3; //according to rfc
	unsigned char data_offset:4; /*The number of 32-bit words in the TCP header.
	This indicates where the data begins.
	The length of the TCP header is always a multiple
	of 32 bits.*/

	unsigned char fin :1; //Finish Flag
	unsigned char syn :1; //Synchronise Flag
	unsigned char rst :1; //Reset Flag
	unsigned char psh :1; //Push Flag
	unsigned char ack :1; //Acknowledgement Flag
	unsigned char urg :1; //Urgent Flag

	unsigned char ecn :1; //ECN-Echo Flag
	unsigned char cwr :1; //Congestion Window Reduced Flag

	////////////////////////////////

	unsigned short window; // window
	unsigned short checksum; // checksum
	unsigned short urgent_pointer; // urgent pointer
} TCP_HDR;


FILE *logfile;
int tcp=0,udp=0,icmp=0,others=0,igmp=0,total=0,i,j;
struct sockaddr_in source,dest;
char hex[2];

//Its free!
IPV4_HDR *iphdr;
TCP_HDR *tcpheader;
int ports[65536];
char * target;

int * startSniffer(char * targetToScan, int * portsToScan, char * myIP)
{
	target = targetToScan;
	for (int i = 0; i < sizeof(portsToScan) / sizeof(portsToScan[0]); i++)
		ports[portsToScan[i]] = SCAN;

	SOCKET sniffer;
	struct in_addr addr;
	int in;

	struct hostent *local;
	WSADATA wsa;

	//Initialise Winsock
	printf("\nInitialising Winsock...");
	if (WSAStartup(MAKEWORD(2,2), &wsa) != 0)
	{
		printf("WSAStartup() failed.\n");
		return 1;
	}
	printf("Initialised");

	//Create a RAW Socket
	printf("\nCreating RAW Socket...");
	sniffer = socket(AF_INET, SOCK_RAW, IPPROTO_IP);
	if (sniffer == INVALID_SOCKET)
	{
		printf("Failed to create raw socket.\n");
		return 1;
	}
	printf("Created.");

	memset(&dest, 0, sizeof(dest));
	memcpy(&dest.sin_addr.s_addr, myIP, sizeof(dest.sin_addr.s_addr));
	dest.sin_family = AF_INET;
	dest.sin_port = 0;

	printf("\nBinding socket to local system and port 0 ...");
	if (bind(sniffer,(struct sockaddr *)&dest,sizeof(dest)) == SOCKET_ERROR)
	{
		printf("bind(%s) failed.\n", inet_ntoa(addr));
		return 1;
	}
	printf("Binding successful");

	//Enable this socket with the power to sniff : SIO_RCVALL is the key Receive ALL ;)

	j=1;
	printf("\nSetting socket to sniff...");
	if (WSAIoctl(sniffer, SIO_RCVALL, &j, sizeof(j), 0, 0, (LPDWORD) &in , 0 , 0) == SOCKET_ERROR)
	{
		printf("WSAIoctl() failed.\n");
		return 1;
	}
	printf("Socket set.");

	//Begin
	printf("\nStarted Sniffing\n");
	printf("Packet Capture Statistics...\n");
	StartSniffing(sniffer); //Happy Sniffing

	//End
	closesocket(sniffer);
	WSACleanup();

	return 0;
}

void StartSniffing(SOCKET sniffer)
{
	char *Buffer = (char *)malloc(65536); //Its Big!
	int mangobyte;

	if (Buffer == NULL)
	{
		printf("malloc() failed.\n");
		return;
	}

	do
	{
		mangobyte = recvfrom(sniffer , Buffer , 65536 , 0 , 0 , 0); //Eat as much as u can

		if(mangobyte > 0)
		{
			ProcessPacket(Buffer, mangobyte);
		}
		else
		{
			printf( "recvfrom() failed.\n");
		}
	}
	while (mangobyte > 0);

	free(Buffer);
}

int countOpenPorts = 0, countClosedPorts = 0;

void ProcessPacket(char* Buffer, int Size)
{
	iphdr = (IPV4_HDR *)Buffer;
	++total;

	switch (iphdr->ip_protocol) //Check the Protocol and do accordingly...
	{
		case 6: //TCP Protocol
		++tcp;
		PrintTcpPacket(Buffer,Size);
		break;
	}
	// printf("Scanned: %d\r", countClosedPorts + countOpenPorts);
}


void PrintTcpPacket(char* Buffer, int Size)
{
	// unsigned short iphdrlen;

	// iphdr = (IPV4_HDR *)Buffer;
	// iphdrlen = iphdr->ip_header_len*4;

	// tcpheader=(TCP_HDR*)(Buffer+iphdrlen);

    
    unsigned short iphdrlen;

	iphdr = (IPV4_HDR *)Buffer;
	iphdrlen = iphdr->ip_header_len*4;

	memset(&source, 0, sizeof(source));
	source.sin_addr.s_addr = iphdr->ip_srcaddr;

	memset(&dest, 0, sizeof(dest));
	dest.sin_addr.s_addr = iphdr->ip_destaddr;

    if (!strcmp(inet_ntoa(source.sin_addr), target))
    {
		if(ports[ntohs(tcpheader->source_port)] == 0)
			return;

        tcpheader=(TCP_HDR*)(Buffer+iphdrlen);
        if ((unsigned int)tcpheader->ack == 1 && (ports[ntohs(tcpheader->source_port)] == SCAN || ports[ntohs(tcpheader->source_port)] == FILTERED))
        {
            if ((unsigned int)tcpheader->syn == 1)
            {
                ports[ntohs(tcpheader->source_port)] = OPEN;
                fprintf(logfile, "Port %d is Open\n", ntohs(tcpheader->source_port));
                countOpenPorts++;
            }
            else if((unsigned int)tcpheader->rst == 1)
            {
                ports[ntohs(tcpheader->source_port)] = CLOSED;
                countClosedPorts++;
                // fprintf(logfile, "Port %d is Closed\n", ntohs(tcpheader->source_port));
            }
			else
			{
				ports[ntohs(tcpheader->source_port)] = FILTERED;
				/* code */
			}
			
        }
        if((countClosedPorts + countOpenPorts) == 65535)
        {
            printf("Scanned all fucking ports!\n");
            exit(0);
        }
        // fprintf(logfile," |-CWR Flag : %d\n",(unsigned int)tcpheader->cwr);
        // fprintf(logfile," |-ECN Flag : %d\n",(unsigned int)tcpheader->ecn);
        // fprintf(logfile," |-Urgent Flag : %d\n",(unsigned int)tcpheader->urg);
        // fprintf(logfile," |-Acknowledgement Flag : %d\n",(unsigned int)tcpheader->ack);
        // fprintf(logfile," |-Push Flag : %d\n",(unsigned int)tcpheader->psh);
        // fprintf(logfile," |-Reset Flag : %d\n",(unsigned int)tcpheader->rst);
        // fprintf(logfile," |-Synchronise Flag : %d\n",(unsigned int)tcpheader->syn);
        // fprintf(logfile," |-Finish Flag : %d\n",(unsigned int)tcpheader->fin);
        // fprintf(logfile," |-Window : %d\n",ntohs(tcpheader->window));
        // fprintf(logfile," |-Checksum : %d\n",ntohs(tcpheader->checksum));
        // fprintf(logfile," |-Urgent Pointer : %d\n",tcpheader->urgent_pointer);
        // fprintf(logfile,"\n");
        // fprintf(logfile," DATA Dump ");
        // fprintf(logfile,"\n");

        // fprintf(logfile,"IP Header\n");
        // PrintData(Buffer,iphdrlen);

        // fprintf(logfile,"TCP Header\n");
        // PrintData(Buffer+iphdrlen,tcpheader->data_offset*4);

        // fprintf(logfile,"Data Payload\n");
        // PrintData(Buffer+iphdrlen+tcpheader->data_offset*4
        // ,(Size-tcpheader->data_offset*4-iphdr->ip_header_len*4));

        // fprintf(logfile,"\n###########################################################");
    }
}

/*
	Print the hex values of the data
*/
void PrintData (char* data , int Size)
{
	char a , line[17] , c;
	int j;

	//loop over each character and print
	for(i=0 ; i < Size ; i++)
	{
		c = data[i];

		//Print the hex value for every character , with a space. Important to make unsigned
		fprintf(logfile," %.2x", (unsigned char) c);

		//Add the character to data line. Important to make unsigned
		a = ( c >=32 && c <=128) ? (unsigned char) c : '.';

		line[i%16] = a;

		//if last character of a line , then print the line - 16 characters in 1 line
		if( (i!=0 && (i+1)%16==0) || i == Size - 1)
		{
			line[i%16 + 1] = '\0';

			//print a big gap of 10 characters between hex and characters
			fprintf(logfile ,"          ");

			//Print additional spaces for last lines which might be less than 16 characters in length
			for( j = strlen(line) ; j < 16; j++)
			{
				fprintf(logfile , "   ");
			}

			fprintf(logfile , "%s \n" , line);
		}
	}

	fprintf(logfile , "\n");
}