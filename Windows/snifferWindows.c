
/*
	Simple Sniffer in winsock
	Author : Silver Moon ( m00n.silv3r@gmail.com )
*/

#include <stdio.h>
#include <windows.h>
#include <winsock2.h>
#include <WS2tcpip.h>

#pragma comment(lib,"ws2_32.lib") //For winsock

#define SIO_RCVALL _WSAIOW(IOC_VENDOR,1) //this removes the need of mstcpip.h

#define SCAN -1
#define OPEN 1
#define CLOSED 2
#define SCANNED 3

// #define RED   "\033[31m"
// #define GRN   "\033[32m"
// #define YEL   "\033[33m"
// #define RESET "\033[0m"

static const char YEL[] = "\033[0;33m";
static const char RED[] = "\033[0;31m";
static const char GRN[] = "\033[0;32m";
static const char RESET[] = "\033[0m";

int startSniffer(char * targetToScan, int * portsToScan, int size, char * myIP); // Main export for Nim
void StartSniffing (SOCKET Sock); //This will sniff here and there
void ProcessPacket (char* , int); //This will decide how to digest
void PrintTcpPacket (char* , int);

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


int j;
struct sockaddr_in source,dest;
char hex[2];

//Its free!
IPV4_HDR *iphdr;
TCP_HDR *tcpheader;
int ports[65536];
char * target;
char * my_ip;
int scanned = 0, toScan = 0, countOpenPorts = 0, countClosedPorts = 0, countFilteredPorts = 0;
int dst_port, src_port;
char * dst;
char * src;
DWORD timeout = 0;

// Main sniffer
int startSniffer(char * targetToScan, int * portsToScan, int size, char * myIP)
{
	target = targetToScan;
	my_ip = myIP;
	for (int i = 0; i < (size * 2); i++)
	{
		// printf("%d\n", portsToScan[i]);
		if (portsToScan[i] != 0)
		{
			// printf("%d\n", portsToScan[i]);
			ports[portsToScan[i]] = SCAN;
			toScan++;
		}
	}

	SOCKET sniffer;
	struct in_addr addr;
	int in;

	struct hostent *local;
	WSADATA wsa;

	//Initialise Winsock
	// printf("\nInitialising Winsock...");
	if (WSAStartup(MAKEWORD(2,2), &wsa) != 0)
	{
		printf("WSAStartup() failed.\n");
		return 1;
	}
	// printf("Initialised");

	//Create a RAW Socket
	// printf("\nCreating RAW Socket...");
	sniffer = socket(AF_INET, SOCK_RAW, IPPROTO_IP);
	if (sniffer == INVALID_SOCKET)
	{
		printf("Failed to create raw socket.\n");
		return 1;
	}
	// printf("Created.");

	struct sockaddr_in sa;
	inet_pton(AF_INET, my_ip, &(sa.sin_addr));

	memset(&dest, 0, sizeof(dest));
	memcpy(&dest.sin_addr.s_addr, &sa.sin_addr.s_addr, sizeof(dest.sin_addr.s_addr));
	dest.sin_family = AF_INET;
	dest.sin_port = 0;

	// printf("\nBinding socket to local system and port 0 ...");
	if (bind(sniffer,(struct sockaddr *)&dest,sizeof(dest)) == SOCKET_ERROR)
	{
		printf("bind(%s) failed.\n", inet_ntoa(addr));
		return 1;
	}
	// printf("Binding successful");

	//Enable this socket with the power to sniff : SIO_RCVALL is the key Receive ALL ;)

	j=1;
	// printf("\nSetting socket to sniff...");
	if (WSAIoctl(sniffer, SIO_RCVALL, &j, sizeof(j), 0, 0, (LPDWORD) &in , 0 , 0) == SOCKET_ERROR)
	{
		printf("WSAIoctl() failed.\n");
		return 1;
	}
	// printf("Socket set.");

	//Begin
	// printf("\nStarted Sniffing\n");
	// printf("Packet Capture Statistics...\n");
	StartSniffing(sniffer); //Happy Sniffing

	//End
	closesocket(sniffer);
	WSACleanup();

	return 0;
}

void StartSniffing(SOCKET sniffer)
{
	// char *Buffer = (char *)malloc(65536); //Its Big!
	char Buffer[65536];
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
			printf("Scanned: %d from: %d ports\r", scanned, toScan);
			if(scanned == toScan)
			{	
				// printf("Time elapsed: %d\n", (GetTickCount() - timeout) / 1000);
				if(timeout == 0)
				{
					timeout = GetTickCount();
				}
				else if(((GetTickCount() - timeout) / 1000) > 0.5)
				{
					for(int i = 1; i < 65536; i++)
						if(ports[i] == SCANNED || ports[i] == SCAN)
							countFilteredPorts++;
					for(int i = 1; i < 65536; i++)
					{	
						if (countFilteredPorts <= 10)
							if(ports[i] == SCANNED || ports[i] == SCAN)
								printf("%d %s%s%s\n", i, YEL, "filtered", RESET);		
					}
					if (countFilteredPorts > 10)
						printf("\n%d ports are %sfiltered%s\n", countFilteredPorts, YEL, RESET);
					if (countClosedPorts > 10)
						printf("\n%d ports are %sclosed%s\n", countClosedPorts, RED, RESET);
					printf("Number of open ports: %d\n", countOpenPorts);
					break;
				}
			}
			
			ProcessPacket(Buffer, mangobyte);
		}
		else
		{
			printf( "recvfrom() failed.\n");
		}
	}
	while (mangobyte > 0);

	// free(Buffer);
}

void ProcessPacket(char* Buffer, int Size)
{
	iphdr = (IPV4_HDR *)Buffer;

	switch (iphdr->ip_protocol) //Check the Protocol and do accordingly...
	{
		case 6: //TCP Protocol
		PrintTcpPacket(Buffer,Size);
		break;
	}
	// printf("Scanned: %d\r", scanned);
}

void PrintTcpPacket(char* Buffer, int Size)
{
    unsigned short iphdrlen;

	iphdr = (IPV4_HDR *)Buffer;
	iphdrlen = iphdr->ip_header_len*4;

	tcpheader=(TCP_HDR*)(Buffer+iphdrlen);

	memset(&source, 0, sizeof(source));
	source.sin_addr.s_addr = iphdr->ip_srcaddr;

	memset(&dest, 0, sizeof(dest));
	dest.sin_addr.s_addr = iphdr->ip_destaddr;

	// strcpy(dst, inet_ntoa(dest.sin_addr));
	// strcpy(src, inet_ntoa(source.sin_addr));

	dst = strdup(inet_ntoa(dest.sin_addr));
	src = strdup(inet_ntoa(source.sin_addr));
	dst_port = ntohs(tcpheader->dest_port);
	src_port = ntohs(tcpheader->source_port);

	// printf("%s:%d Sent to %s:%d\n", src, src_port, dst, dst_port);

	

	// Check if sent SYN to target
	if(!strcmp(dst, target))
	{
		// printf("%s Sent %d to %s\n", src, dst_port, dst);
		if ((unsigned int)tcpheader->syn == 1 && ports[dst_port] == SCAN)
		{
			// printf("%s scanned %d\n", src, dst_port);
			ports[dst_port] = SCANNED;
			scanned++;
		}
	}

	// Check if got answer
    else if (!strcmp(src, target))
    {
		// printf("%s Sent %d to %s\n", src, src_port, dst);
		if(ports[src_port] == 0)
			return;

        if ((unsigned int)tcpheader->ack == 1 && (ports[src_port] == SCAN || ports[src_port] == SCANNED))
        {
            if ((unsigned int)tcpheader->syn == 1)
            {
                ports[src_port] = OPEN;
				printf("%d %sOpen%s\n", src_port, GRN, RESET);
                countOpenPorts++;
            }
            else if((unsigned int)tcpheader->rst == 1)
            {
                ports[src_port] = CLOSED;
				if (toScan <= 10) 
					printf("%d %sClosed%s\n", src_port, RED, RESET);
                countClosedPorts++;
            }			
        }
    }

	free(dst);
	free(src);

}

// int main()
// {
// 	printf(GRN);
// 	printf("HI\n");
// 	printf(RESET);
// 	char target[] = "192.168.1.21";
// 	char host[] = "192.168.1.24";
// 	int ports[] = {1, 2, 3, 4, 5, 6, 7, 8, 9 , 10};
// 	startSniffer(target, ports, 10, host);
// }