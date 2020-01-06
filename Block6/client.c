#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <stdio.h>
#include <time.h>
#define MAX 500
#define BUFSIZE 20
#define PRINT_OPTION 1
#define PORT "123"
#define NTP_TIMESTAMP_DELTA 2208988800ull
#define BYTE_TO_BINARY_PATTERN "%c%c%c%c%c%c%c%c"
#define BYTE_TO_BINARY(byte)  \
  (byte & 0x80 ? '1' : '0'), \
  (byte & 0x40 ? '1' : '0'), \
  (byte & 0x20 ? '1' : '0'), \
  (byte & 0x10 ? '1' : '0'), \
  (byte & 0x08 ? '1' : '0'), \
  (byte & 0x04 ? '1' : '0'), \
  (byte & 0x02 ? '1' : '0'), \
  (byte & 0x01 ? '1' : '0')


/*--------------------------------------------------------------------------------------------------------*/
//GLOBAL VARIABLES
typedef struct ntp_packet{

    uint8_t li;                         // li.   Two bits.   Leap indicator.
    uint8_t vn;                         // vn.   Three bits. Version number of the protocol. f.e. 4
    uint8_t mode;                       // mode. Three bits. Client will pick mode 3 for client.

    uint8_t stratum;                    // Eight bits. Stratum level of the local clock.
    uint8_t poll;                       // Eight bits. Maximum interval between successive messages.
    uint8_t precision;                  // Eight bits. Precision of the local clock.

    uint32_t rootDelay;                 // 32 bits. Total round trip delay time.
    uint32_t rootDispersion;            // 32 bits. Max error aloud from primary clock source.
    uint32_t refId;                     // 32 bits. Reference clock identifier.

    uint32_t referenceTimestamp_s;      // 32 bits. Reference time-stamp seconds.
    uint32_t referenceTimestamp_f;      // 32 bits. Reference time-stamp fraction of a second.

    uint32_t originTimestamp_s;         // 32 bits. Originate time-stamp seconds.
    uint32_t originTimestamp_f;         // 32 bits. Originate time-stamp fraction of a second.

    uint32_t receiveTimestamp_s;        // 32 bits. Received time-stamp seconds.
    uint32_t receiveTimestamp_f;        // 32 bits. Received time-stamp fraction of a second.

    uint32_t transmitTimestamp_s;       // 32 bits and the most important field the client cares about. Transmit time-stamp seconds.
    uint32_t transmitTimestamp_f;       // 32 bits. Transmit time-stamp fraction of a second.

} ntp_packet;                           // Total: 384 bits or 48 bytes.

//struct ntp_packet * packet_struct;



/*--------------------------------------------------------------------------------------------------------*/
//Function gets the byte array that was send from the server and puts the values into a struct of type ntp_packet.
//We used pointer arithmetic to get the values
struct ntp_packet * unmarshal(char * in_packet){
    struct ntp_packet * packet_struct = malloc(sizeof(ntp_packet));
    packet_struct->li=in_packet[0]>>6;
    packet_struct->vn=(in_packet[0]>>3)&7;
    packet_struct->mode=in_packet[0]&7;

    packet_struct->stratum = in_packet[1];
    packet_struct->poll = in_packet[2];
    packet_struct->precision = in_packet[3];

    memcpy(packet_struct->rootDelay, in_packet+4, sizeof(u_int32_t));
    memcpy(packet_struct->rootDispersion, in_packet+8, sizeof(u_int32_t));
    memcpy(packet_struct->refId, in_packet+12, sizeof(u_int32_t));
    memcpy(packet_struct->receiveTimestamp_s, in_packet+16, sizeof(u_int32_t));
    memcpy(packet_struct->receiveTimestamp_f, in_packet+20, sizeof(u_int32_t));
    memcpy(packet_struct->originTimestamp_s, in_packet+24, sizeof(u_int32_t));
    memcpy(packet_struct->originTimestamp_f, in_packet+28, sizeof(u_int32_t));
    memcpy(packet_struct->receiveTimestamp_s, in_packet+32, sizeof(u_int32_t));
    memcpy(packet_struct->receiveTimestamp_f, in_packet+36, sizeof(u_int32_t));
    memcpy(packet_struct->transmitTimestamp_s, in_packet+40, sizeof(u_int32_t));
    memcpy(packet_struct->transmitTimestamp_f, in_packet+44, sizeof(u_int32_t));

    return packet_struct;
}

/*--------------------------------------------------------------------------------------------------------*/

char* marshal(uint8_t vn, u_int8_t mode){
    char * packet_stream = malloc(48*sizeof(char));   //marshalled information, size is 384 bits or 48 bytes
    ntp_packet packet = { 0, 0, 0, 0, 0, 0, 0, 0,
                          0, 0, 0, 0,
                          0, 0, 0 };
    memset( &packet, 0, sizeof( ntp_packet ) );
    packet.vn = vn;
    packet.mode = mode;

    uint8_t meta = (vn<<6)|(vn<<3)|(mode);

    memcpy(packet_stream,&meta,1);
    memcpy(packet_stream+1,&packet.stratum,1);
    memcpy(packet_stream+2,&packet.poll,1);
    memcpy(packet_stream+3,&packet.precision,1);
    memcpy(packet_stream+4,&packet.rootDelay,4);
    memcpy(packet_stream+8,&packet.rootDispersion,4);
    memcpy(packet_stream+12,&packet.refId,4);
    memcpy(packet_stream+16,&packet.referenceTimestamp_s,4);
    memcpy(packet_stream+20,&packet.referenceTimestamp_f,4);
    memcpy(packet_stream+24,&packet.originTimestamp_s,4);
    memcpy(packet_stream+28,&packet.originTimestamp_f,4);
    memcpy(packet_stream+32,&packet.receiveTimestamp_s,4);
    memcpy(packet_stream+36,&packet.receiveTimestamp_f,4);
    memcpy(packet_stream+40,&packet.transmitTimestamp_s,4);
    memcpy(packet_stream+44,&packet.transmitTimestamp_f,4);

    return packet_stream;
}

/*--------------------------------------------------------------------------------------------------------*/
int main(int argc, char *argv[]) {

    /*Declare variables and reserve space */
    struct addrinfo * res, hints, *p;
    struct sockaddr * sa;
    socklen_t salen;
    int status;
    char ipstr[INET6_ADDRSTRLEN];
    char * packet_stream;   //marshalled information
    int packet_size;
    int socketfd_arr [argc-3];

    //Check the input args
    int number_requests = -1;
    int number_servers = -1;
    if (argc < 3 ) { //wrong input
        perror("CLient - Function parameters: (./ntpclient) n server1 server2 server3 ...");
        exit(1);
    }
    number_requests = atoi(argv[1]);
    number_servers = argc-3;
    char * ip_arr[number_servers];

    for(int i=0;i<number_servers;i++){
        ip_arr[i] = argv[i+3];
    }

    if(number_requests<0 || number_servers<0){
        perror("Client - Number of requests or number of servers not valid");
        exit(1);
    }

    packet_stream = marshal(4,3);

    for(int i = 0; i<number_servers;i++){
        //Set parameters for addrinfo struct hints; works with IPv4 and IPv6; Stream socket for connection
        memset(&hints,0, sizeof hints);
        hints.ai_family=AF_UNSPEC;
        hints.ai_socktype=SOCK_DGRAM;
        hints.ai_protocol=0; //OR IPPROTO_UDP

        //GetAddrInfo and error check
        if((status=getaddrinfo(ip_arr[i],PORT,&hints,&res))!=0){
            perror("Client - Getaddressinfo error: %s\n: ");
            exit(1);
        }
        //Declare and initialise socket with parameters from res structure
        int socketfd=socket(res->ai_family, res->ai_socktype, res ->ai_protocol);
        if(socketfd_arr[i]==-1){
            perror("Client - Socket failed: ");
            exit(1);
        }
        sa = malloc(res->ai_addrlen);
        memcpy(sa, res->ai_addr, res->ai_addrlen);
        salen = res->ai_addrlen;

        int send_int;
        send_int = sendto(socketfd,packet_stream,sizeof(ntp_packet),0,sa,salen);
        if(send_int<0){
            perror("Client - Socket failed to send: ");
            exit(1);
        }

        int recv_int;
        char * in_packet = malloc(48*sizeof(char));
        memset(in_packet,0,48*sizeof(char));
        recv_int = recvfrom(socketfd, in_packet, sizeof(in_packet), 0, NULL, NULL);
        if(recv_int<0){
            perror("Client - Socket failed to receive: ");
            exit(1);
        }

        struct ntp_packet * in_ntp = malloc(sizeof(ntp_packet));
        in_ntp = unmarshal(in_packet);

        time_t timestamp = (time_t) (in_ntp->transmitTimestamp_s - NTP_TIMESTAMP_DELTA);
        printf( "Time: %s", ctime( ( const time_t* ) &timestamp ) );





    }

    free(packet_stream);

    return(0);
}

