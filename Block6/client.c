#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <sys/time.h>

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

typedef struct
{
    struct timespec t1, t2, t3, t4;
}ntp_timestamps;



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

    memcpy(&packet_struct->rootDelay, in_packet+4, sizeof(u_int32_t));
    memcpy(&packet_struct->rootDispersion, in_packet+8, sizeof(u_int32_t));
    memcpy(&packet_struct->refId, in_packet+12, sizeof(u_int32_t));
    memcpy(&packet_struct->referenceTimestamp_s, in_packet+16, sizeof(u_int32_t));
    memcpy(&packet_struct->referenceTimestamp_f, in_packet+20, sizeof(u_int32_t));
    memcpy(&packet_struct->originTimestamp_s, in_packet+24, sizeof(u_int32_t));
    memcpy(&packet_struct->originTimestamp_f, in_packet+28, sizeof(u_int32_t));
    memcpy(&packet_struct->receiveTimestamp_s, in_packet+32, sizeof(u_int32_t));
    memcpy(&packet_struct->receiveTimestamp_f, in_packet+36, sizeof(u_int32_t));
    memcpy(&packet_struct->transmitTimestamp_s, in_packet+40, sizeof(u_int32_t));
    memcpy(&packet_struct->transmitTimestamp_f, in_packet+44, sizeof(u_int32_t));

    packet_struct->rootDelay = ntohl(packet_struct->rootDelay);
    packet_struct->rootDispersion = ntohl(packet_struct->rootDispersion);
    packet_struct->refId = ntohl(packet_struct->refId);
    packet_struct->referenceTimestamp_s = ntohl(packet_struct->referenceTimestamp_s);
    packet_struct->referenceTimestamp_f = ntohl(packet_struct->referenceTimestamp_f);
    packet_struct->originTimestamp_s = ntohl(packet_struct->originTimestamp_s);
    packet_struct->originTimestamp_f = ntohl(packet_struct->originTimestamp_f);
    packet_struct->receiveTimestamp_s = ntohl(packet_struct->receiveTimestamp_s);
    packet_struct->receiveTimestamp_f = ntohl(packet_struct->receiveTimestamp_f);
    packet_struct->transmitTimestamp_s = ntohl(packet_struct->transmitTimestamp_s);
    packet_struct->transmitTimestamp_f = ntohl(packet_struct->transmitTimestamp_f);

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

double structtodouble(struct timespec time){
    uint32_t seconds= time.tv_sec;
    uint32_t fraction= time.tv_nsec;
    char * number = malloc(20* sizeof(char));
    sprintf(number,"%d.%8d",seconds,fraction);
    double x= strtod(number,NULL);

    return x;

}

double calculateDelay(ntp_timestamps timestamp){


    double t1 = structtodouble(timestamp.t1);
    double t2 = structtodouble(timestamp.t2);
    double t3 = structtodouble(timestamp.t3);
    double t4 = structtodouble(timestamp.t4);

    return ((t4-t1)-(t3-t2));

}
double calculateOffset(ntp_timestamps timestamp){
    //offset = 0.5 * ((t2-t1) + (t3-t4));

    double t1 = structtodouble(timestamp.t1);
    double t2 = structtodouble(timestamp.t2);
    double t3 = structtodouble(timestamp.t3);
    double t4 = structtodouble(timestamp.t4);

    return ((t2-t1)+(t3-t4))/2;

}
double calculatedispersion(int i, int j,double delayarr[][j]){
    double max = delayarr[i][0];
    double min = delayarr[i][0];

    if(j == 0 ) return 0;
    else if( j<7){
        for(int k = 1; k <= j; k++){
            if(delayarr[i][j]>max){
                max = delayarr[i][j];
            }
            if(delayarr[i][j]<min){
                min= delayarr[i][j];
            }
        }
    }
    else{
        for(int k = j-7; k <= j; k++){
            if(delayarr[i][j]>max){
                max = delayarr[i][j];
            }
            if(delayarr[i][j]<min){
                min= delayarr[i][j];
            }
        }
    }
    double res= max-min;
    return res;
}
/*--------------------------------------------------------------------------------------------------------*/
int main(int argc, char *argv[]) {

    /*Declare variables and reserve space */
    struct addrinfo * res, hints, *p;
    struct sockaddr * sa;

    int status;
    char ipstr[INET6_ADDRSTRLEN];
    char * packet_stream;   //marshalled information
    int packet_size;
    int socketfd_arr [argc-2];
    struct timespec start, finish;
    //Check the input args
    int number_requests = -1;
    int number_servers = -1;
    if (argc < 3 ) { //wrong input
        perror("CLient - Function parameters: (./ntpclient) n server1 server2 server3 ...");
        exit(1);
    }
    number_requests = atoi(argv[1]);
    number_servers = argc-2;
    char * ip_arr[number_servers];

    for(int i=0;i<number_servers;i++){
        ip_arr[i] = argv[i+2];
    }

    if(number_requests<=0 || number_servers<=0){
        perror("Client - Number of requests or number of servers not valid");
        exit(1);
    }

    packet_stream = marshal(4,3);
    double  delayarr[number_servers][number_requests];
    double offsetarr[number_servers][number_requests];
    uint8_t rootDispersion[number_servers][number_requests];
    double  dispersion[number_servers][number_requests];
    for(int i = 0; i<number_servers;i++) {
        //Set parameters for addrinfo struct hints; works with IPv4 and IPv6; Stream socket for connection
        memset(&hints, 0, sizeof hints);
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_DGRAM;
        hints.ai_protocol = IPPROTO_UDP; // OR 0

        //GetAddrInfo and error check
        if ((status = getaddrinfo(ip_arr[i], PORT, &hints, &res)) != 0) {
            perror("Client - Getaddressinfo error: %s\n: ");
            exit(1);
        }
        //Declare and initialise socket with parameters from res structure
        int socketfd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
        if (socketfd == -1) {
            perror("Client - Socket failed: ");
            exit(1);
        }

        if (connect(socketfd, res->ai_addr, res->ai_addrlen) < 0) {
            perror("Client - Connection failed: ");
            exit(1);
        }
        for (int j = 0; j < number_requests; j++) {

            clock_gettime(CLOCK_REALTIME, &start);
            if (send(socketfd, packet_stream, 48, 0) < 0) {
                perror("Client - Send failed: ");
                exit(1);
            }

            char *in_packet = malloc(sizeof(ntp_packet));
            memset(in_packet, 0, 48 * sizeof(char));

            if (recv(socketfd, in_packet, 48, 0) < 0) {
                perror("Client - Recv failed: ");
                exit(1);
            }
            clock_gettime(CLOCK_REALTIME, &finish);


            struct ntp_packet *in_ntp = malloc(sizeof(ntp_packet));
            in_ntp = unmarshal(in_packet);

            in_ntp->receiveTimestamp_s=in_ntp->receiveTimestamp_s-NTP_TIMESTAMP_DELTA;
            in_ntp->transmitTimestamp_s=in_ntp->transmitTimestamp_s-NTP_TIMESTAMP_DELTA;


            ntp_timestamps timestamps = {0, 0, 0, 0};

            timestamps.t1.tv_sec=start.tv_sec;
            timestamps.t1.tv_nsec=start.tv_nsec;
            timestamps.t2.tv_sec=in_ntp->receiveTimestamp_s;
            timestamps.t2.tv_nsec=in_ntp->receiveTimestamp_f;
            timestamps.t3.tv_sec=in_ntp->transmitTimestamp_s;
            timestamps.t3.tv_nsec=in_ntp->transmitTimestamp_f;
            timestamps.t4.tv_sec=finish.tv_sec;
            timestamps.t4.tv_nsec=finish.tv_nsec;


            double delay = calculateDelay(timestamps);
            delayarr[i][j]=delay;

            double offset = calculateOffset(timestamps);
            offsetarr[i][j]=offset;

            rootDispersion [i][j]=in_ntp->rootDispersion;

            dispersion[i][j]  = calculatedispersion(i,j,delayarr);


            if(PRINT_OPTION == 1) printf("%s; %i; %u; %f; %f; %f\n", ip_arr[i], j, rootDispersion[i][j],dispersion[i][j],delay, offset);
            if(PRINT_OPTION == 2) printf("%s, %i, %u, %f, %f, %f\n", ip_arr[i], j, rootDispersion[i][j],dispersion[i][j],delay, offset);

            sleep(8);
        }
    }

    //free(packet_stream);

    return(0);
}

