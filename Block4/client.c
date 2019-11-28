#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <stdio.h>
#define MAX 500
#define BUFSIZE 20
#define PRINT_OPTION 1
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
typedef struct packet{
    uint8_t reserved;
    uint8_t ack;
    uint8_t com;

    uint16_t keylen;
    uint32_t vallen;

    char* key;
    char* value;
}packet;

struct packet * packet_struct;

/*--------------------------------------------------------------------------------------------------------*/
//Function gets the input <command> and assigns it to the variables command or throws an error when the
//command is unknown.
int get_command(char*argv[], uint8_t * command){
    if(strcmp(argv[3],"GET") == 0) *(command) = 4;
    else if(strcmp(argv[3],"SET") == 0) *(command) = 2;
    else if(strcmp(argv[3],"DELETE") == 0) *(command) = 1;
    else {printf("Command %s is not valid! Options: GET SET DELETE \n",argv[3]); exit(1);}
    return 0;
}

/*--------------------------------------------------------------------------------------------------------*/
//Function gets the byte array that was send from the server and puts the values into a struct of type packet.
//We used pointer arithmetic to get the values
struct packet * unmarshal(char * in_packet){
    struct packet * packet_struct = malloc(sizeof(packet));
    packet_struct->reserved=in_packet[0]>>4;
    packet_struct->ack=(in_packet[0]&8)>>3;
    packet_struct->com=in_packet[0]&7;

    packet_struct->keylen = (in_packet[1]<<8)|in_packet[2];
    packet_struct->vallen = (in_packet[3]<<24)|(in_packet[4]<<16)|(in_packet[5]<<8)|in_packet[6];
    packet_struct->key = malloc(packet_struct->keylen* sizeof(char));
    packet_struct->value = malloc(packet_struct->vallen*sizeof(char));
    memcpy(packet_struct->key, in_packet+7, packet_struct->keylen);
    memcpy(packet_struct->value, in_packet+7+packet_struct->keylen, packet_struct->vallen);
    return packet_struct;
}

/*--------------------------------------------------------------------------------------------------------*/
//Reads input from both argv and stdin and saves values to corresponding variables, we used getchar()
// to read every single char and copied it into buffer.
// We than copied the buffer to the value and realloc() the variable
char* marshal(int argc, char *argv[], int* packet_size, uint16_t *keylen, uint32_t*vallen){
    char * packet_stream;   //marshalled information
    char * value;
    char * key = malloc(strlen(argv[4]));
    //uint16_t keylen;
    //uint32_t vallen;

    uint8_t command;
    get_command(argv, &command);

    key = argv[4];
    *keylen = strlen(key);
    char * input_buffer = malloc(BUFSIZE*sizeof(char));
    int tmp;
    int counter = 0;
    int index_buffer =0;
    if(command == 2 && argc ==5) { //SET
        value = malloc(BUFSIZE*sizeof(char));
        while ((tmp = getchar()) != EOF) {
            *(input_buffer + index_buffer) = (char)tmp;
            index_buffer++;
            counter++;
            if (index_buffer % BUFSIZE == 0) {
                index_buffer = 0;
                memcpy(value + counter - BUFSIZE, input_buffer, BUFSIZE);
                memset(input_buffer, 0, BUFSIZE);
            }
            value = realloc(value, (counter + BUFSIZE) * sizeof(char));

        }
        memcpy(value+counter-index_buffer, input_buffer, index_buffer);
        *vallen = counter;

    }else if(command == 2 && argc ==6){ //SET without piping
        value = malloc(strlen(argv[5]));
        value = argv[5];
        *vallen = strlen(value);
    }else{ //GET & DELETE
        value = NULL;
        *vallen = 0;
    }

    *(packet_size) = 7+(*keylen)+(*vallen);
    packet_stream = malloc(*(packet_size)*sizeof(char));
    memset(packet_stream,0,*packet_size);

    uint16_t keylen_netorder = htons(*keylen);
    uint32_t vallen_netorder = htonl(*vallen);


    memcpy(packet_stream,&command,1);
    memcpy(packet_stream+1,&keylen_netorder, 2);
    memcpy(packet_stream+3,&vallen_netorder,4);
    memcpy(packet_stream+7,key,*keylen);
    memcpy(packet_stream+7+(*keylen),value,(*vallen));
    //fwrite(packet_stream+7+keylen,sizeof(char),vallen*sizeof(char),stdout);
    if(command == 2 && argc ==5) free(value);
    free(input_buffer);

    return packet_stream;
}

/*--------------------------------------------------------------------------------------------------------*/
int main(int argc, char *argv[]) {

    /*Declare variables and reserve space */
    char * buffer = malloc(MAX* sizeof(char));
    struct addrinfo * res, hints, *p;
    int status;
    char ipstr[INET6_ADDRSTRLEN];
    char * packet_stream;   //marshalled information
    int packet_size;

    //Check the input args
    if (argc < 5 || argc > 6) { //wrong input
        perror("Server - Function parameters: (./server) host port_number Command Key Value");
        exit(1);
    }
    uint16_t keylen = 0;
    uint32_t vallen = 0;
    packet_stream = marshal(argc, argv, &packet_size, &keylen, &vallen);
    //fwrite(packet_stream+7+keylen,sizeof(char),vallen*sizeof(char),stdout);

    //Set parameters for addrinfo struct hints; works with IPv4 and IPv6; Stream socket for connection
    memset(&hints,0, sizeof hints);
    hints.ai_family=AF_UNSPEC;
    hints.ai_socktype=SOCK_STREAM;

    //GetAddrInfo and error check
    if((status=getaddrinfo(argv[1],argv[2],&hints,&res))!=0){
        perror("Client - Getaddressinfo error: %s\n: ");
        exit(1);
    }
    /*
    //Save ai_family depending on IPv4 or IPv6
    for(p=res;p!=NULL;p=p->ai_next){
        void *addr;
        char * ipver;
        if (p->ai_family == AF_INET) { //IPv4
            struct sockaddr_in *ipv4 = (struct sockaddr_in *)p->ai_addr;
            addr = &(ipv4->sin_addr);
            ipver = "IPv4";
        } else { //IPv6
            struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *)p->ai_addr;
            addr = &(ipv6->sin6_addr);
            ipver = "IPv6";
        }
    }*/

    //Declare and initialise socket with parameters from res structure
   int socketcs=socket(res->ai_family, res->ai_socktype, res ->ai_protocol);
    if(socketcs==-1){
        perror("Client - Socket failed: ");
        exit(1);
    }
    //Declare and initialise connection with parameters from res structure
    int connection = connect(socketcs,res->ai_addr,res->ai_addrlen);
    if(connection == -1){
        perror("Client - Connection failed: ");
        exit(1);
    }
    //Send marshalled packet to server using the send() function
    int tmp_send;
    if((tmp_send = send(socketcs,packet_stream, packet_size,0)) == -1){
        perror("Client - Send failed: ");
        exit(1);
    }

    //Call receive function to save message to buffer
    //If the buffer is to small for message, ajust the size of the buffer to the size of the message
    int count_recv;
    char * in_packet = malloc(MAX*sizeof(char));
    int in_packet_size = 0;
    while((count_recv= recv(socketcs,buffer,MAX,0)) != 0){
        if(count_recv == -1){
            perror("Server - Recieve failed: ");
            exit(1);
        }
        in_packet = realloc(in_packet,in_packet_size+count_recv+1);
        //in_packet = realloc(in_packet,in_packet_size+MAX);
        memcpy(in_packet+in_packet_size,buffer,count_recv);

        //printf("RECV: %d",count_recv);
        in_packet_size += count_recv;
        //fprintf(stderr,"LENGTH: %d \n",in_packet+in_packet_size);
    }
    packet_struct = malloc(sizeof(packet));
    packet_struct = unmarshal(in_packet);
    if(PRINT_OPTION == 1) {
        fprintf(stderr,"\tACK: \t\t%d\n", packet_struct->ack);
        fprintf(stderr,"\tCOMMAND: \t%d\n", packet_struct->com);
        fprintf(stderr,"\tKEY LENGTH: \t%d\n", packet_struct->keylen);
        fprintf(stderr,"\tVALUE LENGTH: \t%d\n", packet_struct->vallen);
    }
    if(packet_struct->com == 4) fwrite(packet_struct->value, sizeof(char),packet_struct->vallen,stdout);

    close(socketcs);
    //Free reserved variables
    free(buffer);
    free(packet_stream);
    free(packet_struct);
    free(in_packet);
    freeaddrinfo(res);

    return(0);
}

