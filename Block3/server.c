#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <zconf.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <stdio.h>
#include <time.h>
#include "uthash.h"
#include <netinet/tcp.h>

#define BUFFER_SIZE 10 
#define SIZEOFVALUE 2000

#define BACKLOG 1
typedef unsigned char byte;
typedef struct packet{
    uint8_t reserved;
    uint8_t ack;
    uint8_t com;

    uint16_t keylen;
    uint32_t vallen;

    char* key;
    char* value;
    UT_hash_handle hh;
}packet;
//struct to save in hash table
typedef struct daten{
    char* key;
    char* value;
    uint32_t vallen;

    UT_hash_handle hh;
}daten;

daten* hashtable=NULL;

/*--------------------------------------------------------------------------------------------------------*/
int unmarshal(int socketcs, byte *header, packet *packet_unmarshal){
    byte impbytes = header[0];

    int reserved=impbytes>>4;
    int ack=(impbytes&8)>>3;
    int com=impbytes&7;

    uint16_t keylen = (header[1]<<8)|header[2];
    uint32_t vallen = (header[3]<<24)|(header[4]<<16)|(header[5]<<8)|header[6];

    packet_unmarshal->reserved = reserved;
    packet_unmarshal->ack = ack;
    packet_unmarshal->com = com;
    packet_unmarshal->keylen = keylen;
    packet_unmarshal->vallen = vallen;
    fprintf(stderr,"RESERVED: %d, ACK: %d, COMMAND: %d, KEYLEN: %d, VALLEN: %d \n",reserved, ack, com, packet_unmarshal->keylen, packet_unmarshal->vallen);
    
    int receiving_bytes=0;
    char* bufferkey = malloc(keylen*sizeof(char));
    while(receiving_bytes<keylen){
          receiving_bytes+=recv(socketcs,bufferkey,keylen,0);
    }

    packet_unmarshal->key=bufferkey;
    int recv_int;

    if(packet_unmarshal->vallen != 0){
    	char* buffervalue = (char*)calloc(vallen, sizeof(char));
    	char* buffer_tmp = malloc(BUFFER_SIZE*sizeof(char));
    	int shift_int = 0;

    	while(vallen != shift_int){
    		memset(buffer_tmp,0,BUFFER_SIZE);
            if((recv_int=recv(socketcs,buffer_tmp,BUFFER_SIZE,0))==0){
          	    perror("Server - RECEIVE IS 0");
          	    exit(1);
            }
            memcpy(buffervalue+shift_int,buffer_tmp,BUFFER_SIZE);
            shift_int+=recv_int;
        }
        packet_unmarshal->value=malloc(vallen*sizeof(char));
        packet_unmarshal->value=buffervalue;
    }
    else {
        packet_unmarshal->value = malloc(4 * sizeof(char));
        packet_unmarshal->value = "Hello here";
    }
    //fprintf(stderr,"Ende Unmarshal: %s\n", input_data->value);
    return 0;
}

/*--------------------------------------------------------------------------------------------------------*/
int marshal(int socketcs, packet *packet_marshal){
    int packet_length = packet_marshal->vallen+packet_marshal->keylen+7;
    char *buf=malloc(packet_length* sizeof(char));

    if(buf==NULL){
        perror("Server - Allocation of memory unsuccessful: ");
        exit(1);
    }
    buf[0]=(packet_marshal->reserved<<4)|(packet_marshal->ack<<3)|packet_marshal->com;
    buf[1]=packet_marshal->keylen>>8;
    buf[2]=packet_marshal->keylen;
    buf[3]=packet_marshal->vallen>>24;
    buf[4]=packet_marshal->vallen>>16;
    buf[5]=packet_marshal->vallen>>8;
    buf[6]=packet_marshal->vallen;

    memcpy(buf+7, packet_marshal->key, packet_marshal->keylen);
    memcpy(buf+7+packet_marshal->keylen, packet_marshal->value, packet_marshal->vallen);

    if((send(socketcs,buf,packet_length,0))==-1){
        perror("Server - Sending Failed: ");
        exit(1);
    }
    return 0;
}

/*--------------------------------------------------------------------------------------------------------*/
daten* get(packet *in_packet){
    daten *out_data=malloc(sizeof(daten)); //data to be returned by method
    out_data->key = malloc(in_packet->keylen*sizeof(char));
    out_data->value = malloc(sizeof(char));

    HASH_FIND(hh,hashtable,in_packet->key,in_packet->keylen, out_data);
    //in case there is already an entry with given key in hashtable
    if(out_data != NULL){
        in_packet->value = out_data->value;
        in_packet->vallen = out_data->vallen;
    }
    return out_data;
}

int set(packet *in_packet){
    daten *in_data; //data to insert
    
    HASH_FIND(hh,hashtable,in_packet->key,in_packet->keylen, in_data);
    if(in_data==NULL){ //given key not already in hashtable
        in_data = malloc(sizeof(daten));
        in_data->key=malloc(in_packet->keylen*sizeof(char));
        in_data->value=malloc(in_packet->vallen*sizeof(char));
        in_data->value = in_packet->value;
        in_data->key = in_packet->key;
        in_data->vallen = in_packet->vallen;
        HASH_ADD_KEYPTR(hh,hashtable, in_data->key, in_packet->keylen, in_data);
    }
    return 0;
}

int delete(packet * in_packet){
    daten* tmp_daten = malloc(sizeof(daten));
    tmp_daten->key = malloc(in_packet->keylen*sizeof(char));
    //tmp_daten->value = malloc(in_packet->*sizeof(char));
    tmp_daten = get(in_packet);
    HASH_DELETE(hh, hashtable, tmp_daten);
    free(tmp_daten);
    return 0;
}

/*--------------------------------------------------------------------------------------------------------*/
int main(int argc, char *argv[]) {

    /*Declare variables and reserve space */
    struct sockaddr_storage their_addr;
    socklen_t addr_size;
    struct addrinfo *res, hints, *p;
    int socketcs, new_socketcs;
    char ipstr[INET6_ADDRSTRLEN];
    int line_counter = 0;
    time_t t;
    int status;
    FILE * fl_copy;
    char * str;
    size_t str_bytes;
    int headerbyt;

    //Input
    if(argc != 2){
        perror("Server - Function parameters: (./server) port_number");
        exit(1);
    }

    //Check if port number is in range
    int port_int = atoi(argv[1]);
    if(port_int<1024 || port_int > 65535){
        printf("Illegal port number!");
        exit(1);
    }

    //Set parameters for addrinfo struct hints; works with IPv4 and IPv6; Stream socket for connection
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

    //GetAddrInfo and error check
    if ((status = getaddrinfo(NULL, argv[1], &hints, &res)) != 0) {
        perror("Getaddressinfo error: ");
        exit(1);
    }

    //Save ai_family depending on IPv4 or IPv6, loop through the struct and bind to the first
    for (p = res; p != NULL; p = p->ai_next) {
        void *addr;
        char *ipver;
        if (p->ai_family == AF_INET) { //IPv4
            struct sockaddr_in *ipv4 = (struct sockaddr_in *) p->ai_addr;
            addr = &(ipv4->sin_addr);
            ipver = "IPv4";
        } else { //IPv6
            struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *) p->ai_addr;
            addr = &(ipv6->sin6_addr);
            ipver = "IPv6";
        }
        // Convert IP to String for printf
        inet_ntop(p->ai_family, addr, ipstr, sizeof ipstr);

        //Declare and initialise socket with parameters from res structure
        socketcs = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (socketcs == -1) {
            perror("Server - Socket failed: ");
            exit(1);
        }
        int yes = 1;
        if (setsockopt(socketcs,SOL_SOCKET,SO_REUSEADDR,&yes,sizeof yes) == -1) {
            perror("Server - setsockopt: ");
            exit(1);
        }
        int bind_int = bind(socketcs, p->ai_addr, p->ai_addrlen);
        if(bind_int == -1){
            perror("Server - Binding to port failed: ");
            exit(1);
        }
        break;
    }

    //structure not needed anymore
    freeaddrinfo(res);

    if(res == NULL){
        perror("Server - server could not bind");
    }
    int listen_int = listen(socketcs, BACKLOG);
    if(listen_int == -1){
        perror("Server - listen failed: ");
        exit(1);
    }
    printf("Server - Open for connections.\n");
    daten* tmp = malloc(sizeof(tmp));

    while(1){
        //unmarshal
        //creates a new socket, to communicate with the client that called connect
        addr_size = sizeof their_addr;
        new_socketcs = accept(socketcs, (struct sockaddr *)&their_addr, &addr_size);
        if(new_socketcs == -1) {
            perror("Server - Accept failed: ");
            exit(1);
        }
        byte *header= malloc(7* sizeof(char));

        if((headerbyt=recv(new_socketcs,header,7,0))==-1){
            perror("Receiving of data failed");
            exit(1);
        }
       
        packet *out_packet = malloc(sizeof(packet));

        unmarshal(new_socketcs, header, out_packet);
        //fprintf(stderr,"Unmarshal completed\n");
       
        struct daten* out_data= malloc(sizeof(daten));
        
        out_packet->ack=1;
    
        //fprintf(stderr,"RESERVED: %d, ACK: %d, COMMAND: %d \n",out_packet->reserved, out_packet->ack, out_packet->com);

        if(out_packet->com ==4){	//GET
           tmp = get(out_packet);
        }
        else if(out_packet->com==2 || out_packet->com ==1){
            if(out_packet->com==2){	//SET
                set(out_packet);
            }
            else{				//DEL
                delete(out_packet);
            }
            out_packet->keylen=0;
            out_packet->vallen=0;
            out_packet->value=NULL;
            out_packet->key=NULL;
        }
        else{
            perror("Server - Illegal Operation! ");
        	exit(1);
        }
        //fprintf(stderr,"KEY: %s, KEYLENGTH: %d, VALUE: %s, VALUELENGTH: %d \n",out_packet->key, out_packet->keylen, out_packet->value, out_packet->vallen);

        marshal(new_socketcs, out_packet);

        free(out_packet);
        close(new_socketcs);
        //close(socketcs);
        //exit(1);

    }
    return (0);
}
