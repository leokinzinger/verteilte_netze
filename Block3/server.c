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
typedef struct daten{
    uint32_t vallen;

    char* key;
    char* value;

    UT_hash_handle hh;
}daten;

daten* hashtable=NULL;

int unmarshal(int socketcs,byte *header, packet * in_packet ){
    byte impbytes = header[0];

    int reserved=impbytes>>4;
    int ack=(impbytes&8)>>3;
    int com=impbytes&7;

    uint16_t keylen = (header[1]<<8)|header[2];
    uint32_t vallen = (header[3]<<24)|(header[4]<<16)|(header[5]<<8)|header[6];

    in_packet->reserved = reserved;
    in_packet->ack = ack;
    in_packet->com = com;
    in_packet->keylen = keylen;
    in_packet->vallen = vallen;

    int receiving_bytes=0;
    char* bufferkey= malloc(keylen*sizeof(char));
    while(receiving_bytes<keylen){
        receiving_bytes+=recv(socketcs,bufferkey,keylen,0);
    }
    
    in_packet->key=bufferkey;
    int recv_int;
    if(in_packet->vallen != 0){
    	
    	char* buffer_val = (char*)calloc(vallen, sizeof(char));
    	char* buffer_tmp = malloc(BUFFER_SIZE*sizeof(char));
    	int i=0;
    	while(vallen != i){
    		memset(buffer_tmp,0,BUFFER_SIZE);
         if((recv_int=recv(socketcs,buffer_tmp,BUFFER_SIZE,0))==0){
          	perror("Server - RECEIVE IS 0");
          	exit(1);
         } 
         memcpy(buffer_val+i,buffer_tmp,BUFFER_SIZE);
         i+=recv_int;                          
     }  
    in_packet->value=malloc(vallen*sizeof(char));
    in_packet->value=buffer_val;
    
    }else{
		in_packet->value=NULL;
    }
    return 0;
}

int marshal(int socketcs, packet *out_packet){
    int packet_length= out_packet->vallen+out_packet->keylen+7;
    char *buf=malloc(packet_length* sizeof(char));
    if(buf==NULL){
        perror("Server - Allocation of memory unsuccessful: ");
        exit(1);
    }
    buf[0]=(out_packet->reserved<<4)|(out_packet->ack<<3)|out_packet->com;
    buf[1]=out_packet->keylen>>8;
    buf[2]=out_packet->keylen;
    buf[3]=out_packet->vallen>>24;
    buf[4]=out_packet->vallen>>16;
    buf[5]=out_packet->vallen>>8;
    buf[6]=out_packet->vallen;

    memcpy(buf+7,out_packet->key,out_packet->keylen);
    memcpy(buf+7+out_packet->keylen,out_packet->value,out_packet->vallen);

    if((send(socketcs,buf,packet_length,0))==-1){
        perror("Server - Sending Failed: ");
        exit(1);
    }
    return 0;
}

daten* get(packet *in_packet){
    daten *out_data=malloc(sizeof(daten));
    out_data->key = malloc(in_packet->keylen*sizeof(char));
    out_data->value = malloc(sizeof(char));
    HASH_FIND(hh,hashtable,in_packet->key,in_packet->keylen,out_data);
    if(out_data != NULL){
        in_packet->value = out_data->value;
        in_packet->vallen = out_data->vallen;
    }
    return out_data;
}

int set(packet *in_packet){
    daten *in_data;
    daten *out_data;
    
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
    tmp_daten = get(in_packet);
    HASH_DELETE(hh, hashtable, tmp_daten);
    free(tmp_daten);
    return 0;
}


int main(int argc, char *argv[]) {
    /*Declare variables and reserve space */
    struct sockaddr_storage their_addr;
    socklen_t addr_size;
    struct addrinfo *res, hints, *p;
    int socketcs, new_socketcs;
    char ipstr[INET6_ADDRSTRLEN];
    int status;
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

        unmarshal(new_socketcs,header,out_packet);
		   
        //marshal
       
        struct daten* out_data= malloc(sizeof(daten));
        
        out_packet->ack=1;
        if(out_packet->com ==4){	//GET 
        
           
           tmp = get(out_packet);
            
        } else if(out_packet->com==2 || out_packet->com ==1){
          if(out_packet->com==2){	//SET
            
            set(out_packet);
            
          }else{				//DEL
            
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
        marshal(new_socketcs,out_packet);
        free(out_packet);
        close(new_socketcs);
    }
    return (0);
}
