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
    char* value;
    char* key;

    UT_hash_handle hh;
}daten;

daten* hashtable=NULL;

int unmarshal(int socketcs,byte *header, packet *rein ){
    byte impbytes = header[0];

    int reserved=impbytes>>4;
    int ack=(impbytes&8)>>3;
    int com=impbytes&7;

    uint16_t keylen = (header[1]<<8)|header[2];
    uint32_t vallen = (header[3]<<24)|(header[4]<<16)|(header[5]<<8)|header[6];


    rein->reserved = reserved;
    rein->ack = ack;
    rein->com = com;
    rein->keylen = keylen;
    rein->vallen = vallen;
    fprintf(stderr,"RESERVED: %d, ACK: %d, COMMAND: %d, KEYLEN: %d, VALLEN: %d",reserved, ack, com, keylen, vallen);
    perror("");
    
    int receiving_bytes;
    char* bufferkey= malloc(keylen*sizeof(char));
    while(receiving_bytes<keylen){
      //  if
          receiving_bytes+=recv(socketcs,bufferkey,keylen,0);
                                  
      /*                            ))==0) {
            perror("all bytes unmarshalled");
            return -1;
*/
      }
       // received_bytes=received_bytes+receiving_bytes;
    rein->key=bufferkey;
    fprintf(stderr,"Bufferkey: %s",bufferkey);
    int receiving_bytes_s;
    int received_bytes_s;
    char* buffervalue=(char*) calloc(rein->vallen+1, sizeof(char));

    received_bytes_s=0;
    while(receiving_bytes_s<vallen){
        //if
          receiving_bytes_s+=recv(socketcs,buffervalue,vallen,0);
                                     
      /*                               ))==0){
           perror("alle valuebytes empfangen");
            return -1;
      }*/
       // received_bytes_s=received_bytes_s+receiving_bytes_s;
    }
   
    rein->value=buffervalue;

    //command bits correctly set?
    if(bufferkey == NULL){
        perror("No key given");
        return -1;
    }
    if((rein->com & 1) != 0){ //del
        if(buffervalue != NULL){
            perror("You mustn't send any value when deleting");
            return -1;
        }
        //TO DO else delete aufrufen?
    }
    if((rein->com & 2) != 0){ //set
        if(buffervalue == NULL){
            perror("Method 'set' but no value given");
            return -1;
        }
    }
    if((rein->com & 4) != 0){ //get
        if(buffervalue != NULL){
            perror("You mustn't send any value when using get");
            return -1;
        }
    }
    return 0;

}
int marshal(int socketcs, packet *out){
    int slength= out->vallen+out->keylen+7;
    char *buf=malloc(slength* sizeof(char));
    if(buf==NULL){
        perror("No allocation a memory");
        exit(1);
    }
    buf[0]=(out->reserved<<4)|(out->ack<<3)|out->com;
    buf[1]=out->keylen>>8;
    buf[2]=out->keylen;
    buf[3]=out->vallen>>24;
    buf[4]=out->vallen>>16;
    buf[5]=out->vallen<<8;
    buf[6]=out->vallen;

    memcpy(buf+7,out->key,out->keylen);
    memcpy(buf+7+out->keylen,out->value,out->vallen);
    if((send(socketcs,buf,slength,0))==-1){
        perror("Sending Failed");
        exit(1);
    }
    close(socketcs);
    return 0;
}
struct daten *get(char* key){
    daten *data1;
    HASH_FIND_PTR(hashtable,key,data1);
    return data1;

}
int set(char* key, char* value){
    struct daten *insert_data;
    HASH_FIND_PTR(hashtable, key, insert_data);
    if(insert_data==NULL){ //given key not already in hashtable
        insert_data = malloc(sizeof(daten));
        insert_data->value = value;
        insert_data->key = key;
        HASH_ADD_PTR(hashtable, key, insert_data);
    }
    return 0;
}

int delete(daten *deleting){
    HASH_DEL(hashtable, deleting);
    free(deleting);
    return 0;
}



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

        if((headerbyt=recv(new_socketcs,header,56,0))==-1){
            perror("Receiving of data failed");
            exit(1);
        }
     /*   printf("EMPFANGENEN BITS: %d\n",headerbyt);
        printf("Byte 1: %c\n",*(header+0));
        printf("Byte 2: %c\n",*(header+1));
        printf("Byte 3: %c\n",*(header+2));
        printf("Byte 4: %c\n",*(header+3));
        printf("Byte 5: %c\n",*(header+4));
        printf("Byte 6: %c\n",*(header+5));
        printf("Byte 7: %c\n",*(header+6));
        //for( int i=0;i< strlen(header);i++){
          char temp =*(header+7);
          for(int j=0; j<8;j++){
            printf("%d",!!((temp<<j)&0x80));
          }
          printf("\n");
        //}
        */
        packet *ne = malloc(sizeof(packet));

        unmarshal(new_socketcs,header,ne);


        //marshal
        packet *raus= malloc(sizeof(packet));
        raus->reserved=ne->reserved;
        raus->ack=1;
        raus->com=ne->com;

        if(ne->com ==4){
            raus->keylen=ne->keylen;
            raus->vallen=ne->vallen;
            daten *daten2= get(ne->key);

            raus->value=daten2->value;
            raus->key=ne->key;
        } else{

            raus->keylen=0;
            raus->vallen=0;

            raus->value=NULL;
            raus->key=NULL;
            if(ne->com==2){
                set(ne->key,ne->value);
            }else{
                delete(get(ne->key));
            }

        }
        marshal(new_socketcs,raus);

    }
    return (0);
}
