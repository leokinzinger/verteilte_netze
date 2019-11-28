#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <stdio.h>
#include <time.h>
#include "uthash.h"
#include <netinet/tcp.h>

#define MAX 500
#define BUFFER_SIZE 10
#define BACKLOG 1
#define MODE 1 //1-TESTING, 0 RUNNING

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
typedef struct control_message{
    uint8_t con;
    uint8_t reserved;
    uint8_t reply;
    uint8_t lookup;

    uint16_t id_hash;
    uint16_t id_node;
    uint16_t port_node;

    uint32_t ip_node;
}control_message;
daten* hashtable=NULL;
typedef struct node {
    uint16_t hash_id;
    char *node_ip;
    char *node_port;
}node;
struct node self_node;
struct node pre;
struct node suc;



int unmarshal_control_message(byte * buf,control_message * in_control){//in buf wird empfangen die größe beträgt 11 byte
    byte impbytes=buf[0];
    in_control->con=impbytes>>7;
    in_control->reserved=(impbytes&128)>>2;
    in_control->reply=(impbytes&2)>>1;
    in_control->lookup=impbytes&7;
    in_control->id_hash=(buf[1]<<8)|buf[2];
    in_control->id_node=(buf[3]<<8)|buf[4];
    in_control->ip_node=(buf[5]<<24)|(buf[6]<<16)|(buf[7]<<8)|buf[8];
    in_control->port_node=(buf[9]<<8)|buf[10];
    return 0;
}

int unmarshal_packet(int socketcs,byte *header, packet * in_packet ){
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
    in_packet->key = malloc(2*sizeof(char));
    memcpy(in_packet->key,bufferkey,2);
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
int marshal_control_message(int socketcm, control_message * out_control){
    int length_control_message=11;//weil 11 header
    char *buf=malloc(length_control_message*sizeof(char));
    if(buf==NULL){
        perror("Server - Allocation of memory unsuccessful: ");
        exit(1);
    }
    buf[0]=(out_control->con<<7)|(out_control->reserved<<2)|(out_control->reply<<1)|out_control->lookup;
    buf[1]=out_control->id_hash>>8;
    buf[2]=out_control->id_hash;
    buf[3]=out_control->id_node>>8;
    buf[4]=out_control->id_node;
    buf[5]=out_control->ip_node>>24;
    buf[6]=out_control->ip_node>>16;
    buf[7]=out_control->ip_node>>8;
    buf[8]=out_control->ip_node;
    buf[9]=out_control->port_node>>8;
    buf[10]=out_control->port_node;

    if(send(socketcm,buf,length_control_message,0)==-1){
        perror("Server - Sending Control Message Failed: ");
        exit(1);
    }
    return 0;
}

int marshal_packet(packet * out_packet, char *buf){

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

    return 0;
}
int send_to_client(int socketcs, char * buf, int packet_length){
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

int selfcheck(packet*out_packet){
    uint16_t key;
    if(out_packet->keylen>1) key = out_packet->key[0]<<8 | out_packet->key[1];
    else key = out_packet->key[0];

    if(MODE==1)fprintf(stderr,"Key: %d, [0]: %c, [1]: %c\n",key,out_packet->key[0],out_packet->key[1]);
    //memcpy(key,out_packet->key,2);
    daten* tmp = malloc(sizeof(tmp));
    if(MODE==1) {
        fprintf(stderr, "HASH: %i\n", key);
        fprintf(stderr, "PRE: %u\n", pre.hash_id);
        fprintf(stderr, "SELF: %u\n", self_node.hash_id);
        fprintf(stderr, "SUC: %u\n", suc.hash_id);
    }
    if(pre.hash_id>self_node.hash_id){
        if( (key>pre.hash_id && key<65535) || (key>0 && key<=self_node.hash_id) ) return 1;
        else if( (key>self_node.hash_id) && (key<= suc.hash_id)) return 2;
        else return 3;
    }else{
        if (key>pre.hash_id && key <=self_node.hash_id) return 1;
        else if(key>self_node.hash_id && key<= suc.hash_id) return 2;
        else return 3;
    }
}

int do_operation(packet * out_packet, daten* tmp){
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
    return 0;
}

int new_connection(char * ip_addr, char * port){
    struct addrinfo * res, hints;
    int socketfd;
    memset(&hints,0, sizeof hints);
    hints.ai_family=AF_UNSPEC;
    hints.ai_socktype=SOCK_STREAM;

    if((getaddrinfo(ip_addr,port,&hints,&res))!=0){
        perror("Server - Getaddressinfo error: %s\n: ");
        exit(1);
    }
    socketfd=socket(res->ai_family,res->ai_socktype,0);
    if(socketfd==-1){
        perror("Server - Socketcreation failed: ");
        exit(1);
    }
    int connection = connect(socketfd,res->ai_addr,res->ai_addrlen);
    if(connection == -1){
        perror("Server - Connection failed: ");
        exit(1);
    }

    return socketfd;

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


    self_node.node_ip = malloc(4*sizeof(char));
    self_node.node_port = malloc(2* sizeof(char));

    pre.node_ip = malloc(4*sizeof(char));
    pre.node_port = malloc(2* sizeof(char));

    suc.node_ip = malloc(4*sizeof(char));
    suc.node_port = malloc(2* sizeof(char));

    //Input
    if(argc != 10){
        perror("Server - Function parameters: (./peer) self_id self_ip self_port pred_id pre_ip pr_port anc_id  anc_ip anc_port");
        exit(1);
    }

    //Check if port number is in range
    int i = 3;
    while(i<10){
        int port_int = atoi(argv[i]);
        if(port_int<1024 || port_int > 65535) {
            printf("Illegal port number!");
            exit(1);
        }else{
            switch(i){
                case 3: self_node.node_port=argv[i]; break;
                case 6: pre.node_port=argv[i]; break;
                case 9: suc.node_port=argv[i]; break;
                default: exit(1); break;
            }
        }
        i+=3;
    }
    long val = strtol(argv[1],NULL,10);
    self_node.hash_id=(uint16_t)val;
    self_node.node_ip=argv[2];


    val = strtol(argv[4],NULL,10);
    pre.hash_id=(uint16_t)val;
    pre.node_ip=argv[5];

    val = strtol(argv[7],NULL,10);
    suc.hash_id=(uint16_t)val;
    suc.node_ip=argv[8];


    if(MODE ==1) {
        fprintf(stdout, "SELF: %u, %s, %s \nPRED: %u, %s, %s \nSUC: %u, %s, %s \n",
                self_node.hash_id, self_node.node_ip, self_node.node_port,
                pre.hash_id, pre.node_ip, pre.node_port,
                suc.hash_id, suc.node_ip, suc.node_port);
    }

    //Set parameters for addrinfo struct hints; works with IPv4 and IPv6; Stream socket for connection
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

    //GetAddrInfo and error check
    if ((status = getaddrinfo(NULL, self_node.node_port, &hints, &res)) != 0) {

        perror("Getaddressinfo error: ");
        exit(1);
    }
    //Declare and initialise socket with parameters from res structure
    socketcs = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (socketcs == -1) {
        perror("Server - Socket failed: ");
        exit(1);
    }
    int yes = 1;
    if (setsockopt(socketcs,SOL_SOCKET,SO_REUSEADDR,&yes,sizeof yes) == -1) {
        perror("Server - setsockopt: ");
        exit(1);
    }
    int bind_int = bind(socketcs, res->ai_addr, res->ai_addrlen);
    if(bind_int == -1){
        perror("Server - Binding to port failed: ");
        exit(1);
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

        //check which unmarshal should be used
        byte *unmarshalcheckbuf = malloc(sizeof(char));
        int unmarshalcheck;
        packet *out_packet = malloc(sizeof(packet));
        if((unmarshalcheck=recv(new_socketcs,unmarshalcheckbuf,1,MSG_PEEK))==-1){
            perror("Receiving of data failed");
            exit(1);
        }
        unmarshalcheck=0;
        unmarshalcheck=unmarshalcheckbuf[1]>>7;
        //unmarshal packet
        if(unmarshalcheck==0){
            byte *header= malloc(7* sizeof(char));

            if((headerbyt=recv(new_socketcs,header,7,0))==-1){
                perror("Receiving of data failed");
                exit(1);
            }
            unmarshal_packet(new_socketcs,header,out_packet);
            int self_case = selfcheck(out_packet); //1 - Hash belongs to self; 2 - Hash belongs to suc; 3 - lookup


            if(self_case == 1){
                if(MODE ==1) fprintf(stdout, "IT's me!");
                //HASH ID belongs to self, do operation and send out response to server
                int packet_length= out_packet->vallen+out_packet->keylen+7;
                if(MODE ==1) fprintf(stdout, "IT's me!");
                char *buf=malloc(packet_length* sizeof(char));
                do_operation(out_packet,tmp);
                marshal_packet(out_packet,buf);
                send_to_client(new_socketcs,buf, packet_length);
            }

            else if(self_case == 2){
                if(MODE ==1) {
                    fprintf(stdout, "IT's my neighbor!\n");
                }
                //init
                int packet_length= (int)(out_packet->vallen+out_packet->keylen+7);
                char *buf=malloc(packet_length* sizeof(char));
                int socket_nextServer;

                //SELECT SUC
                //SEND PACKET TO PEER WITH NEW SOCKET
                marshal_packet(out_packet,buf);
                if(MODE==1)fprintf(stderr,"%s",out_packet->key);
                socket_nextServer=new_connection(suc.node_ip,suc.node_port);
                send_to_client(socket_nextServer,buf,packet_length);

                free(buf);

                //RECV PACKET FROM PEER
                int count_recv;
                char * in_packet = malloc(MAX*sizeof(char));
                char *buffer = malloc(MAX* sizeof(char));
                int in_packet_size = 0;
                while((count_recv= recv(socket_nextServer,buffer,MAX,0)) != 0){
                    if(count_recv == -1){
                        perror("Server - Recieve failed: ");
                        exit(1);
                    }
                    in_packet = realloc(in_packet,in_packet_size+count_recv+1);
                    memcpy(in_packet+in_packet_size,buffer,count_recv);
                    in_packet_size += count_recv;

                }
                if(MODE ==1) {
                    fprintf(stdout, "Packet: %s!\n",in_packet);
                }
                //SEND PACKET TO CLIENT

                //marshal_packet(in_packet, buf);
                send_to_client(new_socketcs,in_packet, in_packet_size);

            }else{
                if(MODE ==1) {
                    fprintf(stdout, "Lookup!\n");
                }
                //SELECT SUC
                //TODO
                //SEND CONTROL MSG TO PEER
                //TODO
                //RECV CONTROL MSG FROM PEER
                //TODO
                //SEND PACKET TO CLIENT
            }


        //unmarshal control_message
        }else{
            byte *buf=malloc(11*sizeof(char));
            int control_message_recv;

            if((control_message_recv=recv(new_socketcs,buf,11,0))==-1){
                perror("Receiving of data failed");
                exit(1);
            }
            control_message * out_control_message= malloc(sizeof(control_message));
            unmarshal_control_message(buf,out_control_message);
        }


		   
        //marshal
  /*
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
        marshal_packet(new_socketcs,out_packet);

      */
        free(out_packet);
    }
    return (0);
}
