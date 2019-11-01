#include <string.h>
#include "cmake-build-debug/input.h"
#include <stdlib.h>
#include <sys/socket.h>
#include <zconf.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <stdio.h>
#define MAX 512
int main(int argc, char *argv[]) {

    /*Declare variables and reserve space */
    char * address = malloc(20* sizeof(char));
    char * port = malloc(5* sizeof(char));;
    char * buffer = malloc(MAX* sizeof(char));
    struct addrinfo * res, hints, *p;
    int status;
    char ipstr[INET6_ADDRSTRLEN];
    int valid = -1;

    //Set parameters for addrinfo struct hints; works with IPv4 and IPv6; Stream socket for connection
    memset(&hints,0, sizeof hints);
    hints.ai_family=AF_UNSPEC;
    hints.ai_socktype=SOCK_STREAM;

    //GetAddrInfo and error check
    if((status=getaddrinfo(argv[1],argv[2],&hints,&res))!=0){
        printf("Getaddressinfo error: %s\n", gai_strerror(status));
        exit(1);
    }
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
        // Convert IP to String for printf
        inet_ntop(p->ai_family, addr, ipstr, sizeof ipstr);
        //printf(" %s: %s\n", ipver, ipstr);
    }

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
    //Call receive function to save message to buffer
    //If the buffer is to small for message, ajust the size of the buffer to the size of the message
    int maxtmp = recv(socketcs,buffer,MAX,0);
    while(maxtmp != 0){
        //printf("LOOPING with %d",maxtmp);
        if(maxtmp == -1) {
            perror("Client - Recv failed: ");
            exit(1);
        }else if(maxtmp != MAX || strchr(buffer,'\n')) {
            //printf("EXIT WITH %d",maxtmp);
            fwrite(buffer, sizeof(char), strlen(buffer), stdout);
            fflush(stdout);
            break;
        } else {
            //printf("AND AGAIN");
            fwrite(buffer, sizeof(char), strlen(buffer), stdout);
            fflush(stdout);
            //printf("MAXTMP: %d, BUFFER: %s",maxtmp,buffer);
            maxtmp = recv(socketcs, buffer, MAX, 0);
        }

    }
    /*
    int maxtmp=recv(socketcs,buffer,MAX,MSG_PEEK);
    if(maxtmp == -1){
        perror("Client - Recv failed: ");
        exit(1);
    }
    //Print message to screen and close socket
    fwrite(buffer,sizeof(char), strlen(buffer),stdout);
    fflush(stdout);
    */

    close(socketcs);
    //Free reserved variables
    free(buffer);
    freeaddrinfo(res);
    return(0);
}