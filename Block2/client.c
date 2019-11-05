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
    char * buffer = malloc(MAX* sizeof(char));
    struct addrinfo * res, hints, *p;
    int status;
    char ipstr[INET6_ADDRSTRLEN];


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
    int maxtmp ;
    while((maxtmp = recv(socketcs,buffer,MAX,0))>0){
        fwrite(buffer, sizeof(char), strlen(buffer), stdout);
        if(maxtmp==-1){
            perror("Client - RECV failed: ");
            exit(1);
        }
    }

    fflush(stdout);
    close(socketcs);
    //Free reserved variables
    free(buffer);
    freeaddrinfo(res);
    return(0);
}