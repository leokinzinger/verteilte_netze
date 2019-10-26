#include <stdio.h>
#include <String.h>
#include "cmake-build-debug/input.h"
#include <stdlib.h>
#include <sys/socket.h>
#include <zconf.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#define MAX 1000
int main() {


    char * address = malloc(20* sizeof(char));
    char * port = malloc(20* sizeof(char));;
    char buffer[MAX];
    struct sockaddr_in ServAdr;
    char ip[100];
    //address="djxmmx.net";
    //port="17";
    struct addrinfo * res, hints, *p;
    int status;
    char ipstr[INET6_ADDRSTRLEN];

    printf("Please enter valid IP-Address/DNS-Address AND Port! Example: djxmmx.net 17\n");
    scanf("%s %s", address, port);
    printf("The Address is: %s, Port: %s\n", address, port);


    //input(address,port);
    memset(&hints,0, sizeof hints);
    hints.ai_family=AF_UNSPEC;
    hints.ai_socktype=SOCK_STREAM;

    if((status=getaddrinfo(address,port,&hints,&res))!=0){
        printf("Fehler");
    }
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
        // Konvertiere die IP in einen String und printe es
        inet_ntop(p->ai_family, addr, ipstr, sizeof ipstr);
        printf(" %s: %s\n", ipver, ipstr);
    }
    // Speicher von verketteter Liste befreien



    int socketcs=socket(res->ai_family, res->ai_socktype, res ->ai_protocol);

    if(socketcs==-1){
        printf("Fail Socket\n");
    }

    int connection;
    if(connection=connect(socketcs,res->ai_addr,res->ai_addrlen)==-1){
        perror(h_errno);
    }


    freeaddrinfo(res);

    int rec= recv(socketcs,buffer,1000,MSG_PEEK);

    printf("%s",buffer);

    return(0);
}