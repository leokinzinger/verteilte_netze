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
int main() {


    char * address = malloc(20* sizeof(char));
    char * port = malloc(5* sizeof(char));;
    char * buffer = malloc(MAX* sizeof(char));
    char ip[100];
    struct addrinfo * res, hints, *p;
    int status;
    char ipstr[INET6_ADDRSTRLEN];
    int valid = -1;
   // int socketcs;
    while(valid == -1){
        printf("Please enter valid IP-Address/DNS-Address AND Port! Example: djxmmx.net 17\n");
        scanf("%s %s", address, port);
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
        //TODO Leo soll das noch bauen und kommentieren
        int connection = connect(socketcs,res->ai_addr,res->ai_addrlen);

        if(connection == -1){
            perror(h_errno);
        }
        else valid = 0;

        freeaddrinfo(res);
        int maxtmp=recv(socketcs,buffer,MAX,MSG_PEEK);
        if((maxtmp<MAX)){


            buffer = realloc(buffer, sizeof(char)*maxtmp);
            recv(socketcs,buffer,maxtmp,MSG_PEEK);
        }

        printf("%s",buffer);

        close(socketcs);
    }
    free(buffer);
    free(address);
    free(port);

    return(0);
}