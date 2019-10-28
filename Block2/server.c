#include <string.h>
//#include "cmake-build-debug/input.h"
#include <stdlib.h>
#include <sys/socket.h>
#include <zconf.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <stdio.h>

#define MAX 512
#define BACKLOG 1

int main(int argc, char *argv[]) {

    /*Declare variables and reserve space */
    char *address = malloc(20 * sizeof(char));
    char *port = malloc(5 * sizeof(char));
    char *buffer = malloc(MAX * sizeof(char));
    struct sockaddr_storage their_addr;
    socklen_t addr_size;
    struct addrinfo *res, hints, *p;
    int socketcs, new_socketcs;
    int status;
    char ipstr[INET6_ADDRSTRLEN];
    int valid = -1;


    while (valid == -1) {

        //Input
        //printf("Please enter valid Port! Example: 17\n");
        //scanf("%s", port);
        //int port_int = atoi(port);
        //if(port_int<1024 || port_int > 65535){
        //    printf("Illegal port number!");
        //    exit(1);
        //}

        printf("%s\n", argv[1]);
        //Set parameters for addrinfo struct hints; works with IPv4 and IPv6; Stream socket for connection
        memset(&hints, 0, sizeof hints);
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;
        //hints.ai_flags = AI_PASSIVE;

        //GetAddrInfo and error check
        if ((status = getaddrinfo("192.168.178.20", argv[1], &hints, &res)) != 0) {
            perror("Getaddressinfo error: ");
            exit(1);
        }
        //Save ai_family depending on IPv4 or IPv6
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
            //printf(" %s: %s\n", ipver, ipstr);
            
            //Declare and initialise socket with parameters from res structure
            socketcs = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
            if (socketcs == -1) {
                perror("Server - Socket failed: ");
                continue;
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

        }

        freeaddrinfo(res);

        int listen_int = listen(socketcs, BACKLOG);
        if(listen_int == -1){
            perror("Server - listen failed: ");
            exit(1);
        }
        printf("Server - Open for connections.\n");

        addr_size = sizeof their_addr;
        new_socketcs = accept(socketcs, (struct sockaddr *)&their_addr, &addr_size);
        if(new_socketcs == -1){
            perror("Server - Accept failed: ");
            exit(1);
        }
        char * str = malloc(MAX*sizeof(char));
        str = "YEAAAAHH I GOT IT!\n";
        int send_int = send(new_socketcs, str, MAX*sizeof(char), 0);
        if(send_int == -1){
            perror("Server - Send failed: ");
        }
        close(socketcs);
        //exit(1);
    }
    
    free(buffer);
    free(address);
    free(port);
    //freeaddrinfo(res);
    return (0);
}