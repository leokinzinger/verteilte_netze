#include <string.h>
//#include "cmake-build-debug/input.h"
#include <stdlib.h>
#include <sys/socket.h>
#include <zconf.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <stdio.h>
#include <time.h>

#define MAX 512
#define BACKLOG 1
#define IP "192.168.178.20"
#define PORT "2222"
#define DOC "quotes.txt"

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

    FILE * file_pointer;
    char * str = malloc(MAX* sizeof(char));



    /*
    //Input
    if(argc != 3){
        perror("Server - Function parameters: (./server) port_number text_dokument");
        exit(1);
    }
     */
    //Check if port number is in range
    //int port_int = atoi(argv[1]);
    int port_int = atoi(PORT);
    if(port_int<1024 || port_int > 65535){
        printf("Illegal port number!");
        exit(1);
    }
    //file_pointer=fopen(argv[2],"r");
    file_pointer=fopen(DOC,"r");
    if(file_pointer==NULL){
        perror("Server - File did not open: ");
        exit(1);
    }

    //Set parameters for addrinfo struct hints; works with IPv4 and IPv6; Stream socket for connection
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    //hints.ai_flags = AI_PASSIVE;

    //GetAddrInfo and error check
    //if ((status = getaddrinfo(IP, argv[1], &hints, &res)) != 0) {
    if ((status = getaddrinfo(IP, PORT, &hints, &res)) != 0) {
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
        //printf(" %s: %s\n", ipver, ipstr);

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
    //free(buffer);
    //free(address);
    //free(port);

    while(1){
        addr_size = sizeof their_addr;
        new_socketcs = accept(socketcs, (struct sockaddr *)&their_addr, &addr_size);
        if(new_socketcs == -1) {
            perror("Server - Accept failed: ");
            exit(1);
        }
        char * buffer = malloc(MAX * sizeof(char));
        int line_counter = 0;
        while(fgets(buffer, MAX, file_pointer) != NULL){
            line_counter++;
        }
        printf("Linecounter: %d",line_counter);
        fseek(file_pointer, 0, SEEK_SET);

        //https://www.tutorialspoint.com/c_standard_library/c_function_rand.htm
        time_t t;
        srand((unsigned) time(&t));
        int random_elem = rand() % line_counter;
        printf("Random element: %d",random_elem);

        for(int i=0; i<=random_elem; i++){
            if(fgets(str,MAX,file_pointer) == NULL){
                perror("Server - Failed to read line: ");
                exit(1);
            }
        }
        int send_int = send(new_socketcs, str, MAX*sizeof(char), 0);
        if(send_int == -1){
            perror("Server - Send failed: ");
        }
        fclose(file_pointer);
    }
    return (0);
}