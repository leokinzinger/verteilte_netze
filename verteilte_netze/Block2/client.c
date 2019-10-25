#include <stdio.h>
#include "cmake-build-debug/input.h"
#include <stdlib.h>
#include <sys/socket.h>
#include <zconf.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define MAX 1000
int main() {

    char * address = malloc(20* sizeof(char));
    int port = 0;
    char buffer[MAX];
    struct sockaddr_in ServAdr;
    char ip[100];

    ServAdr.sin_family=AF_INET;
    ServAdr.sin_addr.s_addr=inet_addr(ip);
    ServAdr.sin_port=htons(port);




    input(address,&port);
    free(address);

    int socketcs = socket(PF_INET, SOCK_DGRAM, 0);
    if(socketcs==-1){
        printf("Socketcreation failed\n");
    }
    else printf("Socketcreation completed\n");




    if(connect(socketcs,(struct sockaddr*)&ServAdr, sizeof(ServAdr)==-1)){
        printf("Connection failed\n");

    }else printf("Connected\n");



    if(recv(socketcs, buffer , 1000, 0)== -1) {
        printf("Something went wrong");
    } else printf(buffer);
    close(socketcs);
    return 0;
}