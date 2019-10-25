#include <stdio.h>
#include "cmake-build-debug/input.h"
#include <stdlib.h>
#include <stdio.h>
#include <sys/socket.h>

#define MAX 1000
int main() {

    char * address = malloc(20* sizeof(char));
    int port = 0;
    char ip[100];
    char buffer[MAX];

    input(address,&port);
    free(address);

    int verbindung = socket(PF_INET, SOCK_DGRAM, 0);
    if(verbindung<0){
        printf("Keine verbindung");
    }
    else printf("Verbindung");
    connect(verbindung,ip,100);

    return 0;
}