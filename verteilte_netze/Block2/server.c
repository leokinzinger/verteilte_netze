//
// Created by Niklas Teschner on 26.10.19.
//
#include <stdio.h>
#define PORT 2222
int main(){
int socketcn, new_cn;
struct addrinfo hints, *servinf, *f;
int servstatus;
int mode=1;
memset(&hints, 0, sizeof hints);
hints.ai_family=AF_UNSPEC;
hints.ai_socktype=SOCK_STREAM;
hints.ai_flags=AI_PASSIVE;
if(servinf=getaddrinfo(NULL,PORT,&hints,&servinf)!=0)
    printf("Fehler");

}
for(f = servinf; f != NULL; f= f->ai_next) {
    if ((sockcn = socket(f->ai_family, f->ai_socktype, f->ai_protocol)) == -1) {
        printf("Socket Müll");
    }

}
if(bind(sockcn,f->ai_addr, f->addr_len)!=0)

//TODO Leo codet den Bumms und kommentiert alles

