//
// Created by Leonard Kinzinger on 23.10.19.
//
# import <stdio.h>
#include<string.h>
#include <ctype.h>
// Modes: 0:Stable 1:Testing
#define MODE 0

void input(char *address, int *port){

    int mode = MODE;
    char valid;     // valid states: i=initial, v=valid, n=not valid
    char state;     //states: p=ip-address, d=dns-address, i=initial

    while(valid != 'v'){
        valid = 'i'; state = 'i'; //initialise valid and state

        printf("Please enter valid IP-Address/DNS-Address AND Port! Example: djxmmx.net 80\n");
        scanf("%s %d", address, port);
        if(mode == 1) printf("The Address is: %s, Port: %d\n", address, *port);

        //Count number of dots in address
        int counter = 0;
        for(int i = 0; i<strlen(address);i++){
            if(*(address+i) == '.') counter++;
        }

        if(counter == 1 || counter == 2) {
            state = 'd'; valid = 'v';
        }else if(counter == 3) {
            state = 'p'; valid = 'v';
        }else valid = 'n';

        if(mode == 1) printf("State: %c, Valid: %c \n",state,valid);

        //validate DNS or IP depending on the state
        if(state == 'd') validate_DNS(address);
        else if(state == 'p'){
            if(validate_IP(address) == 1) valid = 'v';
            else{
                valid = 'n';
                printf("Invalid IP-Address!\n");
            }
        }
        //validate the port by checking it's scope
        if(*(port) < 0 || *(port) > 65535) {
            valid = 'n';
            printf("Illegal port number! Port: %d\n",port);
        }
    }
}
// CODE FROM https://www.tutorialspoint.com/c-program-to-validate-an-ip-address
int validate_IP(char* ip){
    printf("Validate IP.......\n");
    int i, num, dots = 0;
    char *ptr;
    if (ip == NULL)
        return 0;
    ptr = strtok(ip, "."); //cut the string using dor delimiter
    if (ptr == NULL)
        return 0;
    while (ptr) {
        if (!validate_number(ptr)) return 0;//check whether the sub string is holding only number or not
        num = atoi(ptr); //convert substring to number
        if (num >= 0 && num <= 255) {
            ptr = strtok(NULL, "."); //cut the next part of the string
            if (ptr != NULL)
                dots++; //increase the dot count
        } else return 0;
    }
    if (dots != 3) //if the number of dots are not 3, return false
        return 0;
    printf("Valid IP\n");
    return 1;
}

int validate_DNS(char* address){
    printf("Validate DNS......\n");
    printf("Valid DNS\n");
}

// CODE FROM https://www.tutorialspoint.com/c-program-to-validate-an-ip-address
int validate_number(char *str) {
    while (*str) {
        if(!isdigit(*str)){ //if the character is not a number, return false
            return 0;
        }
        str++; //point to next character
    }
    return 1;
}

