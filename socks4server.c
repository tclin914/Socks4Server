#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <sys/socket.h>
#include <netinet/in.h> /* struct sockaddr_in */
#include <arpa/inet.h>

#include <unistd.h>

#define BUFSIZE 4096
#define GRANTED 90
#define REJECTED 91

void handler(int ssock, char* ip, unsigned short port);
int connectTCP(unsigned int ip, unsigned short port);

int main(int argc, const char *argv[])
{
    int msock, ssock, portno, clilen;
    struct sockaddr_in serv_addr, cli_addr;
    int n, pid;

    msock = socket(AF_INET, SOCK_STREAM, 0);

    if (msock < 0) {
        fprintf(stderr, "Error on open socket\n");
        exit(1);
    }

    int opt = 1;
    setsockopt(msock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    bzero((char*)&serv_addr, sizeof(serv_addr));
    portno = 4433;

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = INADDR_ANY;
    serv_addr.sin_port = htons(portno);

    if (bind(msock, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0) {
        fprintf(stderr, "Error on bind\n");
        exit(1);
    }

    listen(msock, 5);
    clilen = sizeof(cli_addr);

    while (1) {
    
        ssock = accept(msock, (struct sockaddr*)&cli_addr, &clilen);

        fprintf(stdout, "ssock = %d\n", ssock);
        fflush(stdout);

        if (ssock < 0) {
            fprintf(stderr, "Error on accept\n");
            exit(1);
        }

        pid = fork();

        if (pid < 0) {
            fprintf(stderr, "Error on fork\n");
            exit(1);
        }

        if (pid == 0) {
            close(msock);
            handler(ssock, inet_ntoa(cli_addr.sin_addr), cli_addr.sin_port);
            /* close(ssock); */
            exit(0);
        } else {
            close(ssock);
        }
    }

    return 0;
}

void handler(int ssock, char* ip, unsigned short port) {
    int n, rsock;
    char request[BUFSIZE];
    char reply[8];
    memset(request, 0, BUFSIZE);
    memset(reply, 0, 8);

    n = read(ssock, request, BUFSIZE - 1);
    printf("n = %d\n", n);
    
    unsigned char VN = request[0];
    unsigned char CD = request[1];
    unsigned short DST_PORT = request[2] << 8 | request[3];
    unsigned int DST_IP = request[7] << 24 | request[6] << 16 | request[5] << 8 | request[4];
    char* USER_ID = request + 8;

    printf("VN: %hhu, CD: %hhu, DST IP: %hhu.%hhu.%hhu.%hhu, DST PORT: %hu, USERID: %s\n", VN, CD, 
            request[4], request[5], request[6], request[7], DST_PORT, USER_ID);
    printf("Permit Src = %s(%hu), Dst = %hhu.%hhu.%hhu.%hhu(%hu)\n", ip, port, 
            request[4], request[5], request[6], request[7], DST_PORT);
    fflush(stdout);

    if (VN != 0x04) {
        exit(0);
    }

    int nfds;
    fd_set afds, rfds;
    FD_ZERO(&afds);
    char buf[BUFSIZE];
    int s_end = 0;
    int r_end = 0;

    if (CD == 0x01) {    
        printf("connect mode\n");
        rsock = connectTCP(DST_IP, DST_PORT);   
        printf("rsock = %d\n", rsock);
        
        reply[0] = 0;
        reply[1] = (unsigned char)GRANTED;
        reply[2] = request[2];
        reply[3] = request[3];
        reply[4] = request[4];
        reply[5] = request[5];
        reply[6] = request[6];
        reply[7] = request[7];

        write(ssock, reply, 8);

        FD_SET(ssock, &afds);
        FD_SET(rsock, &afds);
        nfds = ((ssock < rsock) ? rsock : ssock) + 1;

        while (1) {
            /* if (r_end == 1 && s_end == 1) { */
                /* close(ssock); */
                /* close(rsock); */
                /* return; */
            /* } */

            FD_ZERO(&rfds);
            memcpy(&rfds, &afds, sizeof(rfds));

            if (select(nfds, &rfds, NULL, NULL, NULL) < 0) {
                fprintf(stderr, "Error on select\n");
                exit(1);
            }
        
            if (FD_ISSET(rsock, &rfds)) {
                printf("rsock\n");
                memset(buf, 0, BUFSIZE);
                n = read(rsock, buf, BUFSIZE);
                if (n > 0) {
                    buf[n] = '\0';
                    printf("%s\n", buf);
                    n = write(ssock, buf, n);
                } else {
                    FD_CLR(rsock, &afds);
                    r_end = 1;
                }
            }

            if (FD_ISSET(ssock, &rfds)) {
                printf("ssock\n");
                memset(buf, 0, BUFSIZE);
                n = read(ssock, buf, BUFSIZE);
                if (n > 0) {
                    buf[n] = '\0';
                    printf("%s\n", buf);
                    n = write(rsock, buf, n);
                } else {
                    FD_CLR(ssock, &afds);
                    s_end = 1;
                }
            }
        }

        /* int n, dsock; */
        /* int dsock; */
        /* struct sockaddr_in dst_addr; */

        /* dsock = socket(AF_INET, SOCK_STREAM, 0); */

        /* bzero((char*)&dst_addr, sizeof(dst_addr)); */
        /* dst_addr.sin_family = AF_INET; */
        /* dst_addr.sin_addr.s_addr = DST_IP;  */
        /* dst_addr.sin_port = htons(DST_PORT); */
     
        /* if (connect(dsock, (struct sockaddr*)&dst_addr, sizeof(dst_addr)) < -1) { */
            /* fprintf(stderr, "Error on connect\n"); */
            /* exit(1); */
        /* } */
        /* printf("n = %d\n", n); */
        /* printf("dsock = %d\n", dsock); */

        /* printf("debug\n"); */
        
    }
}

int connectTCP(unsigned int ip, unsigned short port) {
    int n, dsock;
    struct sockaddr_in dst_addr;

    dsock = socket(AF_INET, SOCK_STREAM, 0);

    bzero((char*)&dst_addr, sizeof(dst_addr));
    dst_addr.sin_family = AF_INET;
    dst_addr.sin_addr.s_addr = ip; 
    dst_addr.sin_port = htons(port);
     
    if ((n = connect(dsock, (struct sockaddr*)&dst_addr, sizeof(dst_addr))) < -1) {
        fprintf(stderr, "Error on connect\n");
        exit(1);
    }
    printf("dsock = %d\n", dsock);
    return dsock;
}
