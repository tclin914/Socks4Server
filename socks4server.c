#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <sys/socket.h>
#include <netinet/in.h> /* struct sockaddr_in */

#include <unistd.h>

#define BUFSIZE 1024
#define GRANTED 90
#define REJECTED 91

void handler(int ssock);

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

    memset((char*)&serv_addr, 0, sizeof(serv_addr));
    portno = 2266;

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
            handler(ssock);
            close(ssock);
            exit(0);
        } else {
            close(ssock);
        }
    }

    return 0;
}

void handler(int ssock) {
    int n;
    char msg_buf[BUFSIZE];
    char package[8];
    memset(msg_buf, 0, BUFSIZE);
    memset(package, 0, 8);

    n = read(ssock, msg_buf, BUFSIZE - 1);
    printf("n = %d\n", n);
    
    unsigned char VN = msg_buf[0];
    unsigned char CD = msg_buf[1];
    unsigned int DST_PORT = msg_buf[2] << 8 | msg_buf[3];
    unsigned int DST_IP = msg_buf[4] << 24 | msg_buf[5] << 16 | msg_buf[6] << 8 | msg_buf[7];
    char* USER_ID = msg_buf + 8;

    printf("VN = %d\n", VN);
    printf("CD = %d\n", CD);
    printf("DST_PORT = %d\n", DST_PORT);
    printf("DST_IP = %d\n", DST_IP);
    printf("USER_ID = %s\n", USER_ID);

    /* package[0] = 0; */
    /* package[1] = (unsigned char)GRANTED; */
    /* package[2] = DST_PORT / 256; */
    /* package[3] = DST_PORT % 256; */

}
