#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <sys/socket.h>
#include <netinet/in.h> /* struct sockaddr_in */
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/wait.h>

#define BUFSIZE  4096
#define GRANTED  0x5a
#define REJECTED 0x5b

void handler(const int ssock, char* ip, const unsigned short port);
int connectTCP(const unsigned int ip, const unsigned short port);
int bindTCP(const unsigned short port);
int readline(int fd,char *ptr,int maxlen);

int main(int argc, const char *argv[])
{
    int msock, ssock, portno, clilen;
    struct sockaddr_in serv_addr, cli_addr;
    int n, pid1, pid2, status;

    msock = socket(AF_INET, SOCK_STREAM, 0);

    if (msock < 0) {
        fprintf(stderr, "Error on open socket\n");
        exit(1);
    }

    int opt = 1;
    setsockopt(msock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    bzero((char*)&serv_addr, sizeof(serv_addr));
    portno = 3001;

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = INADDR_ANY;
    serv_addr.sin_port = htons(portno);

    if (bind(msock, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0) {
        fprintf(stderr, "Error on bind\n");
        exit(1);
    }

    listen(msock, 64);
    clilen = sizeof(cli_addr);

    while (1) {
    
        ssock = accept(msock, (struct sockaddr*)&cli_addr, &clilen);
        
        if (ssock < 0) {
            fprintf(stderr, "Error on accept\n");
            exit(1);
        }
        
        pid1 = fork();

        if (pid1 < 0) {
            fprintf(stderr, "Error on fork\n");
            exit(1);
        }

        if (pid1 == 0) {

            pid2 = fork();

            if (pid2 < 0) {
                fprintf(stderr, "Error on  fork\n");
                exit(1);
            }

            if (pid2 == 0) {
                close(msock);
                handler(ssock, inet_ntoa(cli_addr.sin_addr), cli_addr.sin_port);
                exit(0);
            } else {
                exit(0);
            }

        } else {
            close(ssock);
            waitpid(pid1, &status, 0);
        }
    }

    return 0;
}

void handler(const int ssock, char* ip, const unsigned short port) {
    int n, rsock;
    unsigned char request[BUFSIZE];
    unsigned char reply[8];
    memset(request, 0, BUFSIZE);
    memset(reply, 0, 8);

    n = read(ssock, request, BUFSIZE - 1);
    
    unsigned char VN = request[0];
    unsigned char CD = request[1];
    unsigned short DST_PORT = (unsigned short)request[2] << 8  | request[3];
    unsigned int DST_IP = (request[7] << 24) | (request[6] << 16) | (request[5] << 8) | request[4];
    char* USER_ID = request + 8;

    if (VN != 0x04) {
        return;
    }

    char filebuf[BUFSIZE];
    char rule[10];
    char mode[10];
    char address_string[20];
    unsigned char address[4];
    char* pch;
    
    unsigned char src_address[4];
    pch = strtok(ip, ".");
    src_address[0] = (unsigned char)atoi(pch);
    pch = strtok(ip, ".");
    src_address[1] = (unsigned char)atoi(pch);
    pch = strtok(ip, ".");
    src_address[2] = (unsigned char)atoi(pch);
    pch = strtok(ip, ".");
    src_address[3] = (unsigned char)atoi(pch);

    /* src firwall check */
    FILE* src_firewall_fd;
    if ((src_firewall_fd = fopen("src_socks_conf", "r")) == NULL) {
        printf("Error on open src_firewall_check\n");
        exit(1);
    }

    reply[1] = REJECTED;
	int len = readline(fileno(src_firewall_fd), filebuf, sizeof(filebuf));
    while (len > 0) {
        sscanf(filebuf, "%s %s %s", rule, mode, address_string);
        
        pch = strtok(address_string, ".");
        address[0] = (unsigned char)atoi(pch);
        pch = strtok(NULL, ".");
        address[1] = (unsigned char)atoi(pch);
        pch = strtok(NULL, ".");
        address[2] = (unsigned char)atoi(pch);
        pch = strtok(NULL, ".");
        address[3] = (unsigned char)atoi(pch);

        if ((!strcmp(mode, "c") && CD == 0x01) || (!strcmp(mode, "b") && CD == 0X02))  {
            if (((address[0] == src_address[0]) || (address[0] == 0x00)) && 
                    ((address[1] == src_address[1]) || (address[1] == 0x00)) && 
                    ((address[2] == src_address[2]) || (address[2] == 0x00)) && 
                    ((address[3] == src_address[3]) || (address[3] == 0x00))) {
                reply[1] = GRANTED;
                break;
            }
        }
        len = readline(fileno(src_firewall_fd), filebuf, sizeof(filebuf));
    }

    if (reply[1] == GRANTED) {
        /* firewall check */
        FILE* firewall_fd;
        if ((firewall_fd = fopen("socks.conf", "r")) == NULL) {
            printf("Error on open socks.conf\n");
            exit(1);
        }

        memset(filebuf, 0, BUFSIZE);
        memset(rule, 0, 10);
        memset(mode, 0, 10);
        memset(address_string, 0, 20);

	    len = readline(fileno(firewall_fd), filebuf, sizeof(filebuf));
        while (len > 0) {
            sscanf(filebuf, "%s %s %s", rule, mode, address_string);
        
            pch = strtok(address_string, ".");
            address[0] = (unsigned char)atoi(pch);
            pch = strtok(NULL, ".");
            address[1] = (unsigned char)atoi(pch);
            pch = strtok(NULL, ".");
            address[2] = (unsigned char)atoi(pch);
            pch = strtok(NULL, ".");
            address[3] = (unsigned char)atoi(pch);

            if ((!strcmp(mode, "c") && CD == 0x01) || (!strcmp(mode, "b") && CD == 0X02))  {
                if (((address[0] == request[4]) || (address[0] == 0x00)) && 
                        ((address[1] == request[5]) || (address[1] == 0x00)) && 
                        ((address[2] == request[6]) || (address[2] == 0x00)) && 
                        ((address[3] == request[7]) || (address[3] == 0x00))) {
                    reply[1] = GRANTED;
                    break;
                }
            }
            len = readline(fileno(firewall_fd), filebuf, sizeof(filebuf));
        }
    }

    /* show connection information */
    printf("VN: %hhu, CD: %hhu, DST IP: %hhu.%hhu.%hhu.%hhu, DST PORT: %hu, USERID: %s\n", VN, CD, 
            request[4], request[5], request[6], request[7], DST_PORT, USER_ID);
    printf("Permit Src = %s(%hu), Dst = %hhu.%hhu.%hhu.%hhu(%hu)\n", ip, port, 
            request[4], request[5], request[6], request[7], DST_PORT);
    if (CD == 0x01) 
        printf("SOCKS_CONNECT ");
    else 
        printf("SOCKS_BIND ");
    if (reply[1] == 0x5a) 
        printf("GRANTED ....\n");
    else { 
        printf("REJECTED ....\n");
        fflush(stdout);
        return;
    }
    fflush(stdout);

    int nfds;
    fd_set afds, rfds;
    FD_ZERO(&afds);
    char buf[BUFSIZE];
    int s_end = 0;
    int r_end = 0;

    if (CD == 0x01) {    
        
        reply[0] = 0;
        reply[1] = (unsigned char)GRANTED;
        reply[2] = request[2];
        reply[3] = request[3];
        reply[4] = request[4];
        reply[5] = request[5];
        reply[6] = request[6];
        reply[7] = request[7];

        write(ssock, reply, 8);

        rsock = connectTCP(DST_IP, DST_PORT);   

        FD_SET(ssock, &afds);
        FD_SET(rsock, &afds);
        nfds = ((ssock < rsock) ? rsock : ssock) + 1;

        while (1) {
            if (r_end == 1 || s_end == 1) {
                close(ssock);
                close(rsock);
                break;
            }

            FD_ZERO(&rfds);
            memcpy(&rfds, &afds, sizeof(rfds));

            if (select(nfds, &rfds, NULL, NULL, NULL) < 0) {
                fprintf(stderr, "Error on select\n");
                exit(1);
            }
        
            if (FD_ISSET(rsock, &rfds)) {
                memset(buf, 0, BUFSIZE);
                n = read(rsock, buf, BUFSIZE);
                if (n > 0) {
                    n = write(ssock, buf, n);
                } else {
                    FD_CLR(rsock, &afds);
                    r_end = 1;
                }
            }

            if (FD_ISSET(ssock, &rfds)) {
                memset(buf, 0, BUFSIZE);
                n = read(ssock, buf, BUFSIZE);
                if (n > 0) {
                    n = write(rsock, buf, n);
                } else {
                    FD_CLR(ssock, &afds);
                    s_end = 1;
                }
            }
        }
    } else if (CD == 0x02) {
               
        rsock = bindTCP(DST_IP);

        int z, len;
        struct sockaddr_in sa;
        len = sizeof(sa);
        z = getsockname(rsock, (struct sockaddr*)&sa, &len);
        if (z == -1) {
            fprintf(stderr, "Error on getsockname\n");
            exit(1);
        }

        reply[0] = 0;
        reply[1] = (unsigned char)GRANTED;
        reply[2] = (unsigned char)(ntohs(sa.sin_port) / 256);
        reply[3] = (unsigned char)(ntohs(sa.sin_port) % 256);
        reply[4] = 0;
        reply[5] = 0;
        reply[6] = 0;
        reply[7] = 0;

        write(ssock, reply, 8);

        int fsock;
        struct sockaddr_in ftp_addr;
        if ((fsock = accept(rsock, (struct sockaddr*)&ftp_addr, &len)) < 0) {
            fprintf(stderr, "Error on accept in bind mode\n");
            exit(1);
        }       

        write(ssock, reply, 8);

        FD_SET(ssock, &afds);
        FD_SET(fsock, &afds);
        nfds = ((ssock < fsock) ? fsock: ssock) + 1;
    
        while (1) {
            if (r_end == 1 && s_end == 1) {
                close(ssock);
                close(fsock);
                break;
            }

            FD_ZERO(&rfds);
            memcpy(&rfds, &afds, sizeof(rfds));

            if (select(nfds, &rfds, NULL, NULL, NULL) < 0) {
                fprintf(stderr, "Error on select\n");
                exit(1);
            }
        
            if (FD_ISSET(fsock, &rfds)) {
                memset(buf, 0, BUFSIZE);
                n = read(fsock, buf, BUFSIZE);
                if (n > 0) {
                    n = write(ssock, buf, n);
                } else {
                    FD_CLR(fsock, &afds);
                    r_end = 1;
                }
            }

            if (FD_ISSET(ssock, &rfds)) {
                memset(buf, 0, BUFSIZE);
                n = read(ssock, buf, BUFSIZE);
                if (n > 0) {
                    n = write(fsock, buf, n);
                } else {
                    FD_CLR(ssock, &afds);
                    s_end = 1;
                }
            }
        }
    }
}

int connectTCP(const unsigned int ip, const unsigned short port) {
    int n, dsock;
    struct sockaddr_in dst_addr;

    dsock = socket(AF_INET, SOCK_STREAM, 0);

    bzero((char*)&dst_addr, sizeof(dst_addr));
    dst_addr.sin_family = AF_INET;
    dst_addr.sin_addr.s_addr = ip;
    dst_addr.sin_port = htons(port);
   
    int flags = fcntl(dsock, F_GETFL, 0);
    fcntl(dsock, F_SETFL, flags | O_NONBLOCK);

    while ((n = connect(dsock, (struct sockaddr*)&dst_addr, sizeof(dst_addr))) == -1) {
    }
    
    return dsock;
}

int bindTCP(const unsigned short port) {
    int n, bsock;
    struct sockaddr_in bind_addr;

    bsock = socket(AF_INET, SOCK_STREAM, 0);

    bzero((char*)&bind_addr, sizeof(bind_addr));
    bind_addr.sin_family = AF_INET;
    bind_addr.sin_addr.s_addr = INADDR_ANY;
    bind_addr.sin_port = htons(INADDR_ANY);

    if ((n = bind(bsock, (struct sockaddr*)&bind_addr, sizeof(bind_addr))) < 0) {
        fprintf(stderr, "Error on bind\n");   
        exit(1);
    }

    listen(bsock, 5);
    return bsock;
}

int readline(int fd,char *ptr,int maxlen) {
  int n, rc;
  char c;
  *ptr = 0;
  for(n = 1; n < maxlen; n++)
  {
    rc = read(fd,&c,1);
    if(rc == 1)
    {
      if(c =='\n')  break;
      *ptr++ = c;
    }
    else if(rc ==0)
    {
      if(n == 1)     return 0;
      else         break;
    }
    else return (-1);
  }
  return n;
}      
