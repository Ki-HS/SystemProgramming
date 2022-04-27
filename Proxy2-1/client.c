#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h> // handle inet_addr comfile

#define BUFFSIZE 1024
#define PORTNO 40000

int main()
{
    int socket_fd, len;
    struct sockaddr_in server_addr;
    char haddr[] = "127.0.0.1";
    char buf[BUFFSIZE];

    if ((socket_fd = socket(PF_INET, SOCK_STREAM, 0)) < 0)//소켓을 생성함
    {
        printf("can't create socket.\n");
        return -1;
    }
    bzero(buf, sizeof(buf));//버퍼를 0으로 채움
    bzero((char *)&server_addr, sizeof(server_addr));//server_addr을 0으로 채움
    server_addr.sin_family = AF_INET;//주소 체계를 AF_INET으로 정함
    server_addr.sin_addr.s_addr = inet_addr(haddr);//haddr을 바이너리 주소로 변환
    server_addr.sin_port = htons(PORTNO);//port number의 2바이트 변수에 대해 바이트 순서를 네트워크 바이트 순서로 변환해 저장

    if (connect(socket_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0)//서버의 주소와 소켓을 연결함
    {
        printf("can't connect server with local address.\n");
        close(socket_fd);
        return -1;
    }
    write(STDOUT_FILENO, "input URL > ", 13); 
    //bye가 입력되지 않고, read가 제대로 되는 동안 state진행
    while ((len = read(STDIN_FILENO, buf, sizeof(buf))) > 0)
    {
        if (!strncmp(buf, "bye", 3))
            break;
        if (write(socket_fd, buf, strlen(buf)) > 0)//버퍼의 내용을 socket_fd에 씀
        {
            if ((len = read(socket_fd, buf, sizeof(buf))) > 0)
            {
                write(STDOUT_FILENO, buf, len);//파일 디스크립터에 버퍼를 씀
                bzero(buf, sizeof(buf));
            }
        }
        write(STDOUT_FILENO, "input URL > ", 13);
    }
    close(socket_fd);
    return 0;
}