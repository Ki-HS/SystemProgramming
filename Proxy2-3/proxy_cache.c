//////////////////////////////////////////////////////////////////
// File Name	: proxy_cache.c			                		//
// Date		: 2022/5/6				                        	//
// OS		: Ubuntu 16.04 LTS 64bits			                //
// Author	: Ki Hyeon Seong				                	//
// Student ID	: 2018202073					                //
// ------------------------------------------------------------ //
// Title : System Programming Assignment #2-3 (proxy server)	//
// Description : If Can't receive Http response,         	    //
//              it would print out the "No response" and exit   //
//////////////////////////////////////////////////////////////////

#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <openssl/sha.h>

#include <sys/types.h>
#include <unistd.h>
#include <pwd.h>

#include <sys/stat.h>
#include <stdlib.h>
#include <dirent.h>

#include <fcntl.h> //creat

#include <time.h> //시간

#include <sys/wait.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <signal.h>
#include <arpa/inet.h> // handle inet_addr comfile

#include <netdb.h> //gethostbyname func

#define BUFFSIZE 1024  // buffer size
#define PORTNO 39999   // port number with server
#define HTTP_PORTNO 80 // port number with HTTP protocol

int PARENT = 0;
int socket_fd, client_fd;
char Cache_Dir[BUFFSIZE]; //~/cache/ 의 경로를 담을 변수
char log_dir[BUFFSIZE];   //~/log/의 경로를 담을 변수
char log_file[BUFFSIZE];  //로그 파일의 경로를 담을 변수
char dir_path[BUFFSIZE];  //해시된 주소를 저장하는 디렉터리 경로
char file_path[BUFFSIZE]; //디렉터리 명을 제외한 주소를 저장하는 파일

///////////////////////////// end of haeder and defind data /////////////////////////////////////

//////////////////////////////////////////////////////////////////
// sha1_hash						                        	//
//==============================================================//
// Input: 	char* -> input_url		                    		//
//	 	char* -> hashed_url			                        	//
// Description:	input_url is original URL string (cahr address)	//
//		hashed_url is hashed URL string (char address)	        //
//							                                	//
//							                                  	//
// output: 	char* - hashed_url success		                	//
// Description: output is  Hashed URL string (char address)	    //
//						                                		//
// Purpose : 	input URL and return Hashed URl		        	//
//////////////////////////////////////////////////////////////////
char *sha1_hash(char *input_url, char *hashed_url)
{

    unsigned char hashed_160bits[20];
    char hashed_hex[41];
    int i;

    // input SHA1 function parameter d,n,md
    SHA1(input_url, strlen(input_url), hashed_160bits);

    for (i = 0; i < sizeof(hashed_160bits); i++)
        sprintf(hashed_hex + i * 2, "%02x", hashed_160bits[i]);

    strcpy(hashed_url, hashed_hex); // capy  hashed_hex to heashed_url

    return hashed_url;
}

//////////////////////////////////////////////////////////////////
// getHomeDir							                        //
//==============================================================//
// Input: 	char* -> home					                    //
// Description:	home is save HomeDirectory in address	    	//
//							                                	//
// output: 	char* -home success			                    	//
// Description:  return home directory path string		        //
//								                                //
// Purpose : 	get Home directory path				            //
//////////////////////////////////////////////////////////////////
char *getHomeDir(char *home)
{
    struct passwd *usr_info = getpwuid(getuid());
    strcpy(home, usr_info->pw_dir);

    return home;
}

//////////////////////////////////////////////////////////////////
// subProcess			            	            			//
//==============================================================//
// Input: 	char* -> Cache_Dir 		                    		//
//          FILE* -> log                                        //
//   	                                                   		//
// Description	                                                //
// Cache_Dir : to store user's home path           	            //
// log  : to store user's home path           	                //
//								                                //
// output: 	char* - home    		                        	//
// Description: home : to store user's home path    	        //
//							                                	//
// Purpose : to get user's home path                      		//
//////////////////////////////////////////////////////////////////
bool subProcess(char *url, char *Cache_Dir, FILE *log)
{
    int miss = 0, hit = 0; // hit 횟수와 miss 횟수를 담을 변수
    struct tm *now;        //현재 시간을 담을 변수
    time_t getTime1, getTime2, getTime3;

    umask(0); //파일 및 디렉터리 권한 부여 제한 해제

    DIR *pDir;            //디렉터리가 존재하는지 확인하기 위한 변수
    struct dirent *pFile; //디렉터리 명을 제외한 주소를 저장하는 파일 변수

    char hash_dir[4];                                    //해시된 주소를 저장하는 디렉터리 이름
    char *hased_url = (char *)malloc(41 * sizeof(char)); //해시된 url을 담기 위한 변수

    char file_name[BUFFSIZE]; //디렉터리 명을 제외한 주소를 저장하는 파일

    // url 해싱
    sha1_hash(url, hased_url);

    int length = strlen(hased_url);

    if (length > 3)
    {
        int i;
        for (i = 0; i < length; i++)
        {
            if (i < 3) //처음 세글자는 디렉터리명
                hash_dir[i] = hased_url[i];
            else //나머지는 파일 명
                file_name[i - 3] = hased_url[i];
        }
        hash_dir[3] = '\0';
        file_name[i - 3] = '\0';

        //해시 url의 디렉터리 경로 저장
        strcpy(dir_path, Cache_Dir);
        strcat(dir_path, "/");
        strncat(dir_path, hash_dir, 3);
        strcpy(file_path, dir_path);

        // Cache 디렉터리가 없으면 디렉터리 생성
        if (!opendir(Cache_Dir))
            mkdir(Cache_Dir, S_IRWXG | S_IRWXU | S_IRWXO);

        pDir = opendir(file_path);

        //해시 url의 디렉터리가 없으면
        if (!pDir)
        {
            //디렉터리 생성 후
            mkdir(file_path, S_IRWXG | S_IRWXU | S_IRWXO);
            //해당 디렉터리에 파일 저장
            strcat(file_path, "/");
            strcat(file_path, file_name);
            creat(file_path, 0666);
            // Miss 로그 출력
            time(&getTime1);
            now = localtime(&getTime1);
            fprintf(log, "[MISS] ServerPID : %ld | %s-[%d/%d/%d, %d:%d:%d]\n", (long)getpid(), url, (now->tm_year) + 1900, now->tm_mon + 1, now->tm_mday, now->tm_hour, now->tm_min, now->tm_sec);
            return 0;
        }
        else ////해시 url의 디렉터리가 있으면
        {
            strcat(file_path, "/");
            strcat(file_path, file_name);

            bool exist = false;
            //디렉터리 내 파일을 전부 읽음
            for (pFile = readdir(pDir); pFile; pFile = readdir(pDir))
            {
                //동일한 url을 입력한적 있으면 for문 탈출
                if (!strcmp(pFile->d_name, file_name))
                {
                    exist = true;
                    break;
                }
            }
            if (!exist) //해당 디렉터리에 파일 저장
            {
                creat(file_path, 0666);
                // miss log 출력
                time(&getTime2);
                now = localtime(&getTime2);
                fprintf(log, "[MISS] ServerPID : %ld | %s-[%d/%d/%d, %d:%d:%d]\n", (long)getpid(), url, (now->tm_year) + 1900, now->tm_mon + 1, now->tm_mday, now->tm_hour, now->tm_min, now->tm_sec);
                return 0;
            }
            else
            {
                // HIT 로그 출력
                time(&getTime3);
                now = localtime(&getTime3);
                fprintf(log, "[HIT] ServerPID : %ld | %s/%s-[%d/%d/%d, %d:%d:%d]\n", (long)getpid(), hash_dir, file_name, (now->tm_year) + 1900, now->tm_mon + 1, now->tm_mday, now->tm_hour, now->tm_min, now->tm_sec);
                fprintf(log, "[HIT]%s\n", url);
                return 1;
            }
        }
        closedir(pDir);
    }

    return 0;
}

//////////////////////////////////////////////////////////////////
// handler  			            	            			//
//==============================================================//
// Description	                                                //
//								                                //
//							                                	//
// Purpose : using for argument of function signal         		//
//          if any child process is not terminated,             //
//          return immediately.                                 //
//////////////////////////////////////////////////////////////////
static void handler()
{
    pid_t pid;
    int status;
    while ((pid = waitpid(-1, &status, WNOHANG)) > 0)
        ;
}

//////////////////////////////////////////////////////////////////
// sigintHandler  			            	            		//
//==============================================================//
// Description	                                                //
//								                                //
//							                                	//
// Purpose : if SIGINT is occured, terminate immediately        //
//////////////////////////////////////////////////////////////////
static void sigintHandler(int sig)
{
    puts("\n[Interrupt Occured(Ctrn +  C)]\n");
    sleep(1);

    exit(0);
}

//////////////////////////////////////////////////////////////////
// webserverHandlerM 			            	            	//
//==============================================================//
// Description	                                                //
//								                                //
//							                                	//
// Purpose : if there is no response during 10 seconds,         //
//           terminate child process immediately                //
//////////////////////////////////////////////////////////////////
static void webserverHandlerM()
{

    puts("\n[Signal]\n");
    puts("no response\n"); 

    char response_message[BUFFSIZE] = {
        0,
    };

    sprintf(response_message, "no response");
    write(client_fd, response_message, strlen(response_message));
    ; 

    remove(file_path);
    rmdir(dir_path);

    close(client_fd);
    alarm(0);
    exit(0);
}

//////////////////////////////////////////////////////////////////
// webserverHandlerH  			            	            	//
//==============================================================//
// Description	                                                //
//								                                //
//							                                	//
// Purpose : if there is no response during 10 seconds,         //
//           terminate child process immediately                //
//////////////////////////////////////////////////////////////////
static void webserverHandlerH()
{

    puts("\n[Signal]\n");
    puts("no response\n"); 

    char response_message[BUFFSIZE] = {
        0,
    };

    sprintf(response_message, "no response");
    write(client_fd, response_message, strlen(response_message));
    ; 

    close(client_fd);
    alarm(0);
    exit(0);
}

int main(int argc, char const *argv[])
{
    pid_t child;

    DIR *pLog;             //로그
    getHomeDir(Cache_Dir); // home까지의 경로를 얻음
    strcpy(log_dir, Cache_Dir);
    strcat(Cache_Dir, "/cache"); // 뒤에 /cache를 붙여줌
    strcat(log_dir, "/logfile"); // 뒤에 /log를 붙여줌
    strcpy(log_file, log_dir);
    strcat(log_file, "/logfile.txt");

    pLog = opendir(log_dir);
    // log 디렉터리가 존재하지 않으면
    if (!pLog)
    {
        // log 디렉터리와, log 파일 생성
        mkdir(log_dir, S_IRWXG | S_IRWXU | S_IRWXO);
        creat(log_file, 0777);
    }

    FILE *log;

    struct sockaddr_in server_addr, client_addr; //서버의 주소와 client의 주소를 담는 구조체 변수
    int len, len_out;                            //입력한 명령어의 크기를 담을 변수
    int state;
    char buf[BUFFSIZE]; //입력받을 버퍼
    pid_t pid;

    if ((socket_fd = socket(PF_INET, SOCK_STREAM, 0)) < 0) //소켓 생성
    {
        write(STDOUT_FILENO, "Server : Can't open stream socket\n", 35);
        return 0;
    }

    bzero((char *)&server_addr, sizeof(server_addr));
    //서버의 정보를 할당함
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    server_addr.sin_port = htons(PORTNO);

    int opt = 1;
    setsockopt(socket_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)); // Prevention bind() TIME_WAIT

    //소켓에 서버를 할당함
    if (bind(socket_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0)
    {
        write(STDOUT_FILENO, "Server : Can't bind local address\n", 35);
        close(socket_fd);
        return 0;
    }

    listen(socket_fd, 5); //연결 요청을 대기함
    signal(SIGCHLD, (void *)handler);

    int miss = 0, hit = 0;          // hit 횟수와 miss 횟수를 담을 변수
    struct tm *now;                 //현재 시간을 담을 변수
    time_t main_start, main_finish; //프로그램을 동작한 시간을 확인하기 위한 변수

    while (1)
    {
        signal(SIGINT, sigintHandler);

        struct in_addr inet_client_address;

        log = fopen(log_file, "a");

        bzero((char *)&client_addr, sizeof(client_addr));
        len = sizeof(client_addr);
        client_fd = accept(socket_fd, (struct sockaddr *)&client_addr, &len); //접속 대기

        if (client_fd < 0) //연결을 받아들이는데 실패했을 때
        {
            printf("Server : accept failed  %d\n", getpid());
            close(socket_fd);
            fclose(log);
            return 0;
        }

        inet_client_address.s_addr = client_addr.sin_addr.s_addr;
        //클라이언트와 연결되었을때
        printf("[%s : %d] client was connected\n", inet_ntoa(client_addr.sin_addr), client_addr.sin_port);
        pid = fork();

        if (pid == -1) // fork가 제대로 되지 않았을 때
        {
            close(client_fd);
            close(socket_fd);
            fclose(log);
            continue;
        }
        if (pid == 0) // child process
        {
            char tmp[BUFFSIZE] = {
                0,
            };
            char method[20] = {
                0,
            };
            char url[BUFFSIZE] = {
                0,
            };
            char *tok = NULL;

            umask(0);

            hit = 0;
            miss = 0;

            time(&main_start); //시작 시간
            //클라이언트에서 버퍼 크기만큼 읽어들임
            if ((read(client_fd, buf, BUFFSIZE)) > 0)
            {
                strcpy(tmp, buf);
                puts("==================================================");
                printf("Request from [%s : %d]\n", inet_ntoa(inet_client_address), client_addr.sin_port);
                puts("==================================================\n");

                tok = strtok(tmp, " ");
                strcpy(method, tok);
                if (strcmp(method, "GET") == 0) // if  request가 GET이라면
                {
                    tok = strtok(NULL, " ");
                    strcpy(url, tok);
                    if (url[strlen(url) - 1] == '/')
                        url[strlen(url) - 1] = '\0';
                }
                else
                {
                    exit(0);
                    break;
                } //아니면 break

                char web_server_msg[BUFFSIZE];
                bzero(web_server_msg, BUFFSIZE);
                char *URL = strtok(url, "http://");
                struct passwd *pwd = getpwuid(getuid());
                if (subProcess(url, Cache_Dir, log)) //이전에 입력했던 url을 입력했을 때
                {
                                        signal(SIGALRM, webserverHandlerH); // 10초동안 리스폰스가 없을 경우에 대한 시그널을 처리하는 핸들러 설치
                    alarm(10);
                    hit++;
                    puts("===================================\n");
                    puts("[HIT]\n");
                    FILE *c_file;                                 //캐시 파일을 엶
                    if ((c_file = fopen(file_path, "r")) == NULL) //파일을 열지 못했다면
                    {
                        puts(" response data file can't open\n");
                        exit(0);
                    }
                    while (!feof(c_file)) //파일을 끝까지 읽을동안
                    {
                        fgets(web_server_msg, sizeof(web_server_msg), c_file);    //캐시 파일에서 response data를 읽어 옴
                        write(client_fd, web_server_msg, strlen(web_server_msg)); //읽어온 메시지를 client로 보내줌.
                    }
                                        alarm(0); // 알람을 꺼줌

                    fclose(c_file);
                }
                else
                {
                    signal(SIGALRM, webserverHandlerM); // 10초동안 리스폰스가 없을 경우에 대한 시그널을 처리하는 핸들러 설치
                    miss++;

                    struct hostent *hent; // host entry
                    char *web_ip;
                    int web_fd, web_len;
                    char web_buf[BUFFSIZE];
                    bzero(web_buf, 0);

                    struct sockaddr_in web_addr;

                    puts("===================================\n");
                    puts("[MISS]\n");

                    hent = gethostbyname(URL); // URL로부터 network host entry를 가져옴
                    if (hent == NULL)          //가져오는데 실패했을 경우
                    {
                        //오류문구 출력 후 종료
                        puts("gethostbyname fucn error : this domain name not exist");
                        exit(0);
                    }

                    web_ip = inet_ntoa(*((struct in_addr *)hent->h_addr_list[0]));

                    //소켓 생성이 실패한다면
                    if ((web_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
                    {
                        //오류문구 출력 후 종료
                        printf("fail create web socket\n");
                        exit(0);
                    }

                    web_addr.sin_family = AF_INET;
                    web_addr.sin_port = htons(HTTP_PORTNO);
                    web_addr.sin_addr.s_addr = inet_addr(web_ip);

                    //웹 서버와 소켓을 연결
                    if (connect(web_fd, (struct sockaddr *)&web_addr, sizeof(web_addr)) < 0)
                    { //연결이 실패한다면
                        puts("Server not connected");
                        exit(0);
                    }
                    puts("Web server connected!");

                    alarm(10); // 10초 알람 설정

                    send(web_fd, buf, strlen(buf), 0); // web 소켓으로 데이터 전송

                    long len_buf = 0;

                    DIR *pDir = opendir(dir_path); // cache 디렉터리를 엶
                    if (!pDir)                     //디렉터리가 없으면 생성
                        mkdir(dir_path, S_IRWXU | S_IRWXG | S_IRWXO);
                    creat(file_path, 0666); //파일 생성

                    int cache_fd = open(file_path, O_WRONLY); // cache 파일을 읽기 전용으로 엶

                    web_len = read(web_fd, web_buf, BUFFSIZE); //웹 소켓에서 데이터를 읽음
                    len_buf += web_len;

                    while (web_len > 0) //데이터를 읽을 수 있는 동안
                    {
                        write(client_fd, web_buf, web_len);        // response를 클라이언트에 write함
                        write(cache_fd, web_buf, web_len);         // response를 캐시에 write함
                        web_len = read(web_fd, web_buf, BUFFSIZE); //웹 소켓에서 데이터를 읽음

                        len_buf += web_len;
                    }
                    alarm(0); // 알람을 꺼줌
                    closedir(pDir);

                    close(cache_fd);
                    // response data size
                    if (len_buf < 1)
                    {
                        remove(file_path);
                        exit(0);
                    }

                    close(web_fd); // close web socket
                }
            }
            time(&main_finish); // 종료시간 저장
            //시작 시간과 종료 시간의 차를 구함
            int sec = (int)difftime(main_finish, main_start);
            //동작시간 로그에 저장
            fprintf(log, "[Terminated] run time: %d sec. #request hit : %d, miss : %d\n", sec, hit, miss); //전체 시간 및 서브 프로세스 수 log에 기록
            fclose(log);

            printf("[%s : %d] client was disconnected\n", inet_ntoa(client_addr.sin_addr), client_addr.sin_port);
            exit(0);
        }
    }

    return 0;
}
