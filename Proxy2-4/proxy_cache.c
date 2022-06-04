//////////////////////////////////////////////////////////////////
// File Name	: proxy_cache.c			                		//
// Date		: 2022/5/24				                        	//
// OS		: Ubuntu 16.04 LTS 64bits			                //
// Author	: Ki Hyeon Seong				                	//
// Student ID	: 2018202073					                //
// ------------------------------------------------------------ //
// Title : System Programming Assignment #2-4 (proxy server)	//
// Description : When MISS, write response cache,         	    //
//               When HIT, read response data from cache.       //
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

int childCount = 0;
time_t main_start, main_finish;

char child_add[BUFFSIZE];
in_port_t child_port;
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
            fprintf(log, "[MISS]%s-[%d/%d/%d, %d:%d:%d]\n", url, (now->tm_year) + 1900, now->tm_mon + 1, now->tm_mday, now->tm_hour, now->tm_min, now->tm_sec);
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
                fprintf(log, "[MISS]%s-[%d/%d/%d, %d:%d:%d]\n", url, (now->tm_year) + 1900, now->tm_mon + 1, now->tm_mday, now->tm_hour, now->tm_min, now->tm_sec);
                return 0;
            }
            else
            {
                // HIT 로그 출력
                time(&getTime3);
                now = localtime(&getTime3);
                fprintf(log, "[HIT]%s/%s-[%d/%d/%d, %d:%d:%d]\n", hash_dir, file_name, (now->tm_year) + 1900, now->tm_mon + 1, now->tm_mday, now->tm_hour, now->tm_min, now->tm_sec);
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
static void sigintHandler()
{
    time(&main_finish);
    int runningTime = difftime(main_finish, main_start);

    FILE *log = fopen(log_file, "a");

    fprintf(log, "**SERVER** [Terminated] run time: %02d sec. #sub process: %d\n", runningTime, childCount);
    fclose(log);

    sleep(1);
    puts("\n[Interrupt Occured(Ctrn +  C)]\n");

    exit(0);
    
}

//////////////////////////////////////////////////////////////////
// webserverHandler 			            	            	//
//==============================================================//
// Description	                                                //
//								                                //
//							                                	//
// Purpose : if there is no response during 10 seconds,         //
//           terminate child process immediately                //
//////////////////////////////////////////////////////////////////
static void webserverHandler()
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

int main(int argc, char const *argv[])
{
    time(&main_start); //시작 시간
    PARENT = getpid();
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

    bzero((char *)&server_addr, sizeof(server_addr));
    //서버의 정보를 할당함
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    server_addr.sin_port = htons(PORTNO);

    if ((socket_fd = socket(PF_INET, SOCK_STREAM, 0)) < 0) //소켓 생성
    {
        write(STDOUT_FILENO, "Server : Can't open stream socket\n", 35);
        return 0;
    }

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

        //포크
        pid = fork();

        //포크 중 오류가 생기면 
        if (pid == -1)
        {
            close(client_fd);
            close(socket_fd);
            fclose(log);
            continue;
        }
        //child 프로세스일 경우 1 증가시킴
        childCount++; 
        if (pid == 0)
        {

            strcpy(child_add, inet_ntoa(inet_client_address));
            child_port = client_addr.sin_port;

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

            int cache = -1;

            int res_len;
            char res_buf[BUFFSIZE];

            umask(0);
        
            if (read(client_fd, buf, BUFFSIZE) > 0)
            {
                strcpy(tmp, buf);

                tok = strtok(tmp, " ");
                strcpy(method, tok);

                if (strcmp(method, "GET") == 0)
                {
                    printf("[%s : %d] request GET client was connected\n", child_add, child_port);

                    tok = strtok(NULL, " ");

                    strcpy(url, (tok + 7));
                    if (url[strlen(url) - 1] == '/')
                        url[strlen(url) - 1] = '\0';
                }
                else
                {//method가 GET이 아닌 경우
                    exit(0);
                }
                printf("URL : %s\n", url);
                //HIT
                if (subProcess(url, Cache_Dir, log)) 
                {
                    printf("========== HIT ==========\n");                    
                    
                    //캐시 파일을 열지 못한경우
                    //오류 출력 후 종료
                    if (cache = open(file_path, O_RDONLY) <0)
                    {
                        printf("Can't open the Cache file\n");
                        exit(0);
                    }

                    bzero(res_buf, sizeof(res_buf));

                    res_len = 2;
                    while (res_len > 0)
                    { 
                        //캐시 파일에서 리스폰스를 읽음
                        res_len = read(cache, res_buf, res_len); 

                        //캐시 파일에서 읽은 데이터의 크기가 1이하라면,
                        //아래 구문 실행
                        if (res_len < 2) // end of file
                        {
                            if (res_len == 1)
                            {
                                write(client_fd, res_buf, 1);
                            }

                            break;
                        }

                        //읽은 데이터를 클라이언트로 보내줌
                        write(client_fd, res_buf, res_len); 
                        bzero(res_buf, (res_len + 1));      
                    }

                    printf("Completed Loading response from cache file\n\n");
                    close(cache);
                    exit(0);
                }
                else
                {//MISS
                    //SIGALRM을 감지하는 시그널 함수
                    signal(SIGALRM, webserverHandler); 

                    struct hostent *hent; // host entry
                    char *web_ip;
                    int web_fd, res_len;
                    char res_buf[BUFFSIZE];
                    char URL[BUFFSIZE];
                    bzero(res_buf, 0);

                    struct sockaddr_in web_addr;

                    strcpy(URL, url);
                    strtok(URL, "/");
                    printf("=========== MISS ==========\n");

                    hent = gethostbyname(URL);
                    if (hent == NULL)
                    {
                        printf("this domain name not exist\n\n");
                        exit(0);
                    }
                    web_ip = inet_ntoa(*((struct in_addr *)hent->h_addr_list[0]));

                    //소켓을 생성함.
                    //생성 실패시 오류 문구 출력 후 종료
                    if ((web_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
                    {
                        printf("Can't create web socket \n");
                        exit(0);
                    }

                    web_addr.sin_family = AF_INET;               
                    web_addr.sin_port = htons(HTTP_PORTNO);      
                    web_addr.sin_addr.s_addr = inet_addr(web_ip); 

                    //웹 서버와 소켓을 연결함.
                    //연결 실패시 오류문구 출력 후 종료
                    if (connect(web_fd, (struct sockaddr *)&web_addr, sizeof(web_addr)) < 0) 
                    {
                        printf("Connection fail\n");
                        exit(0);
                    }
                    printf("Connected\n");

                    //알람을 25초로 설정
                    alarm(25);
                    
                    //소켓으로 데이터를 보내줌
                    send(web_fd, buf, strlen(buf), 0);

                    DIR *pdir = opendir(dir_path);
                    if (pdir == NULL)
                        mkdir(dir_path, S_IRWXU | S_IRWXG | S_IRWXO); 
                    closedir(pdir);
                    creat(file_path, 0666);

                    //캐시 파일을 엶
                    cache = open(file_path, O_WRONLY); 

                    bzero(res_buf, sizeof(res_buf)); 

                    res_len = 2;
                    while (res_len > 0)
                    { 
                        //알람 25초 설정
                        alarm(25);

                        //소켓으로부터 리스폰스 데이터를 읽음
                        res_len = read(web_fd, res_buf, res_len); 

                        //읽어들인 데이터의 길이가 1 이하일때,
                        if (res_len < 2)
                        {
                            if (res_len == 1)
                            {
                                write(client_fd, res_buf, 1); 
                                write(cache, res_buf, 1);   
                            }
                            break;
                        }
                        
                        //읽어들인 데이터를 캐시파일과 클라이언트 소켓에 각각 써줌.
                        write(client_fd, res_buf, res_len); 
                        write(cache, res_buf, res_len);  
                        bzero(res_buf, (res_len + 1));    

                        //알람을 끔
                        alarm(0);
                    }
                    //알람을 끔
                    alarm(0);
                    printf("Complete Saving response in cache file\n\n");
                    close(cache);

                    close(web_fd);
                    exit(0);
                }
            }

            printf("[%s : %d] client was disconnected\n", inet_ntoa(client_addr.sin_addr), client_addr.sin_port);
            close(client_fd);
            exit(0);
        }
        close(client_fd);
    }
    close(socket_fd);

    return 0;
}
