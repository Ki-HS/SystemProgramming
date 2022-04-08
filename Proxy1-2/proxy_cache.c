//////////////////////////////////////////////////////////////////
// File Name	: proxy_cache.c			                		//
// Date		: 2022/3/30				                        	//
// OS		: Ubuntu 16.04 LTS 64bits			                //
// Author	: Ki Hyeon Seong				                	//
// Student ID	: 2018202073					                //
// ------------------------------------------------------------ //
// Title : System Programming Assignment #1-1 (proxy server)	//
// Description : make cache dir, create Hashed URL file 	    //
//////////////////////////////////////////////////////////////////

#include <stdio.h>
#include <string.h>
#include <openssl/sha.h>

#include <sys/types.h>
#include <unistd.h>
#include <pwd.h>

#include <sys/stat.h>
#include <stdlib.h>
#include <dirent.h>

#include <fcntl.h> //creat

#include <time.h> //시간
//////////////////////////////////////////////////////////////////
// sha1_hash			            	            			//
//==============================================================//
// Input: 	char* -> input_url		                    		//
//	 	char* -> hashed_url		                        		//
// Description	                                                //
// input_url : original URL                  	                //
// hashed_url : converted original url as hexadecimal           //
//								                                //
// output: 	char* - hashed_url		                        	//
// Description: output : Hashed URL string (char address)	    //
//							                                	//
// Purpose : hash the original url                      		//
//////////////////////////////////////////////////////////////////
char *sha1_hash(char *input_url, char *hashed_url)
{
    unsigned char hashed_160bits[20]; //해시된 160bits의 값
    char hashed_hex[41];              // hashed_160bits 를 1byte 씩 16 진수로 표현하고 , 이를 문자열로 변환한 것
    int i;

    //입력받은 url을 해싱하는 함수
    SHA1(input_url, sizeof(input_url), hashed_160bits);
    // 16진수로 표현하고, 문자열로 변환하기 위한 과정
    for (i = 0; i < sizeof(hashed_160bits); i++)
        sprintf(hashed_hex + i * 2, "%02x", hashed_160bits[i]);

    strcpy(hashed_url, hashed_hex);

    return hashed_url;
}

//////////////////////////////////////////////////////////////////
// getHomeDir			            	            			//
//==============================================================//
// Input: 	char* -> home   		                    		//
//	 	                    	                        		//
// Description	                                                //
// home : to store user's home path             	            //
//								                                //
// output: 	char* - home    		                        	//
// Description: home : to store user's home path    	        //
//							                                	//
// Purpose : to get user's home path                      		//
//////////////////////////////////////////////////////////////////
char *getHomeDir(char *home)
{
    struct passwd *usr_info = getpwuid(getuid()); //사용자의 상세정보를 얻는 함수
    strcpy(home, usr_info->pw_dir);
    return home;
}

int main(int argc, char const *argv[])
{
    char *Cache_Dir = (char *)calloc(32, sizeof(char)); //~/cache/ 의 경로를 담을 변수
    char *log_dir = (char *)calloc(32, sizeof(char));   //~/log/의 경로를 담을 변수
    char *log_file = (char *)calloc(32, sizeof(char));  //로그 파일의 경로를 담을 변수
    DIR *pLog;                                          //로그
    Cache_Dir = getHomeDir(Cache_Dir);                  // home까지의 경로를 얻음
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

    FILE *log = fopen(log_file, "a");

    int miss = 0, hit = 0; // hit 횟수와 miss 횟수를 담을 변수
    struct tm *now;        //현재 시간을 담을 변수
    time_t getTime1, getTime2, getTime3;
    time_t start, finish; //프로그램을 동작한 시간을 확인하기 위한 변수
    time(&start);         //시작 시간
    while (1)
    {
        umask(0); //파일 및 디렉터리 권한 부여 제한 해제

        DIR *pDir;            //디렉터리가 존재하는지 확인하기 위한 변수
        struct dirent *pFile; //디렉터리 명을 제외한 주소를 저장하는 파일 변수

        char hash_dir[4];                                    //해시된 주소를 저장하는 디렉터리 이름
        char *url = (char *)malloc(125 * sizeof(char));      // url을 입력받기 위한 변수
        char *hased_url = (char *)malloc(41 * sizeof(char)); //해시된 url을 담기 위한 변수

        char *dir_path = (char *)malloc(125 * sizeof(char)); //해시된 주소를 저장하는 디렉터리 경로
        char *file_name = (char *)malloc(41 * sizeof(char)); //디렉터리 명을 제외한 주소를 저장하는 파일
        printf("input url>");
        scanf("%s", url);

        // bye를 입력하면 동적할당 해제 후 while문 탈출
        if (!strcmp(url, "bye"))
        {
            free(url);
            free(hased_url);
            free(dir_path);
            free(file_name);
            break;
        }
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

            // Cache 디렉터리가 없으면 디렉터리 생성
            if (!opendir(Cache_Dir))
                mkdir(Cache_Dir, S_IRWXG | S_IRWXU | S_IRWXO);

            pDir = opendir(dir_path);
            //해시 url의 디렉터리가 없으면
            if (!pDir)
            {
                //디렉터리 생성 후
                mkdir(dir_path, S_IRWXG | S_IRWXU | S_IRWXO);
                //해당 디렉터리에 파일 저장
                strcat(dir_path, "/");
                strcat(dir_path, file_name);
                creat(dir_path, 0777);
                // Miss 로그 출력
                time(&getTime1);
                now = localtime(&getTime1);
                fprintf(log, "[MISS]%s-[%d/%d/%d, %d:%d:%d]\n", url, (now->tm_year) + 1900, now->tm_mon + 1, now->tm_mday, now->tm_hour, now->tm_min, now->tm_sec);
                miss++; // miss 카운트 증가
            }
            else ////해시 url의 디렉터리가 있으면
            {
                int n = 0;
                //디렉터리 내 파일을 전부 읽음
                for (pFile = readdir(pDir); pFile; pFile = readdir(pDir))
                {
                    //동일한 url을 입력한적 있으면 for문 탈출
                    if (!strcmp(pFile->d_name, file_name))
                    {
                        n = 1;
                        break;
                    }
                }
                if (!n) //해당 디렉터리에 파일 저장
                {
                    creat(dir_path, 0777);
                    // miss log 출력
                    time(&getTime2);
                    now = localtime(&getTime2);
                    fprintf(log, "[MISS]%s-[%d/%d/%d, %d:%d:%d]\n", url, (now->tm_year) + 1900, now->tm_mon + 1, now->tm_mday, now->tm_hour, now->tm_min, now->tm_sec);
                    miss++; // miss 카운트 증가
                }
                else
                {
                    // HIT 로그 출력
                    time(&getTime3);
                    now = localtime(&getTime3);
                    fprintf(log, "[HIT]%s/%s\n", hash_dir, file_name);
                    fprintf(log, "[HIT]%s-[%d/%d/%d, %d:%d:%d]\n", url, (now->tm_year) + 1900, now->tm_mon + 1, now->tm_mday, now->tm_hour, now->tm_min, now->tm_sec);
                    hit++;
                }
            }
        }

        free(url);
        free(hased_url);
        free(dir_path);
        free(file_name);
    }
    time(&finish); // 종료시간 저장
    //시작 시간과 종료 시간의 차를 구함
    int sec = (int)difftime(finish, start);
    //동작시간 로그에 저장
    fprintf(log, "[Terminated] run time: %d sec. #request hit : %d, miss : %d\n", sec, hit, miss);
    fclose(log);
    free(log_dir);
    free(Cache_Dir);
    return 0;
}
