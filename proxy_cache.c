#include <stdio.h>
#include <string.h>
#include <openssl/sha.h>

#include <sys/types.h>
#include <unistd.h>
#include <pwd.h>

#include <sys/stat.h>
#include <stdlib.h>
#include <dirent.h>

#include <fcntl.h>
char *sha1_hash(char *input_url, char *hashed_url)
{
    unsigned char hashed_160bits[20];
    char hashed_hex[41];
    int i;

    SHA1(input_url, sizeof(input_url), hashed_160bits);

    for (i = 0; i < sizeof(hashed_160bits); i++)
        sprintf(hashed_hex + i * 2, "%02x", hashed_160bits[i]);

    strcpy(hashed_url, hashed_hex);

    return hashed_url;
}

char *getHomeDir(char *home)
{
    struct passwd *usr_info = getpwuid(getuid());
    strcpy(home, usr_info->pw_dir);
    return home;
}

int main(int argc, char const *argv[])
{
    char *Cache_Dir = (char *)calloc(32, sizeof(char));
    Cache_Dir = getHomeDir(Cache_Dir);
    strcat(Cache_Dir, "/cache"); // ~/cache

    while (1)
    {
        umask(0);

        DIR *pDir;
        struct dirent *pFile;

        char hash_dir[4];
        char *url = (char *)malloc(125 * sizeof(char));
        char *hased_url = (char *)malloc(41 * sizeof(char));

        char *dir_path = (char *)malloc(125 * sizeof(char));
        char *file_name = (char *)malloc(41 * sizeof(char));
        printf("input url>");
        scanf("%s", url);

        if (!strcmp(url, "bye"))
        {
            free(url);
            free(hased_url);
            free(dir_path);
            free(file_name);
            break;
        }

        sha1_hash(url, hased_url);

        int length = strlen(hased_url);

        if (length > 3)
        {
            int i;
            for (i = 0; i < length; i++)
            {
                if (i < 3)
                    hash_dir[i] = hased_url[i];
                else
                    file_name[i - 3] = hased_url[i];
            }
            file_name[i - 3] = '\0';

            strcpy(dir_path, Cache_Dir);
            strcat(dir_path, "/");
            strncat(dir_path, hash_dir, 3);

            if (!opendir(Cache_Dir))
                mkdir(Cache_Dir, S_IRWXG | S_IRWXU | S_IRWXO);

            pDir = opendir(dir_path);
            if (!pDir)
            {
                mkdir(dir_path, S_IRWXG | S_IRWXU | S_IRWXO);

                strcat(dir_path, "/");
                strcat(dir_path, file_name);
                creat(dir_path, 0777);
            }
            else
            {
                int n = 0;
                for (pFile = readdir(pDir); pFile; pFile = readdir(pDir))
                {
                    if (!strcmp(pFile->d_name, file_name))
                    {
                        n = 1;
                        break;
                    }
                }
                if (!n)
                    creat(dir_path, 0666);
            }
        }

        free(url);
        free(hased_url);
        free(dir_path);
        free(file_name);
    }
    free(Cache_Dir);
    return 0;
}
