#include <unistd.h>  
#include <stdio.h>
#include <stdlib.h>    
#include <sys/socket.h>  
#include <linux/in.h>  
#include <string.h>  
#include <errno.h>  
  
#define SOCKET_OPT_BASE 128
#define SOCKET_OPT_SETTARGET (128)
#define SOCKET_OPT_GETTARGET (128)
#define SOCKET_OPT_MAX (SOCKET_OPT_BASE+1) 
    
#define MSG_LEN  1024  

static const char info_message[] =
	"upredirect - udp proxy daemon\n"
    "zuoyipeng@chinacache.com\n\n";
static const char help_message[] =
	"Usage: pdnsd [-h] [-g] [-d port] [-a port]" 
	"Options:\n"
	"-h\t\t--or--\n"
	"--help\t\tprint this help page and exit.\n"
	"-g\t\tprint all proxy ports and exit.\n"
	"-a port\t\tadd proxy port into kernel model and exit.\n"
	"-d port\t\tdel proxy port from kernel model and exit.\n" ;  	
char kmsg[MSG_LEN];  
char check_arg_is_num(char *argv, int len){
    char flag = 0;
    int i = 0;
    for(; i<len; i++){
        if (argv[i]>='0' && argv[i]<='9'){
            continue;       
        }
        else{
            flag = -1;
            break;
        }                
    }   
    return flag;
}  
int main(int argc, char *argv[])  
{  
    int sockfd;  
    int len;  
    int ret;  
    int i=0;
    char test_msg[16] = {'\0'};
    char cmd_type = '\0';
    for (i=1; i<argc; i++) {
        char *arg=argv[i];
        if (strcmp(arg,"-h")==0 || strcmp(arg,"--help")==0) {
			fputs(info_message, stdout);
			fputs(help_message, stdout);
			exit(1);
		}
        else if (strcmp(arg, "-g") == 0){            
            cmd_type = 'g';
        }
        else if (strcmp(arg, "-a") == 0){
            if (++i<argc) {
                if(check_arg_is_num(argv[i], strlen(argv[i]))<0) {
                    fprintf(stderr,"Error: port is expected as num\n");
                    exit(1);                   
                }
                test_msg[0] = 'a';
                sprintf(&test_msg[1], " %s", argv[i]);
                cmd_type = 'a';
            } else {
                fprintf(stderr,"Error: port expected after %s option.\n", arg);
                exit(1);
            }
        } 
       else if (strcmp(arg, "-d") == 0) {
            if (++i<argc) {
                if(check_arg_is_num(argv[i], strlen(argv[i]))<0) {
                    fprintf(stderr,"Error: port is expected as num\n");
                    exit(1);                   
                }
                test_msg[0] = 'd';
                sprintf(&test_msg[1], " %s", argv[i]);
                cmd_type = 'd';
            } else {
                fprintf(stderr,"Error: port expected after %s option.\n", arg);
                exit(1);
            }
        }
        else{ 
            fprintf(stderr,"Error args.\n");   
            exit(1);
        }           
    }
    sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);  
    if(sockfd < 0)  
    {  
        perror("can not create a socket");  
        exit(1);  
    }  
    if (cmd_type == 'a'){
        ret = setsockopt(sockfd, IPPROTO_IP, SOCKET_OPT_SETTARGET, test_msg, strlen(test_msg));  
        if (ret != 0)  
        {  
            printf("getsockopt error: errno = %d, errstr = %s\n", errno, strerror(errno));  
        }    
        //printf("setsockopt: ret = %d. msg = %s\n", ret, test_msg);
        printf("add redirect udp port %s\n", test_msg+2);    
    }
    else if (cmd_type == 'd'){
        ret = setsockopt(sockfd, IPPROTO_IP, SOCKET_OPT_SETTARGET, test_msg, strlen(test_msg));  
        if (ret != 0)  
        {  
            printf("getsockopt error: errno = %d, errstr = %s\n", errno, strerror(errno));  
        }    
        //printf("setsockopt: ret = %d. msg = %s\n", ret, test_msg);
        printf("del redirect udp port %s\n", test_msg+2);    
    }        
    else if (cmd_type == 'g'){
        len = MSG_LEN;  
        ret = getsockopt(sockfd, IPPROTO_IP, SOCKET_OPT_GETTARGET, kmsg, &len);  
        if (ret != 0)  
        {  
            printf("getsockopt error: errno = %d, errstr = %s\n", errno, strerror(errno));  
        }         
        //printf("getsockopt: ret = %d. msg = %s\n", ret, kmsg);  
        printf("redirect udp port is %s\n", kmsg);        
    }
    close(sockfd);  
    return 0;  
}  