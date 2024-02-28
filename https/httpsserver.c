#include <stdio.h>
#include <stdlib.h>
#include <memory.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <ctype.h>

#include <mysql/mysql.h>

#include <dirent.h>
#include <time.h>

#include "threadpool.h"

#include <openssl/rsa.h>
#include <openssl/crypto.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <sys/epoll.h>

#define CERTF   "servercert.crt" /*服务端的证书(需经CA签名)*/
#define KEYF   "serverkey.pem"  /*服务端的私钥(建议加密存储)*/
#define CACERT "cacert.crt" /*CA 的证书*/
#define PORT   8090   /*准备绑定的端口*/

#define CHK_NULL(x) if ((x)==NULL) exit (1)
#define CHK_ERR(err,s) if ((err)==-1) { perror(s); exit(1); }
#define CHK_SSL(err) if ((err)==-1) { ERR_print_errors_fp(stderr); exit(2); }

enum Action{
    DOWNLOAD,
    UPLOAD,
    DELETE
};


void write_log(char* user,enum Action action,char* file){
    char message[200] = {0};
    // 获取当前时间
    time_t now = time(NULL);

    // 根据当前时间得到本地时间结构
    struct tm *local_time = localtime(&now);

    // 提取年、月、日、时、分、秒信息
    int year = local_time->tm_year + 1900;
    int month = local_time->tm_mon + 1;
    int day = local_time->tm_mday;
    int hour = local_time->tm_hour;
    int minute = local_time->tm_min;
    int second = local_time->tm_sec;

    // 打印时间信息
    sprintf(message,"[%04d-%02d-%02d %02d:%02d:%02d] ", year, month, day, hour, minute, second);
    strcat(message,user);
    if(action == DOWNLOAD) strcat(message," downloads");
    if(action == UPLOAD) strcat(message," uploads");
    if(action == DELETE) strcat(message," deletes");
    strcat(message," ");
    strcat(message,file);
    strcat(message,"\n");
    int log_fd = open("log.txt",O_WRONLY | O_APPEND);
    write(log_fd,message,strlen(message));
    close(log_fd);
}


void* binary_strstr(const void* haystack, size_t haystack_len, const void* needle, size_t needle_len) {
    if (needle_len > haystack_len) {
        return NULL;
    }

    const unsigned char* h = (const unsigned char*)haystack;
    const unsigned char* n = (const unsigned char*)needle;
    size_t max_search = haystack_len - needle_len;

    for (size_t i = 0; i <= max_search; i++) {
        if (memcmp(h + i, n, needle_len) == 0) {
            return (void*)(h + i);
        }
    }

    return NULL;
}

int correct(MYSQL *conn, char* username,char* password){

    // 1.构建查询数据的 SQL 语句
    char query[200];
    snprintf(query, sizeof(query), "SELECT * FROM user WHERE username='%s' AND password='%s'", username, password);

    // 2.执行查询语句
    if (mysql_query(conn, query)) {
        fprintf(stderr, "%s\n", mysql_error(conn));
        return -1;
    }
    
    MYSQL_RES *res = mysql_use_result(conn);
    MYSQL_ROW row = mysql_fetch_row(res);

    if (row) {
        printf("用户登录成功！\n");
    } else {
        printf("用户名或密码错误！\n");
        return 1;
    }
    mysql_free_result(res);
    return 0;
}
int registerUser(MYSQL *conn, const char *username, const char *password) {
    // 1.构建插入数据的 SQL 语句
    char query[200];
    snprintf(query, sizeof(query), "INSERT INTO user (username, password) VALUES ('%s', '%s')", username, password);

    // 2.执行 SQL 语句插入数据
    if (mysql_query(conn, query)) {
        fprintf(stderr, "%s\n", mysql_error(conn));
        printf("用户注册失败！\n");
        return 1;
    }
    else{
        char folder_name[50] = {0};
        strcat(folder_name,"");
        strcat(folder_name,username);
        strcat(folder_name,"_file");
        printf("%s",folder_name);

        if (mkdir(folder_name, 0777) == 0) {
            printf("用户注册成功！\n");
        } 
        else{
            printf("Failed to create folder.\n");
            return 1;
        }
    }
    return 0;
}


int strncmp (const char *s1, const char *s2, size_t n)
{
    char c1;
    unsigned char c2;
    while (n > 0)
    {
        c1 = (unsigned char) *s1++;
        c2 = (unsigned char) *s2++;
        if (c1 != c2)
            return c1 - c2;
        n--;
    }
    return c1-c2;
}

typedef struct Contents{
    SSL *ssl;
    int epfd;
    int curfd;
    int is_bigfile;
    char* boundary;
    char user[20];
    char password[100];
    int log_sd;
}Contents;

void taskFunc(void* arg)
{
    char  buf[40960] ={0};
    Contents* contents = (Contents*)arg;
    int err = SSL_read (contents->ssl, buf, 40960);
    int _404_status = 1;
    
    if(err > 0)
    {
    	MYSQL *conn;
  	    // 初始化 MySQL 连接
    	conn = mysql_init(NULL);
    	// 尝试连接到 MySQL 服务器
   	    if (mysql_real_connect(conn, "localhost", "root", "2358", "mydb", 0, NULL, 0) == NULL) 
        {
            fprintf(stderr, "%s\n", mysql_error(conn));
        	return ;	
        }
    	else printf("数据库连接成功！\n");
        
        
        char response[4096] = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nConnection: keep-alive\r\n"
        "Content-Length:";
        char bad_response[] = "HTTP/1.1 404 Not Found\r\nContent-Type: text/html\r\nContent-Length:";
        //用于调试，查看接收到的报文
        printf ("Got %d chars:\n%s\n\n", err, buf);
        
        char *p = strchr(buf, '/');
        //下面进行报文判断，根据不同的要求采取不同的操作
        if(*(p+1) == ' ')//返回欢迎界面，可以选择登录或者注册
        {
            int welcome_fd = open("../welcome.html",O_RDONLY);
            char welcome[10000];
            read(welcome_fd,welcome,sizeof(welcome));
            int content_length = strlen(welcome);
            char length[10];
            sprintf(length,"%d",content_length);
            strcat(response,length);
            strcat(response,"\r\n\r\n");
            strcat(response,welcome);
            SSL_write (contents->ssl, response, strlen(response));
            close(welcome_fd);
            _404_status = 0;
        }
        else if(strncmp(p,"/prelogin ",10) == 0)
        {//在欢迎界面中点击login，返回真正的登录界面
            int login_fd = open("../log.html",O_RDONLY);
            char login[10000];
            read(login_fd,login,sizeof(login));
            int content_length = strlen(login);
            char length[10];
            sprintf(length,"%d",content_length);
            strcat(response,length);
            strcat(response,"\r\n\r\n");
            strcat(response,login);
            SSL_write (contents->ssl, response, strlen(response));
            close(login_fd);
            _404_status = 0;
        }
        else if(strncmp(p,"/preregist ",11) == 0)
        {//在欢迎界面中点击register，返回真正的注册界面
            int regist_fd = open("../reg.html",O_RDONLY);
            char regist[10000];
            read(regist_fd,regist,sizeof(regist));
            int content_length = strlen(regist);
            char length[10];
            sprintf(length,"%d",content_length);
            strcat(response,length);
            strcat(response,"\r\n\r\n");
            strcat(response,regist);
            SSL_write (contents->ssl, response, strlen(response));
            close(regist_fd);
            _404_status = 0;
        }
        
        else if(strncmp(p,"/login ",7) == 0)
        {//正式处理登录请求，向数据库查询用户信息，判断是否能登录
            
            printf("hello,enter /login\n");
            
            char *username = strstr(buf,"username");
            char *hashedPassword = strstr(buf,"hashedPassword");
            
            if(username != NULL && hashedPassword != NULL)
            {
                char user[20] = {0};
                char password[100] = {0};
                char *location_begin = strchr(username,'=');
                char *location_end = strchr(username,'&');
                strncpy(user,location_begin+1,location_end-location_begin-1);
                //会被利用之前残留的hashedPassword
                //location_begin = strchr(hashedPassword,'=');
                //strncpy(password,location_begin+1,64);
                
                location_begin = buf + strlen(buf) - 64;
                strncpy(password, location_begin, 64);
                //调试信息看是否从报文中正式提取了用户名和密码
                //printf("user:%s\npassword:%s\n",user,password);

                //correct函数为向数据库进行比对，返回值为0时说明用户信息正确可以登录
                if(correct(conn, user, password)==0)
                {
                    _404_status = 0;
                    char redirect_response[200] = "HTTP/1.1 302 Found\r\nLocation: /filelist\r\n"
                    "Set-Cookie: session_id=";
                    strcat(redirect_response,user);
                    strcat(redirect_response,"&");
                    strcat(redirect_response,password);
                    
                    SSL_write(contents->ssl, redirect_response, strlen(redirect_response));
                    
                    char menu_response[10240] = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nConnection: keep-alive\r\n"
                    "Content-Length:";
                    int filelist_fd = open("filelist.html",O_RDONLY);
                    char filelist_html[5080] = {0};
                    read(filelist_fd,filelist_html,sizeof(filelist_html));
                    int content_length = strlen(filelist_html);
                    char length[10] = {0};
                    sprintf(length,"%d",content_length);
                    strcat(menu_response,length);
                    strcat(menu_response,"\r\n\r\n");
                    strcat(menu_response,filelist_html);
                    SSL_write(contents->ssl, menu_response, strlen(menu_response));
                    close(filelist_fd);
                }
                //否则返回一个页面提示用户名或密码错误，不能登录，暂时漏着吧
            }
        }
        else if(strncmp(p,"/register ",10) == 0)
        {
            
            printf("hello,enter /register\n");
            
            char *username = strstr(buf,"username");
            char *hashedPassword = strstr(buf,"hashedPassword");
            
            if(username != NULL && hashedPassword != NULL)
            {
                char user[20] = {0};
                char password[100] = {0};
                char *location_begin = strchr(username,'=');
                char *location_end = strchr(username,'&');
                strncpy(user,location_begin+1,location_end-location_begin-1);
                location_begin = buf + strlen(buf) - 64;
                strncpy(password, location_begin, 64);
                
                //printf("user:%s\npassword:%s\n",user,password);
                
                //数据库进行新增数据
                //成功则给出提示信息由用户自行手动跳转到login界面
                if(registerUser(conn, user, password) ==0)
                {
                    _404_status = 0;
                    char succ_response[4096] = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nConnection: keep-alive\r\n"
                    "Content-Length:";
                    int _succ_fd = open("../succreg.html",O_RDONLY);
	                printf("注册成功！\n");
	                char _succ[4096] = {0};
	                read(_succ_fd,_succ,sizeof(_succ));
	                int content_length = strlen(_succ);
	                char length[10] = {0};
	                sprintf(length,"%d",content_length);
	                strcat(succ_response,length);
	                strcat(succ_response,"\r\n\r\n");
	                strcat(succ_response,_succ);
	                SSL_write (contents->ssl, succ_response, strlen(succ_response));
	                close(_succ_fd);
                }
                //失败给出提示信息由用户自行手动跳转到register界面
                else{
                    _404_status = 0;
                    char fail_response[40960] = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nConnection: keep-alive\r\n"
                    "Content-Length:";
                    int _fail_fd = open("../failreg.html",O_RDONLY);
	                printf("注册失败！\n");
	                char _fail[40960] = {0};
	                read(_fail_fd,_fail,sizeof(_fail));
	                int content_length = strlen(_fail);
	                char length[10] = {0};
	                sprintf(length,"%d",content_length);
	                strcat(fail_response,length);
	                strcat(fail_response,"\r\n\r\n");
	                strcat(fail_response,_fail);
	                SSL_write (contents->ssl, fail_response, strlen(fail_response));
                    close(_fail_fd);      
                }
                
            }
        }
        else if(strncmp(p,"/filelist/search=",17) == 0)
        {
            char* user_location = strstr(buf,"session_id");
            char* password_location = strchr(buf,'&');
            char* file_begin = strstr(buf,"/filelist/search=") + 17;
            if(user_location != NULL || password_location != NULL || file_begin != NULL)
            {
                char* file_end = strstr(file_begin," ");
                *file_end = 0;
                char file[30];
                strcpy(file,file_begin);
                char user[20] = {0};
                char password[100] = {0};
                strncpy(user,user_location + 11,password_location  -user_location - 11);
                strncpy(password,password_location+1,64);
                if(correct(conn, user, password)==0)
                {
                    //printf("user:%s password:%s\n",user,password);
                    char menu_response[10240] = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n"
                    "Content-Length:";
                    int filelist_fd = open("filelist.html",O_RDONLY);
                    char filelist_html[5080] = {0};
                    read(filelist_fd,filelist_html,sizeof(filelist_html));
                    char* filelist_start = strstr(filelist_html,"<!--filelist_label-->");
                    char filelist[10240] = {0};
                    strncpy(filelist,filelist_html,filelist_start - filelist_html);
                    //printf("%s\n",filelist);
                    char file_path[50] = {0};
                    strcat(file_path,"./");
                    strcat(file_path,user);
                    strcat(file_path,"_file");
                    printf("%s\n",file_path);
                    DIR* dir = opendir(file_path);
                    while(1)
                    {
                        struct dirent* ptr = readdir(dir);
                        if(ptr == NULL)
                        {
                            //printf("目录读完了...\n");
                            break;
                        }
                        if(ptr->d_type == DT_REG)
                        {
                            char filename[30] = {0};
                            strcpy(filename,file_path);
                            strcat(filename,"/");
                            strcat(filename,ptr->d_name);
                            char file_colum[256] = "<tr><td class=\"col1\">";
                            strcat(file_colum,filename);
                            strcat(file_colum,"<td class=\"col2\"><a href=\"download/");
                            strcat(file_colum,filename);
                            strcat(file_colum,"\">下载</a></td> <td class=\"col3\"><a href=\"delete/");
                            strcat(file_colum,filename);
                            strcat(file_colum,"\">删除</a></td></tr>\n");
                            //printf("%s\n",file_colum);
                            if(strstr(ptr->d_name,file) != NULL)
                                strcat(filelist,file_colum);
                        }
                    }
                    char length[10] = {0};
                    int content_length = strlen(filelist);
                    sprintf(length,"%d",content_length);
                    strcat(menu_response,length);
                    strcat(menu_response,"\r\n\r\n");
                    strcat(menu_response,filelist);
                    SSL_write(contents->ssl, menu_response, strlen(menu_response));
                    _404_status = 0;
                }
            }
        }
        else if(strncmp(p,"/filelist ",10) == 0){
            char* user_location = strstr(buf,"session_id");
            char* password_location = strchr(buf,'&');
            if(user_location != NULL || password_location != NULL)
            {
                char user[20] = {0};
                char password[100] = {0};
                strncpy(user,user_location+11,password_location-user_location-11);
                strncpy(password,password_location+1,64);
                if(correct(conn, user, password)==0)
                {
                    //printf("user:%s password:%s\n",user,password);
                    char menu_response[10240] = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n"
                    "Content-Length:";
                    int filelist_fd = open("filelist.html",O_RDONLY);
                    char filelist_html[5080] = {0};
                    read(filelist_fd,filelist_html,sizeof(filelist_html));
                    char* filelist_start = strstr(filelist_html,"<!--filelist_label-->");
                    char filelist[10240] = {0};
                    strncpy(filelist,filelist_html,filelist_start - filelist_html);
                    //printf("%s\n",filelist);
                    char file_path[50] = {0};
                    strcat(file_path,"./");
                    strcat(file_path,user);
                    strcat(file_path,"_file");
                    printf("%s\n",file_path);
                    DIR* dir = opendir(file_path);
                    while(1)
                    {
                        struct dirent* ptr = readdir(dir);
                        if(ptr == NULL)
                        {
                            printf("目录读完了...\n");
                            break;
                        }
                        if(ptr->d_type == DT_REG)
                        {
                            char filename[30] = {0};
                            strcpy(filename,file_path);
                            strcat(filename,"/");
                            strcat(filename,ptr->d_name);
                            char file_colum[256] = "<tr><td class=\"col1\">";
                            strcat(file_colum,filename);
                            strcat(file_colum,"<td class=\"col2\"><a href=\"download/");
                            strcat(file_colum,filename);
                            strcat(file_colum,"\">下载</a></td> <td class=\"col3\"><a href=\"delete/");
                            strcat(file_colum,filename);
                            strcat(file_colum,"\">删除</a></td></tr>\n");
                            //printf("%s\n",file_colum);
                            strcat(filelist,file_colum);
                        }
                    }
                    //<tr><td class="col1">filenamename</td> <td class="col2"><a href="download/filename">下载</a></td> <td class="col3"><a href="delete/filename">删除</a></td></tr>
                    char length[10] = {0};
                    int content_length = strlen(filelist);
                    sprintf(length,"%d",content_length);
                    strcat(menu_response,length);
                    strcat(menu_response,"\r\n\r\n");
                    strcat(menu_response,filelist);
                    SSL_write(contents->ssl, menu_response, strlen(menu_response));
                    _404_status = 0;
                }
            }
        }
        else if(strncmp(p,"/download/",10) == 0)
        {
            char* user_location = p + 10;
            char* password_location = strchr(buf,'&');
            char * user_location_end = strchr(buf,'_');
            if(user_location != NULL && password_location != NULL && user_location_end != NULL)
            {
                char user[20] = {0};
                char password[100] = {0};
                strncpy(user,user_location,user_location_end - user_location);
                strncpy(password,password_location + 1,64);
                if(correct(conn, user, password)==0)
                {
                    char file_path[50] = "./";
                    char* file_path_end = strstr(buf,"HTTP");
                    strncat(file_path,user_location,file_path_end - 1 - user_location);
                    int file_num = open(file_path,O_RDONLY);
                    printf("%s\n",file_path);
                    struct stat st;
                    if(file_num > 0)
                    {
                        printf("hello download here\n");
                        stat(file_path,&st);
                        char * dy_file = (char*)malloc((int)st.st_size);
                        char length[10] = {0};
                        sprintf(length,"%d",(int)st.st_size);
                        memset(dy_file,0,(int)st.st_size);
                        read(file_num,dy_file,(int)st.st_size);
                        write_log(user,DOWNLOAD,file_path);
                        char * filedownload_response = (char*)malloc((int)st.st_size+200);
                        memset(filedownload_response,0,(int)st.st_size+200);
                        strcpy(filedownload_response,"HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\n"
                                                    "Content-Disposition: attachment; filename=\"");
                        strcat(filedownload_response,file_path);
                        strcat(filedownload_response,"\"\r\n");
                        strcat(filedownload_response,"Content-length: ");
                        strcat(filedownload_response,length);
                        strcat(filedownload_response,"\r\n\r\n");
                        int filedownload_response_length = strlen(filedownload_response);
                        memcpy(filedownload_response + filedownload_response_length,dy_file,(int)st.st_size);
                        SSL_write(contents->ssl,filedownload_response,(int)st.st_size+200);
                        _404_status = 0;
                        free(dy_file);
                        free(filedownload_response);
                        close(file_num);
                    }
                }
            }
        }
        else if(strncmp(p,"/delete/",8) == 0)
        {
            char* user_location = p + 8;
            char* password_location = strchr(buf,'&');
            char * user_location_end = strchr(buf,'_');
            if(user_location != NULL && password_location != NULL && user_location_end != NULL)
            {
                char user[20] = {0};
                char password[100] = {0};
                strncpy(user,user_location,user_location_end - user_location);
                strncpy(password,password_location + 1,64);
                if(correct(conn, user, password)==0)
                {
                    char file_path[20] = "./";
                    char* file_path_end = strstr(buf,"HTTP");
                    strncat(file_path,user_location,file_path_end - 1 - user_location);
                    int file_num = open(file_path,O_RDONLY);
                    if(remove(file_path) == 0){
                        write_log(user,DELETE,file_path);
                        _404_status = 0;
                        char redirect_response[200] = "HTTP/1.1 302 Found\r\nLocation: /filelist\r\n"
                        "Set-Cookie: session_id=";
                        strcat(redirect_response,user);
                        strcat(redirect_response,"&");
                        strcat(redirect_response,password);
                        SSL_write(contents->ssl, redirect_response, strlen(redirect_response));
                        char menu_response[10240] = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nConnection: keep-alive\r\n"
                        "Content-Length:";
                        int filelist_fd = open("filelist.html",O_RDONLY);
                        char filelist_html[5080] = {0};
                        read(filelist_fd,filelist_html,sizeof(filelist_html));
                        int content_length = strlen(filelist_html);
                        char length[10] = {0};
                        sprintf(length,"%d",content_length);
                        strcat(menu_response,length);
                        strcat(menu_response,"\r\n\r\n");
                        strcat(menu_response,filelist_html);
                        SSL_write(contents->ssl, menu_response, strlen(menu_response));
                        close(filelist_fd);
                    }
                }
            }
        }
        else if(strncmp(p,"/upload ",8) == 0)
        {
            printf("enter upload\n");
            char* user_location = strstr(buf,"session_id");
            char* password_location = strchr(buf,'&');
            if(user_location != NULL && password_location != NULL)
            {
                char user[20] = {0};
                char password[100] = {0};
                strncpy(user,user_location+11,password_location-user_location-11);
                strncpy(password,password_location+1,64);
                if(correct(conn, user, password)==0) ;
                {
                    printf("password right\n");
                    char *boundary_start, *boundary_end;
                    char *filename_start, *filename_end;
                    char *content_start, *content_end;
                    char *file_data_start, *file_data_end;
                    char *file_content;
                    boundary_start = strstr(buf, "boundary=");
                    if(!boundary_start) {printf("1");return;}
                    boundary_start += 9;
                    boundary_end = strchr(boundary_start, '\r');
                    if(!boundary_end) { printf("2");return; }
                    *boundary_end = '\0';
                    filename_start = strstr(boundary_end + 2, "filename=\"");
                    if(!filename_start) 
                    {
                        printf("3\n");
                        contents->is_bigfile = 1; 
                        contents->boundary = (char*)malloc(boundary_end - boundary_start);
                        strcpy(contents->user,user);
                        strcpy(contents->password,password);
                        strcpy(contents->boundary,boundary_start);
                        return;
                    }
                    filename_start  += 10;
                    filename_end = strchr(filename_start, '\"');
                    if(!filename_end) {printf("4");return;}
                    *filename_end = '\0';
                    printf("%s\n",filename_start);
                    content_start = strstr(filename_end + 1, "\r\n\r\n");
                    if(!content_start) {printf("5");return;}
                    content_start += 4;
                    content_end = binary_strstr(content_start, err ,boundary_start,strlen(boundary_start)) - 2;
                    printf("%s\n",content_end);
                    printf("%ld\n",strlen(buf));
                    file_data_start = content_start;
                    file_data_end = content_end;
                    int file_data_size = file_data_end - file_data_start;
                    file_content = malloc(file_data_size);
                    memcpy(file_content, file_data_start, file_data_size);
                    char file_path[500] = "./";
                    strcat(file_path,user);
                    strcat(file_path,"_file/");
                    strcat(file_path,filename_start);
                    int file_fd = open(file_path,O_RDWR | O_CREAT | O_EXCL,0744);
                    if(file_fd == -1) return;
                    write(file_fd,file_content,content_end - content_start);
                    _404_status = 0;
                    char redirect_response[200] = "HTTP/1.1 302 Found\r\nLocation: /filelist\r\n"
                    "Set-Cookie: session_id=";
                    strcat(redirect_response,user);
                    strcat(redirect_response,"&");
                    strcat(redirect_response,password);
                    SSL_write(contents->ssl, redirect_response, strlen(redirect_response));
                    write_log(user,UPLOAD,file_path);
                    char menu_response[10240] = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nConnection: keep-alive\r\n"
                    "Content-Length:";
                    int filelist_fd = open("filelist.html",O_RDONLY);
                    char filelist_html[5080] = {0};
                    read(filelist_fd,filelist_html,sizeof(filelist_html));
                    int content_length = strlen(filelist_html);
                    char length[10] = {0};
                    sprintf(length,"%d",content_length);
                    strcat(menu_response,length);
                    strcat(menu_response,"\r\n\r\n");
                    strcat(menu_response,filelist_html);
                    SSL_write(contents->ssl, menu_response, strlen(menu_response));
                    free(file_content);
                }
            }
        }
        /*else if (contents->is_bigfile)
        {
            char boundary_start[100];
            char *filename_start, *filename_end;
            char *content_start, *content_end;
            char *file_data_start, *file_data_end;
            char *file_content;
            strcpy(boundary_start,contents->boundary);
            filename_start = strstr(buf, "filename=\"");
            if(!filename_start) return;
            filename_start  += 10;
            filename_end = strchr(filename_start, '\"');
            *filename_end = '\0';
            printf("%s\n",filename_start);
            content_start = strstr(filename_end + 1, "\r\n\r\n");
            content_start += 4;
            content_end = binary_strstr(content_start, err ,boundary_start,strlen(boundary_start)) - 2;
            file_data_start = content_start;
            file_data_end = content_end;
            int file_data_size = file_data_end - file_data_start;
            file_content = malloc(file_data_size);
            memcpy(file_content, file_data_start, file_data_size);
            char file_path[500] = "./";
            strcat(file_path,contents->user);
            strcat(file_path,"_file/");
            strcat(file_path,filename_start);
            int file_fd = open(file_path,O_RDWR | O_CREAT | O_EXCL,0744);
            if(file_fd == -1) return;
            write(file_fd,file_content,content_end - content_start);
            _404_status = 0;
            char redirect_response[200] = "HTTP/1.1 302 Found\r\nLocation: /filelist\r\n"
            "Set-Cookie: session_id=";
            strcat(redirect_response,contents->user);
            strcat(redirect_response,"&");
            strcat(redirect_response,contents->password);
            SSL_write(contents->ssl, redirect_response, strlen(redirect_response));
            char menu_response[10240] = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nConnection: keep-alive\r\n"
            "Content-Length:";
            int filelist_fd = open("filelist.html",O_RDONLY);
            char filelist_html[5080] = {0};
            read(filelist_fd,filelist_html,sizeof(filelist_html));
            int content_length = strlen(filelist_html);
            char length[10] = {0};
            sprintf(length,"%d",content_length);
            strcat(menu_response,length);
            strcat(menu_response,"\r\n\r\n");
            strcat(menu_response,filelist_html);
            close(filelist_fd);
            SSL_write(contents->ssl, menu_response, strlen(menu_response));
            free(file_content);
        }*/
        
        if(_404_status){
            int _404_fd = open("../404.html",O_RDONLY);
            printf("没有响应资源！\n");
            char _404[4096] = {0};
            read(_404_fd,_404,sizeof(_404));
            int content_length = strlen(_404);
            char length[10] = {0};
            sprintf(length,"%d",content_length);
            strcat(bad_response,length);
            strcat(bad_response,"\r\n\r\n");
            strcat(bad_response,_404);
            SSL_write (contents->ssl, bad_response, strlen(bad_response));
            close(_404_fd);  
        }
        
        mysql_close(conn);
    }
    else if(err == 0)
    {
        printf("客户端已经断开了连接\n");
        // 将这个文件描述符从epoll模型中删除
        if(epoll_ctl(contents->epfd, EPOLL_CTL_DEL, contents->curfd, NULL)!=0) return;
        close(contents->curfd);
        SSL_shutdown(contents->ssl);
        SSL_free(contents->ssl);
        if(contents->is_bigfile)
        {
            contents->is_bigfile = 0;
            free(contents->boundary);
            memset(contents->user,0,20);
            memset(contents->password,0,100);
        }
        
        
    }
    if(err < 0)
    {
    	printf("err:%d\n", err);
        return ;
    }
    return;
}

int main ()
{
    int err;
    int listen_sd;
    int sd;
    struct sockaddr_in sa_serv;
    struct sockaddr_in sa_cli;
    int client_len;
    SSL_CTX* ctx;
    X509*    client_cert;
    char*    str;
    SSL* ssl[1024] = {0};
    const SSL_METHOD *meth;
    ThreadPool* pool = threadPoolCreate(3, 10, 100);
    SSL_load_error_strings();            /*为打印调试信息作准备*/
    OpenSSL_add_ssl_algorithms();        /*初始化*/
    meth = TLS_server_method();  /*采用什么协议(SSLv2/SSLv3/TLSv1)在此指定*/
    SSL_CTX_set_min_proto_version(ctx, TLS1_VERSION); // 设置最小版本为TLS 1.0
    SSL_CTX_set_max_proto_version(ctx, TLS1_2_VERSION); // 设置最大版本为TLS 1.2

    ctx = SSL_CTX_new (meth);
    CHK_NULL(ctx);
    // SSL_CTX_set_verify(ctx,SSL_VERIFY_PEER,NULL);   /*验证与否*/
    // SSL_CTX_load_verify_locations(ctx,CACERT,NULL); /*若验证,则放置CA证书*/
    if (SSL_CTX_use_certificate_file(ctx, CERTF, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(3);
    }
    if (SSL_CTX_use_PrivateKey_file(ctx, KEYF, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(4);
    }

    // if (!SSL_CTX_check_private_key(ctx)) {
    //     printf("Private key does not match the certificate public key\n");
    //     exit(5);
    // }

    /*开始正常的TCP socket过程.................................*/
    printf("Begin TCP socket...\n");

    listen_sd = socket (AF_INET, SOCK_STREAM, 0);
    CHK_ERR(listen_sd, "socket");
    int reuse = 1;
    setsockopt(listen_sd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
    memset (&sa_serv, 0, sizeof(sa_serv));
    sa_serv.sin_family      = AF_INET;
    sa_serv.sin_addr.s_addr = INADDR_ANY;
    sa_serv.sin_port        = htons (PORT);

    err = bind(listen_sd, (struct sockaddr*) &sa_serv,sizeof (sa_serv));

    CHK_ERR(err, "bind");

    /*接受TCP链接*/
    err = listen (listen_sd, 5);
    CHK_ERR(err, "listen");
    
    int epfd = epoll_create(100);
    if(epfd == -1)
    {
        perror("epoll_create");
        exit(0);
    }
    printf("你好\n");
    struct epoll_event ev;
    ev.events = EPOLLIN;    // 检测sd读读缓冲区是否有数据
    ev.data.fd = listen_sd;
    int ret = epoll_ctl(epfd, EPOLL_CTL_ADD, listen_sd, &ev);

    if(ret == -1)
    {
        perror("epoll_ctl");
        exit(0);
    }

    struct epoll_event evs[1024];

    int size = sizeof(evs) / sizeof(struct epoll_event);
    Contents *contents = (Contents *)malloc(sizeof(Contents)*1024);
    memset(contents,0,sizeof(Contents)*1024);
    for(int i = 0;i < 1024;i++){
        contents->is_bigfile = 0;
    }
    while(1){
        printf("wait for connecting...\n");
        int num = epoll_wait(epfd, evs, size, -1);
        for(int i = 0;i < num; ++i){
            int curfd = evs[i].data.fd;
            // 判断这个文件描述符是不是用于监听的
            if(curfd == listen_sd)
            {
                // 建立新的连接
                int sd = accept(curfd, NULL, NULL);
                ssl[sd] = SSL_new (ctx);
                SSL_set_fd (ssl[sd], sd);
                SSL_accept(ssl[sd]);
                printf("建立了新连接\n");
                // 新得到的文件描述符添加到epoll模型中, 下一轮循环的时候就可以被检测了
                ev.events = EPOLLIN | EPOLLET;    // 读缓冲区是否有数据
                ev.data.fd = sd;
                ret = epoll_ctl(epfd, EPOLL_CTL_ADD, sd, &ev);
                if(ret == -1)
                {
                    perror("epoll_ctl-accept");
                    exit(0);
                }
            }
            else{
                printf("SSL_accept finished\n");
                printf("当前文件描述符为:%d\n",curfd);
                contents[curfd].ssl = ssl[curfd];
                contents[curfd].curfd = curfd;
                contents[curfd].epfd = epfd;
                printf("让线程开始工作");
                threadPoolAdd(pool, taskFunc, &contents[curfd]);  
            }
        }
    }
    close(listen_sd);
    threadPoolDestroy(pool);
    SSL_CTX_free (ctx);
    free(contents);
    return 0;
}
