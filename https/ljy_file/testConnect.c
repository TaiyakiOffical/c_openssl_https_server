#include <mysql/mysql.h>
#include <stdio.h>

int registerUser(MYSQL *conn, const char *username, const char *password) {
    // 1.构建插入数据的 SQL 语句
    char query[200];
    snprintf(query, sizeof(query), "INSERT INTO user (username, password) VALUES ('%s', SHA2('%s',256))", username, password);

    // 2.执行 SQL 语句插入数据
    if (mysql_query(conn, query)) {
        fprintf(stderr, "%s\n", mysql_error(conn));
        printf("用户注册失败！\n");
        return 1;
    }

    printf("用户注册成功！\n");
    return 0;
}

int loginUser(MYSQL *conn, const char *username, const char *password) {
    // 1.构建查询数据的 SQL 语句
    char query[100];
    snprintf(query, sizeof(query), "SELECT * FROM user WHERE username = '%s' AND password = SHA2('%s',256)", username, password);

    // 2.执行查询语句
    if (mysql_query(conn, query)) {
        fprintf(stderr, "%s\n", mysql_error(conn));
        return 1;
    }
    
    MYSQL_RES *res = mysql_use_result(conn);
    MYSQL_ROW row = mysql_fetch_row(res);

    if (row) {
        printf("用户登录成功！\n");
    } else {
        printf("用户名或密码错误！\n");
    }
    
    while ((row = mysql_fetch_row(res)) != NULL) 
        printf("ID: %s, Username: %s, Password: %s, Online:%s\n", row[0], row[1], row[2], row[3]);
    
    mysql_free_result(res);
    return 0;
}

int main() {
    MYSQL *conn;

    // 初始化 MySQL 连接
    conn = mysql_init(NULL);
  
    // 尝试连接到 MySQL 服务器
    if (mysql_real_connect(conn, "localhost", "root", "2358", "mydb", 0, NULL, 0) == NULL) {
        fprintf(stderr, "%s\n", mysql_error(conn));
        return 1;
    }
    
    // 获取用户的用户名和密码
    char username[50], password[50];
    printf("请输入用户名：");
    scanf("%s", username);
    printf("请输入密码：");
    scanf("%s", password);
    
    // 调用注册函数
    registerUser(conn, username, password);

    // 调用登录函数
    loginUser(conn, username, password);

    // 释放连接
    mysql_close(conn);
    return 0;
    
}

