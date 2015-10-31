/* A TCP echo server with timeouts.
 *
 * Note that you will not need to use select and the timeout for a
 * tftp server. However, select is also useful if you want to receive
 * from multiple sockets at the same time. Read the documentation for
 * select on how to do this (Hint: Iterate with FD_ISSET()).
 */

#include <assert.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <glib.h>
#include <arpa/inet.h>

/* Secure socket layer headers */
#include <openssl/ssl.h>
#include <openssl/err.h>

/* Macros */
#define MAX_CONNECTIONS 5

/**/
struct connection {
    int connfd;
    SSL *ssl;
};

/**/
gboolean print_tree(gpointer key, gpointer value, gpointer data) {
    fprintf(stdout, "inside print tree!\n");
    struct connection *conn = (struct connection *) value;
    fprintf(stdout, "connfd: %d\n", conn->connfd);
    fflush(stdout);
} 

/**/
gboolean is_greater_fd(gpointer key, gpointer value, gpointer data) {
    fprintf(stdout, "inside print tree!\n");
    struct connection *conn = (struct connection *) value;
    int fd = *(int *) data;
    fprintf(stdout, "connfd: %d -- fd: %d\n", conn->connfd, fd);
    fflush(stdout);

    if(conn->connfd > fd) {
        *(int *)data = conn->connfd;
    }

    return FALSE;
} 

/**/
gboolean check_connection(gpointer key, gpointer value, gpointer data) {
    fprintf(stdout, "inside check connection\n");
    struct connection *conn = (struct connection *) value;
    fprintf(stdout, "connfd: %d\n", conn->connfd);
    fflush(stdout);
} 

/* Function that is called when we get a 'bye' message from the client. */
void bye(FILE *fp, struct sockaddr_in client) {
    /* Creating the timestamp. */
    time_t now;
    time(&now);
    char buf[sizeof "2011-10-08T07:07:09Z"];
    memset(buf, 0, sizeof(buf));
    strftime(buf, sizeof buf, "%Y-%m-%dT%H:%M:%SZ", gmtime(&now));
    /* Write disconnect info to screen. */
    fprintf(stdout, "%s : %s:%d %s \n", buf, inet_ntoa(client.sin_addr), client.sin_port, "disconnected");
    fflush(stdout);
    /* Write disconnect info to file. */
    fprintf(fp, "%s : %s:%d %s \n", buf, inet_ntoa(client.sin_addr), client.sin_port, "disconnected");
    fflush(fp);
}

/* This can be used to build instances of GTree that index on
   the address of a connection. */
int sockaddr_in_cmp(const void *addr1, const void *addr2) {
    const struct sockaddr_in *_addr1 = addr1;
    const struct sockaddr_in *_addr2 = addr2;

    /* If either of the pointers is NULL or the addresses
       belong to different families, we abort. */
    g_assert((_addr1 == NULL) || (_addr2 == NULL) ||
            (_addr1->sin_family != _addr2->sin_family));

    if (_addr1->sin_addr.s_addr < _addr2->sin_addr.s_addr) {
        return -1;
    } else if (_addr1->sin_addr.s_addr > _addr2->sin_addr.s_addr) {
        return 1;
    } else if (_addr1->sin_port < _addr2->sin_port) {
        return -1;
    } else if (_addr1->sin_port > _addr2->sin_port) {
        return 1;
    }
    return 0;
}

int main(int argc, char **argv) {
    /* Create filepointer for log file */
    FILE *fp;
    fprintf(stdout, "SERVER INITIALIZING -- %d C00L 4 SCH00L!\n", argc);
    fflush(stdout);
    int sockfd, sock, listen_sock;
    struct sockaddr_in server, client;
    char *str;
    size_t client_len;
    char message[512];
    char recvMessage[8196];

    SSL_CTX *ctx;
    SSL *ssl;
    SSL_METHOD *method;

    X509 *client_cert = NULL;
    short int s_port = 1337;    

    /* Initialize OpenSSL */
    /* Load encryption & hash algorithms for SSL */
    SSL_library_init();
    /* Load the error strings for good error reporting */
    SSL_load_error_strings();

    method = SSLv3_server_method();

    ctx = SSL_CTX_new(method);    

    if(!ctx){
        perror("Error newing ctx\n");
        exit(1);
    }

    /* Loading certificate from the certificate file */
    if(SSL_CTX_use_certificate_file(ctx, argv[2], SSL_FILETYPE_PEM) <= 0) {
        perror("Error loading certificate.\n");
        exit(1);
    }
    /* Loading private key from the private key file */
    if(SSL_CTX_use_PrivateKey_file(ctx, argv[3], SSL_FILETYPE_PEM) <= 0) {
        perror("Error loading private key.\n");
        exit(1);
    }

    /* Verify server's private key */
    if(!SSL_CTX_check_private_key(ctx)) {
        perror("Error checking private key, doesn't match cert public key\n");
        exit(1);
    }

    listen_sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);

    if(listen_sock < 0){
        perror("Error creating socket listen_sock");
        exit(1);
    }

    memset(&server, '\0', sizeof(server));
    server.sin_family = AF_INET;
    /* Network functions need arguments in network byte order instead of
       host byte order. The macros htonl, htons convert the values, */
    server.sin_addr.s_addr = htonl(INADDR_ANY);
    server.sin_port = htons(atoi(argv[1]));
    if(bind(listen_sock, (struct sockaddr *) &server, sizeof(server)) < 0){
        perror("Error binding socket\n");
        exit(1);
    }

    client_len = sizeof(client);
    listen(listen_sock, 5);

    //struct connection connections[MAX_CONNECTIONS];
    GTree* tree = g_tree_new(sockaddr_in_cmp);
    int i = 0;
    /*
    int i = 0;
    for(; i < MAX_CONNECTIONS; i++){
        connections[i].connfd = -1;
    }
    */

    for (;;) {
        fd_set rfds;
        struct timeval tv;
        int retval;

        FD_ZERO(&rfds);

        // TODO
        //int highestFD = listen_sock;
        int highestFD = -1;
        g_tree_foreach(tree, is_greater_fd, &highestFD);

        /*
        for(i = 0; i < MAX_CONNECTIONS; i++){
            if(connections[i].connfd != -1){
                FD_SET(connections[i].connfd, &rfds);
                if(highestFD < connections[i].connfd){
                    highestFD = connections[i].connfd;
                }
            }
        }
        */

        FD_SET(listen_sock, &rfds);
        if(listen_sock > highestFD) {
            highestFD = listen_sock;
        }
        
        fprintf(stdout, "before select %d\n", highestFD);        
        fflush(stdout);
        retval = select(highestFD + 1, &rfds, (fd_set *) 0, (fd_set *) 0, &tv);
        fprintf(stdout, "after select\n");        
        fflush(stdout);

        /* Open file log file. */
        fp = fopen("src/httpd.log", "a+");
        tv.tv_sec = 5;
        tv.tv_usec = 0;
        if (retval == -1) {
            perror("select()");
        } else if (retval > 0) {

            if(FD_ISSET(listen_sock, &rfds)){
                //for(i = 0; i < MAX_CONNECTIONS; i++){
                    //if(connections[i].connfd == -1){
                        struct sockaddr_in *addr = g_new0(struct sockaddr_in, 1);
                        size_t len = sizeof(addr);
                        struct connection *conn = g_new0(struct connection, 1);

                        //connections[i].connfd = accept(listen_sock, (struct sockaddr*) &client, &client_len);
                        //connections[i].connfd = accept(listen_sock, (struct sockaddr*) &addr, &len);
                        
                        fprintf(stdout, "berore accept\n");
                        fflush(stdout);
                        //conn->connfd = accept(listen_sock, (struct sockaddr*) &addr, &len); 
                        conn->connfd = accept(listen_sock, (struct sockaddr*) &addr, &len); 
                        fprintf(stdout, "after accept\n");
                        fflush(stdout);

                        if(conn->connfd < 0){
                            perror("Error accepting\n");
                            exit(1);
                        }
                        conn->ssl = SSL_new(ctx);
                        if(conn->ssl == NULL){
                            perror("Connections SSL NULL");
                            exit(1);
                        }
                        
                        SSL_set_fd(conn->ssl, conn->connfd);
                        if(SSL_accept(conn->ssl) < 0){
                            perror("Accepting ssl error");
                            exit(1);
                        } 
                        /*
                        if(connections[i].connfd < 0){
                            perror("Error accepting\n");
                            exit(1);
                        }
                        connections[i].ssl = SSL_new(ctx);
                        if(connections[i].ssl == NULL){
                            perror("Connections SSL NULL");
                            exit(1);
                        }

                        SSL_set_fd(connections[i].ssl, connections[i].connfd);
                        if(SSL_accept(connections[i].ssl) < 0){
                            perror("Accepting ssl error");
                            exit(1);
                        } 
                        */

                        fprintf(stdout, "CHECK!!!!!!!!!!!!! CONNFD: %d\n", conn->connfd);
                        fprintf(stdout, "check - i: %d\n", i);
                        fflush(stdout);

                        g_tree_insert(tree, addr, conn);

                        /* Creating the timestamp. */
                        time_t now;
                        time(&now);
                        char buf[sizeof "2011-10-08T07:07:09Z"];
                        memset(buf, 0, sizeof(buf));
                        strftime(buf, sizeof buf, "%Y-%m-%dT%H:%M:%SZ", gmtime(&now));
                        /* Write info to screen. */
                        fprintf(stdout, "%s : %s:%d %s \n", buf, inet_ntoa(client.sin_addr), client.sin_port, "connected");
                        fflush(stdout);
                        /* Write info to file. */
                        fprintf(fp, "%s : %s:%d %s \n", buf, inet_ntoa(client.sin_addr), client.sin_port, "connected");
                        fflush(fp);
                        break;
                    //}
                //}
            }

            struct connection *conn;
            g_tree_foreach(tree, print_tree, conn);

            /*
            for(i = 0; i < MAX_CONNECTIONS; i++){
                if(connections[i].connfd != -1){
                    if(FD_ISSET(connections[i].connfd, &rfds)){
                        int sizerly = 0;
                        memset(recvMessage, '\0', strlen(recvMessage));
                        sizerly = SSL_read(connections[i].ssl, recvMessage, sizeof(recvMessage));
                        if(sizerly < 0 ){
                            perror("ssl_read fail!\n");
                            exit(1);

                        }
                        if(sizerly == 0){
                            fprintf(stdout, "inside sizerly == 0\n");
                            fflush(stdout);
                            SSL_shutdown(connections[i].ssl);
                            close(connections[i].connfd);
                            connections[i].connfd = -1;
                            SSL_free(connections[i].ssl);
                            break; 
                        }
                        recvMessage[sizerly] = '\0';
                        fprintf(stdout, "Recieved %d characters from client:\n '%s'\n", sizerly, recvMessage);
                        fflush(stdout);

                        int j = 0;
                        for(; j < MAX_CONNECTIONS; j++){
                            if(connections[j].connfd != -1){
                                sizerly = SSL_write(connections[j].ssl, recvMessage, strlen(recvMessage));
                                if(sizerly < 0){
                                    perror("Error writing to client");
                                    exit(1);
                                }
                            }
                        }          
                    }
                }
           } 
            */


            //SSL_shutdown(ssl);
            //close(sock);
            //SSL_free(ssl);
            //SSL_CTX_free(ctx);  

            //shutdown(sock, SHUT_RDWR);
            //close(sock);

            /* Close the logfile. */
            fclose(fp);
        } else {
            fprintf(stdout, "No message in five seconds.\n");
            fflush(stdout);
        }
    }
}
