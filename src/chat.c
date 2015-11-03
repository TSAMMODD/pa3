/* A UDP echo server with timeouts.
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
#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <termios.h>
#include <signal.h>
#include <arpa/inet.h>

/* Secure socket layer headers */
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/engine.h>
#include <openssl/conf.h>
#include <openssl/sha.h>

/* For nicer interaction, we use the GNU readline library. */
#include <readline/readline.h>
#include <readline/history.h>

/* MACROS */
#define UNUSED(x) (void)(x)
#define MAX_LENGTH 9999
#define HASH_ITERATION 5000
#define PEM_FILE "/home/hir.is/danielb13/Tolvusamskipti/tsam15/pa3/src/CAfile.pem"

/* This variable is 1 while the client is active and becomes 0 after
   a quit command to terminate the client and to clean up the
   connection. */
static int active = 1;

/* The salt string that we use to prepend to the password before we hash it. */
const char *SALT = "TYRIONLANNISTER";

/* To read a password without echoing it to the console.
 *
 * We assume that stdin is not redirected to a pipe and we won't
 * access tty directly. It does not make much sense for this program
 * to redirect input and output.
 *
 * This function is not safe to termination. If the program
 * crashes during getpasswd or gets terminated, then echoing
 * may remain disabled for the shell (that depends on shell,
 * operating system and C library). To restore echoing,
 * type 'reset' into the sell and press enter.
 */
void getpasswd(const char *prompt, char *passwd, size_t size) {
    struct termios old_flags, new_flags;

    /* Clear out the buffer content. */
    memset(passwd, 0, size);

    /* Disable echo. */
    tcgetattr(fileno(stdin), &old_flags);
    memcpy(&new_flags, &old_flags, sizeof(old_flags));
    new_flags.c_lflag &= ~ECHO;
    new_flags.c_lflag |= ECHONL;

    if (tcsetattr(fileno(stdin), TCSANOW, &new_flags) != 0) {
        perror("tcsetattr");
        exit(EXIT_FAILURE);
    }

    printf("%s", prompt);
    fgets(passwd, size, stdin);

    /* The result in passwd is '\0' terminated and may contain a final
     * '\n'. If it exists, we remove it.
     */
    if (passwd[strlen(passwd) - 1] == '\n') {
        passwd[strlen(passwd) - 1] = '\0';
    }

    /* Memsetting the memory for security reasons. */
    char buf1[MAX_LENGTH], buf2[MAX_LENGTH];
    memset(buf1, '\0', MAX_LENGTH);
    memset(buf2, '\0', MAX_LENGTH);
    char the_password[MAX_LENGTH];
    strncpy(the_password, SALT, strlen(SALT));
    strncat(the_password, passwd, strlen(passwd));
    /* The hash logic. Hash 5001 Times. */
    SHA256((unsigned char *) the_password, strlen(the_password), (unsigned char *)buf1);
    
    int i = 0;
    for(; i < HASH_ITERATION; i++) {
        SHA256((unsigned char *)buf1, strlen(buf1), (unsigned char *) buf2);
        memset(buf1, '\0', strlen(buf1));
        strncpy(buf1, buf2, strlen(buf2));
        memset(buf2, '\0', strlen(buf2));
    }    

    /* Memsetting the memory for security reasons. */
    memset(passwd, '\0', strlen(passwd));
    memset(passwd, '\0', strlen(the_password));
    strncpy(passwd, buf1, strlen(buf1));

    /* Restore the terminal */
    if (tcsetattr(fileno(stdin), TCSANOW, &old_flags) != 0) {
        perror("tcsetattr");
        exit(EXIT_FAILURE);
    }
}

/* The next two variables are used to access the encrypted stream to
 * the server. The socket file descriptor server_fd is provided for
 * select (if needed), while the encrypted communication should use
 * server_ssl and the SSL API of OpenSSL.
 */
static int sockfd;
static SSL *server_ssl;
static SSL_CTX *ssl_ctx;

/* This variable shall point to the name of the chatroom. The initial
   value is NULL (not member of a chat room). Set this variable whenever
   the user changed the chat room successfully. */
static char *chatroom;

/* This prompt is used by the readline library to ask the user for
 * input. It is good style to indicate the name of the user and the
 * chat room he is in as part of the prompt. */
static char *prompt;

/* If someone kills the client, it should still clean up the readline
   library, otherwise the terminal is in a inconsistent state. We set
   active to 0 to get out of the loop below. Also note that the select
   call below may return with -1 and errno set to EINTR. Do not exit
   select with this error. */
void sigint_handler(int signum) {
    UNUSED(signum);
    active = 0;

    /* We should not use printf inside of signal handlers, this is not
     * considered safe. We may, however, use write() and fsync(). */
    write(STDOUT_FILENO, "Terminated.\n", 12);

    /* Client's cleanup. */
    free(prompt);
    rl_callback_handler_remove();
    SSL_shutdown(server_ssl);
    close(sockfd);
    SSL_free(server_ssl);
    SSL_CTX_free(ssl_ctx);
    RAND_cleanup();
    ENGINE_cleanup();
    CONF_modules_unload(1);
    CONF_modules_free();
    EVP_cleanup();
    ERR_free_strings();
    ERR_remove_state(0);
    CRYPTO_cleanup_all_ex_data();

    fsync(STDOUT_FILENO);  
    exit(0);
}

/* When a line is entered using the readline library, this function
   gets called to handle the entered line. Implement the code to
   handle the user requests in this function. The client handles the
   server messages in the loop in main(). */
void readline_callback(char *line) {
    char buffer[256];
    if (NULL == line) {
        rl_callback_handler_remove();
        active = 0;
        return;
    }
    if (strlen(line) > 0) {
        add_history(line);
    }
    if ((strncmp("/bye", line, 4) == 0) ||
            (strncmp("/quit", line, 5) == 0)) {
        rl_callback_handler_remove();
        active = 0;
        return;
    }
    if (strncmp("/game", line, 5) == 0) {
        /* Skip whitespace */
        int i = 5;
        while (line[i] != '\0' && isspace(line[i])) { i++; }
        if (line[i] == '\0') {
            write(STDOUT_FILENO, "Usage: /game username\n", 29);
            fsync(STDOUT_FILENO);
            rl_redisplay();
            return;
        }
        return;
    }
    if (strncmp("/join", line, 5) == 0) {
        /* Skip whitespace */
        int i = 5;
        while (line[i] != '\0' && isspace(line[i])) { i++; }
        if (line[i] == '\0') {
            write(STDOUT_FILENO, "Usage: /join chatroom\n", 22);
            fsync(STDOUT_FILENO);
            rl_redisplay();
            return;
        }

        chatroom = strdup(&(line[i]));

        /* Process and send this information to the server. */
        if(SSL_write(server_ssl, line, strlen(line)) < 0 ){
            perror("Error Writing /join to server\n");
            exit(1);
        }

        return;
    }
    if (strncmp("/list", line, 5) == 0) {
        /* Query all available chat rooms */
        if(SSL_write(server_ssl, line, strlen(line)) < 0){
            perror("Error writing /list to server\n");
            exit(1);
        }

        return;
    }
    if (strncmp("/roll", line, 5) == 0) {
        /* roll dice and declare winner. */
        return;
    }
    if (strncmp("/say", line, 4) == 0) {
        /* Skip whitespace */
        int i = 4;
        while (line[i] != '\0' && isspace(line[i])) { i++; }
        if (line[i] == '\0') {
            write(STDOUT_FILENO, "Usage: /say username message\n", 29);
            fsync(STDOUT_FILENO);
            rl_redisplay();
            return;
        }
        /* Skip whitespace */
        int j = i+1;
        while (line[j] != '\0' && isgraph(line[j])) { j++; }
        if (line[j] == '\0') {
            write(STDOUT_FILENO, "Usage: /say username message\n", 29);
            fsync(STDOUT_FILENO);
            rl_redisplay();
            return;
        }

        /* Send private message to receiver. */
        if(SSL_write(server_ssl, line, strlen(line)) < 0){
            perror("Error writing /say to server\n");
            exit(1);
        }
        return;
    }
    if (strncmp("/user", line, 5) == 0) {
        /* Skip whitespace */
        int i = 5;
        while (line[i] != '\0' && isspace(line[i])) { i++; }
        if (line[i] == '\0') {
            write(STDOUT_FILENO, "Usage: /user username\n", 22);
            fsync(STDOUT_FILENO);
            rl_redisplay();
            return;
        }

        char passwd[48];
        getpasswd("Password: ", passwd, 48);
        /* Send Username and /user command */
        if(SSL_write(server_ssl, line, strlen(line)) < 0){
            perror("Error writing /user to server\n");
            exit(1);
        }

        /* Send password independantly. Server expects this. */
        if(SSL_write(server_ssl, passwd, strlen(passwd)) < 0){
            perror("Error writing pw to server\n");
            exit(1);
        }

        return;
    }
    /* Sent the buffer to the server. */
    if (strncmp("/who", line, 4) == 0) {
        /* Send who command to server, info is processed by server and returned as string */
        if(SSL_write(server_ssl, line, strlen(line)) < 0){
            perror("Error writing /who to server\n");
            exit(1);
        }
        return;
    }
    
    /* If there is no command we only have to send the message to the server */
    snprintf(buffer, 255, "Message: %s\n", line);
    if(SSL_write(server_ssl, line, strlen(line)) < 0){
        perror("Error writing message to server\n");
        exit(1);
    }
    fsync(STDOUT_FILENO);
}

int main(int argc, char **argv)
{
    /* Welcome message in client. */
    fprintf(stdout, "CLIENT INITIALIZING -- %d COOL 4 SCH00L!\n", argc);
    fflush(stdout);
    /* Setting sigint handler. */
    signal(SIGINT, sigint_handler);
    /* Initialize OpenSSL */
    /* Load encryption & hash algorithms for SSL */
    SSL_library_init();
    /* Load the error strings for good error reporting */
    SSL_load_error_strings();
   
    X509 *server_cert;
    const SSL_METHOD *method;
    char *str;    
    char recvMessage[8196];

    /* User SSLv3 client method since this is a dedicated client */
    method = SSLv3_client_method();

    /* New an SSL_CTX structure and check for errors */
    ssl_ctx = SSL_CTX_new(method);
    if(ssl_ctx == NULL){
        perror("Error loading CA.\n");
        exit(1);
    }

    /* New an ssl structure */
    server_ssl = SSL_new(ssl_ctx);

    /* Loading CA from the CA file and verify the certificate from the server */
    if(SSL_CTX_load_verify_locations(ssl_ctx, PEM_FILE, NULL) <= 0) {
        perror("Error loading CA.\n");
        exit(0);
    }

    /* Make the client require the server certificate */
    SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_PEER, NULL);

    SSL_CTX_set_verify_depth(ssl_ctx, 1);
    
    /* Create a sockaddress for server and client */
    struct sockaddr_in server;// , client;
    /* Create and bind a TCP socket */
    if((sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0) {
        perror("Could not create socket.\n");
        exit(0);
    }
    /* Set the server address */
    memset(&server, '\0', sizeof(server));
    server.sin_family = AF_INET;
    /* Network functions need arguments in network byte order instead of 
       host byte order. The macros htonl, htons convert the values */
    server.sin_addr.s_addr = inet_addr("127.0.0.1");
    server.sin_port = htons(atoi(argv[1]));

    /* Connect to the server using TCP */
    if(connect(sockfd, (struct sockaddr*)&server, sizeof(server)) != 0) {
        perror("Could not connect to server.\n");
        exit(1);
    }

    /* New an SSL structure using the ssl_ctx specified */
    server_ssl = SSL_new(ssl_ctx);

    if(server_ssl == NULL){
        perror("server_ssl == NULL\n");
        exit(1);
    }

    /* Set the ssl structure to the socket */
    SSL_set_fd(server_ssl, sockfd);

    if(server_ssl == NULL){
        perror("ssl == null\n");
        exit(1);
    }    

    /* Make the handshake with the server */
    if(SSL_connect(server_ssl) == -1){
        perror("Error SSL_connecting to server\n");
        exit(1);
    }

    /* Get server's certificate */
    server_cert = SSL_get_peer_certificate(server_ssl);

    if(server_cert != NULL){
        str = X509_NAME_oneline(X509_get_subject_name(server_cert), 0, 0);

        if(str == NULL){
            perror("X509 subject name error\n");
            exit(1); 
        }
        free(str);
        X509_free(server_cert);
    }
    else{
        fprintf(stdout, "Server has no certificate!\n");
        fflush(stdout);
    }
    
    /* Before we can accept messages, we have to listen to the port. */
    listen(sockfd, 1);

    /* Read characters from the keyboard while waiting for input.
    */
    prompt = strdup("> ");
    rl_callback_handler_install(prompt, (rl_vcpfunc_t*) &readline_callback);
    while (active) {
        fd_set rfds;
        struct timeval timeout;
        /* Clear the fd set */
        FD_ZERO(&rfds);
        /* Add the STDIN fd to the set */
        FD_SET(STDIN_FILENO, &rfds);
        /* Add the socket fd to the set */
        FD_SET(sockfd, &rfds);
        timeout.tv_sec = 5;
        timeout.tv_usec = 0;
        /* Set the highest fd for select */
        int highestFD = sockfd;
        if(STDIN_FILENO > sockfd){
            highestFD = STDIN_FILENO;
        }
        /* Wait for messages for 5 seconds from server or input */
        int r = select(highestFD + 1, &rfds, NULL, NULL, &timeout);
        if (r < 0) {
            if (errno == EINTR) {
                /* This should either retry the call or
                   exit the loop, depending on whether we
                   received a SIGTERM. */
                continue;
            }
            /* Not interrupted, maybe nothing we can do? */
            perror("select()");
            break;
        }
        if (r == 0) {
            fsync(STDOUT_FILENO);
            /* Whenever you print out a message, call this
               to reprint the current input line. */
            rl_redisplay();
            continue;
        }
        else{
            /* Check if input has been typed */
            if(FD_ISSET(STDIN_FILENO, &rfds)) {
                rl_callback_read_char();
            }
            /* Check if socket has message */
            if(FD_ISSET(sockfd, &rfds)){
                memset(recvMessage, '\0', sizeof(recvMessage));
                /* SSL_read from server since there is a message to read */          
                int size = SSL_read(server_ssl, recvMessage, sizeof(recvMessage));
                /* If size of message is 0 then the server closed the connection, cleanup. */
                if(size == 0){
                    fprintf(stdout, "Server Closed the Connection! - Exiting\n");
                    fflush(stdout);
                    SSL_shutdown(server_ssl);
                    close(sockfd);
                    SSL_free(server_ssl);
                    SSL_CTX_free(ssl_ctx);
                    rl_callback_handler_remove();

                    fsync(STDOUT_FILENO);  
                    exit(0);
                }
                /* Print the received message on the screen */
                strcat(recvMessage, "\n> ");
                write(STDOUT_FILENO, recvMessage, strlen(recvMessage));
                fsync(STDOUT_FILENO);               
                rl_redisplay(); 
            }
        }
    }
    
    /* Cleanup connection and ssl */
    SSL_shutdown(server_ssl);
    close(sockfd);
    SSL_free(server_ssl);
    SSL_CTX_free(ssl_ctx);
}
