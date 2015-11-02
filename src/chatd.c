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
#define UNUSED(x) (void)(x)
#define MAX_CONNECTIONS 5
#define MAX_LENGTH 999
#define MAX_USER_LENGTH 48
#define TIMEOUT_SECONDS 300

/*  */
static GTree* user_tree;
/*  */
static GTree* room_tree;
/*  */
GList *userinfo;
/* Filepointer for log file */
FILE *fp;

/**/
struct user {
    int connfd;
    SSL *ssl;
    time_t timeout;
    int loginTries;
    time_t loginTryTime;
    char *room_name;
    char nick_name[MAX_USER_LENGTH];
    char username[MAX_USER_LENGTH];
    char password[MAX_USER_LENGTH];
};

struct room {
    char* room_name;
    GList *users;
};

struct userstruct {
    char username[MAX_USER_LENGTH];
    char password[MAX_USER_LENGTH];
};

struct namecompare {
    char *name;
    int found;
    struct sockaddr_in *curruser_key;
};


struct privatemessage {
    char username[MAX_USER_LENGTH];
    char message[MAX_LENGTH + MAX_USER_LENGTH + sizeof("[PM]: ")];
};

void sigint_handler(int signum) {
    UNUSED(signum);
    GList *l = userinfo;
    GList *next;
    while (l != NULL) {
       next = l->next;
       free(l->data);
       userinfo = g_list_delete_link(userinfo, l); 
       l = next;
    }
    g_list_free(userinfo);
    g_tree_destroy(user_tree);
    g_tree_destroy(room_tree);
    
    exit(0);
}

/* This can be used to build instances of GTree that index on
   the address of a connection. */
gint sockaddr_in_cmp(const void *addr1, const void *addr2, gpointer user_data) {
    UNUSED(user_data);
    const struct sockaddr_in *_addr1 = addr1;
    const struct sockaddr_in *_addr2 = addr2;

    /* If either of the pointers is NULL or the addresses
       belong to different families, we abort. */
    g_assert(_addr1 != NULL);
    g_assert(_addr2 != NULL);
    g_assert(_addr1->sin_family == _addr2->sin_family);

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

int search_sockaddr_in_cmp(const void *addr1, const void *addr2) {
    const struct sockaddr_in *_addr1 = addr1;
    const struct sockaddr_in *_addr2 = addr2;

    int retval = sockaddr_in_cmp(_addr1, _addr2, NULL);
    
    if(retval == -1) return 1;
    if(retval == 1) return -1;
    else return 0;
}

gint _strcmp(const void *addr1, const void *addr2, gpointer user_data) {
    UNUSED(user_data);
    return strcmp(addr1, addr2);
}

int search_strcmp(const void *addr1, const void *addr2) {
    const char *_addr1 = addr1;
    const char *_addr2 = addr2;
    int ret = strcmp(_addr1, _addr2);
    if(ret < 0) return 1;
    else if(ret > 0) return -1; 
    else  return 0;
}

void print_users(gpointer data, gpointer user_data) {
    UNUSED(user_data);
    struct sockaddr_in *user = (struct sockaddr_in *) data;
    fprintf(stdout, "User: %d\n", user->sin_port);
    fflush(stdout);
}

void room_key_destroy(gpointer data) {
    char* room_name = (char *) data;
    g_free(room_name);
}

void room_value_destroy(gpointer data) {
    struct room *room = (struct room *) data;
    char* room_name = room->room_name;
    GList* list = room->users;
    while(list != NULL) {
        GList* next = list->next;
        g_free(list->data);
        room->users = g_list_delete_link(room->users, list);
        list = next;   
    }
    g_free(room_name);
}

void user_key_destroy(gpointer data) {
    struct sockaddr_in *addr = (struct sockaddr_in *) data;
    g_free(addr);
}

void user_value_destroy(gpointer data) {
    struct user *user = (struct user *) data;
    g_free(user);     
}

/* 
 * 
 */
gboolean print_rooms(gpointer key, gpointer value, gpointer data) {
    UNUSED(data);
    char *room_name = (char *) key;
    struct room *room = (struct room *) value;
    fprintf(stdout, "Room: %s\n", room_name);
    fflush(stdout);
    g_list_foreach(room->users, print_users, NULL);
    return FALSE;
}

/* A method that is used when we receive the command '/who' and has
 * the purpose of listing all necessary information about a given user. 
 * It is sent as a parameter to a g_tree_foreach that iterates through
 * all users in our user_tree and prints out said information about every user.
 */
gboolean list_userinfo(gpointer key, gpointer value, gpointer data) {
    struct sockaddr_in *conn_key = (struct sockaddr_in *) key;
    struct user *user = (struct user *) value;
    char *users = (char *) data;
    strcat(users, "User => User name: ");
    if(strlen(user->username) != 0) {     
        strcat(users, user->username);
    } else {
        strcat(users, "No user name registered");
    }
    strcat(users, ". IP adress: ");
    strcat(users, inet_ntoa(conn_key->sin_addr));
    strcat(users, ". Port number: ");
    char the_port[20];
    sprintf(the_port, "%d", conn_key->sin_port);
    strcat(users, the_port);
    strcat(users, ". Current room: ");
    if(user->room_name == NULL) {
        strcat(users, "No room.\n");
    } else {
        strcat(users, user->room_name);
        strcat(users, ".\n");
    }
    
    return FALSE;
}

gboolean check_timeout(gpointer key, gpointer value, gpointer data) {
    UNUSED(data);
    struct sockaddr_in *user_key = (struct sockaddr_in *) key;
    struct user *user = (struct user *) value;

    time_t now;
    time(&now);
    
    fflush(stdout);
    if(now - user->timeout > TIMEOUT_SECONDS){
        char buf[sizeof "2011-10-08T07:07:09Z"];
        memset(buf, 0, sizeof(buf));
        strftime(buf, sizeof buf, "%Y-%m-%dT%H:%M:%SZ", gmtime(&now));
        /* Write disconnect info to screen. */
        fprintf(stdout, "%s : %s:%d %s \n", buf, inet_ntoa(user_key->sin_addr), user_key->sin_port, "timed out.");
        fflush(stdout);
        /* Write disconnect info to file. */
        fprintf(fp, "%s : %s:%d %s \n", buf, inet_ntoa(user_key->sin_addr), user_key->sin_port, "timed out.");
        fflush(fp);
        SSL_shutdown(user->ssl);
        close(user->connfd);
        user->connfd = -1;
        SSL_free(user->ssl);
        g_tree_remove(user_tree, user_key);
    }

    return FALSE;
}
 

gboolean check_user(gpointer key, gpointer value, gpointer data) {
    struct sockaddr_in *conn_key = (struct sockaddr_in *) key;
    struct user *user = (struct user *) value;    
    struct namecompare *namecompare = (struct namecompare *) data;

    if(sockaddr_in_cmp(conn_key, namecompare->curruser_key, NULL) != 0 && strlen(user->username) != 0 && strcmp(user->username, namecompare->name) == 0) {
        namecompare->found = 1;
    } else if(sockaddr_in_cmp(conn_key, namecompare->curruser_key, NULL) != 0 && strlen(user->nick_name) != 0 && strcmp(user->nick_name, namecompare->name) == 0) {
        namecompare->found = 1;
    }

    return FALSE;
}

/* A method that is used when we receive the command '/list' and has
 * the purpose of listing all necessary information about a given room. 
 * It is sent as a parameter to a g_tree_foreach that iterates through
 * all rooms in our room_tree and prints out said information about every room.
 */
gboolean list_roominfo(gpointer key, gpointer value, gpointer data) {
    UNUSED(value);
    char* room_name = (char *) key;
    char *rooms = (char *) data;
    strcat(rooms, "Room => Room name: ");
    strcat(rooms, room_name);
    strcat(rooms, "\n");
    
    return FALSE;
}

/**/
gboolean fd_set_nodes(gpointer key, gpointer value, gpointer data) {
    UNUSED(key);
    struct user *conn = (struct user *) value;
    fd_set *rfds = (fd_set *) data;
    if(conn->connfd != -1) {
        FD_SET(conn->connfd, rfds);
    }

    return FALSE;
} 

/**/
gboolean is_greater_fd(gpointer key, gpointer value, gpointer data) {
    UNUSED(key);
    struct user *conn = (struct user *) value;
    int fd = *(int *) data;
    if(conn->connfd > fd) {
        *(int *)data = conn->connfd;
    }

    return FALSE;
} 

gboolean send_private_message(gpointer key, gpointer value, gpointer data) {
    UNUSED(key);
    struct user *conn = (struct user *) value;
    struct privatemessage *pm = (struct privatemessage *) data; 
    int size = 0;
    if(strcmp(conn->username, pm->username) == 0) {
        size = SSL_write(conn->ssl, pm->message, strlen(pm->message));
        if(size < 0) {
            perror("Error writing to client.");
            exit(1);
        }
    }
    
    return FALSE;
}

void send_message_to_user(gpointer data, gpointer user_data) {
    struct sockaddr_in addr = *(struct sockaddr_in *) data;
    fprintf(stdout, "sockaddr_in.sin_port: %d\n", addr.sin_port);
    fflush(stdout);
    char *recvMessage = (char *) user_data;
    int size = 0;
    struct user *user = g_tree_search(user_tree, search_sockaddr_in_cmp, &addr);

    fprintf(stdout, "user->connfd: %d\n", user->connfd);
    fflush(stdout);

    if(user == NULL) {
        perror("Error finding user.\n");
        exit(1);
    }
    size = SSL_write(user->ssl, recvMessage, strlen(recvMessage));
    if(size < 0){
        perror("Error writing to client.");
        exit(1);
    }
}

void print_userinfo(gpointer data, gpointer user_data) {
    UNUSED(user_data);
    struct userstruct *user = (struct userstruct *) data;
    //fprintf(stdout, "Inside userinfo\n");
    //fflush(stdout);

    if(user == NULL){
        //fprintf(stdout, "NULL\n");
        //fflush(stdout);
        return;
    }
    //fprintf(stdout, "Pointer: %d -> Username: %s, password: %s\n", user, user->username, user->password);
    //fflush(stdout);
}


/**/
gboolean check_connection(gpointer key, gpointer value, gpointer data) {
    struct sockaddr_in *user_key = (struct sockaddr_in *) key;
    struct user *user = (struct user *) value;
    fd_set *rfds = (fd_set *) data;
    char recvMessage[MAX_LENGTH];
    int size = 0;
    if(FD_ISSET(user->connfd, rfds)){
       time(&user->timeout); 
        memset(recvMessage, '\0', strlen(recvMessage));
        size = SSL_read(user->ssl, recvMessage, sizeof(recvMessage));
        if(size < 0 ){
            perror("ssl_read fail!\n");
            exit(1);
        }
        if(size == 0){
            /* Creating the timestamp. */
            time_t now;
            time(&now);
            char buf[sizeof "2011-10-08T07:07:09Z"];
            memset(buf, 0, sizeof(buf));
            strftime(buf, sizeof buf, "%Y-%m-%dT%H:%M:%SZ", gmtime(&now));
            /* Write disconnect info to screen. */
            fprintf(stdout, "%s : %s:%d %s \n", buf, inet_ntoa(user_key->sin_addr), user_key->sin_port, "disconnected");
            fflush(stdout);
            /* Write disconnect info to file. */
            fprintf(fp, "%s : %s:%d %s \n", buf, inet_ntoa(user_key->sin_addr), user_key->sin_port, "disconnected");
            fflush(fp);

            if(user->room_name != NULL) {
                struct room *previous_room = g_tree_search(room_tree, search_strcmp, user->room_name);
                previous_room->users = g_list_remove(previous_room->users, user_key);
            }
            SSL_shutdown(user->ssl);
            close(user->connfd);
            SSL_free(user->ssl);
            g_tree_remove(user_tree, user_key);
            return FALSE;
        }
        recvMessage[size] = '\0';

        char message[MAX_LENGTH];
        memset(message, '\0', sizeof(message));
        int size = 0;
        if(strlen(user->username) == 0){
            if(strncmp(recvMessage, "/user", 5) != 0){
                if(SSL_write(user->ssl, "You have to log in or register with '/user <username>'", strlen("You have to log in or register with '/user <username>'")) < 0){
                    perror("Error Writing To Client");
                }
                return FALSE;
            }
        }
        if(strncmp(recvMessage, "/who", 4) == 0) {
            g_tree_foreach(user_tree, list_userinfo, &message);
            size = SSL_write(user->ssl, message, strlen(message));
            if(size < 0){
                perror("Error writing to client");
                exit(1);
            }
        } else if(strncmp(recvMessage, "/say", 4) == 0) {
            char user_name[MAX_USER_LENGTH];
            char message[MAX_LENGTH];
            char messageLine[MAX_USER_LENGTH + MAX_LENGTH + sizeof("[PM]: ")];
            memset(user_name, '\0', sizeof(user_name));
            memset(message, '\0', sizeof(message));
            memset(messageLine, '\0', sizeof(messageLine));
            
            char str[MAX_LENGTH + MAX_USER_LENGTH];
            memset(str, '\0', sizeof(str));
            char *ptr;
            strncpy (str, recvMessage + 5, sizeof(recvMessage));
            strtok_r (str, " ", &ptr);
            strcpy(user_name, str);
            strcpy(message, ptr);
            if (strlen(user->nick_name) != 0) {
                strcpy(messageLine, user->nick_name);
            } else {
                strcpy(messageLine, "Anonymous");
            }
            strcat(messageLine, "[PM]: ");
            strcat(messageLine, message);

            struct privatemessage *pm = (struct privatemessage *) malloc(sizeof(struct privatemessage));
            memset(pm->username, '\0', MAX_USER_LENGTH);
            strcpy(pm->username, user_name);
            memset(pm->message, '\0', MAX_LENGTH);
            strcpy(pm->message, messageLine);

            g_tree_foreach(user_tree, send_private_message, pm);

        } else if(strncmp(recvMessage, "/list", 5) == 0) {
            g_tree_foreach(room_tree, list_roominfo, &message);
            size = SSL_write(user->ssl, message, strlen(message));
            if(size < 0) {
                perror("Error writing to client");
                exit(1);
            }
        } else if(strncmp(recvMessage, "/join", 5) == 0) {
            char room_name[MAX_LENGTH];
            memset(room_name, '\0', sizeof(room_name));
            strncpy(room_name, recvMessage + 6, sizeof(recvMessage));
            struct room *the_room = g_tree_search(room_tree, search_strcmp, room_name);
            if(the_room == NULL) {
                strcat(message, "The room '");
                strcat(message, room_name);
                strcat(message, "' does not exist.");
                size = SSL_write(user->ssl, message, strlen(message));
                if(size < 0) {
                    perror("Error writing to client");
                    exit(1);
                }
            } else {
                if(user->room_name != NULL) {
                    struct room *previous_room = g_tree_search(room_tree, search_strcmp, user->room_name);
                    previous_room->users = g_list_remove(previous_room->users, user_key);
                }
                    
                user->room_name = the_room->room_name;
                the_room->users = g_list_append(the_room->users, user_key); 
                g_tree_foreach(room_tree, print_rooms, NULL);

                strcat(message, "You have succesfully joined '");
                strcat(message, room_name);
                strcat(message, "'.");
                size = SSL_write(user->ssl, message, strlen(message));
                if(size < 0) {
                    perror("Error writing to client");
                    exit(1);
                }
            }
        } else if(strncmp(recvMessage, "/user", 5) == 0) {
            char user_name[MAX_USER_LENGTH];
            char password[MAX_USER_LENGTH];
            int i = 5;
            while (recvMessage[i] != '\0' && isspace(recvMessage[i])) { i++; }
            strncpy(user_name, recvMessage + i, sizeof(recvMessage));
            memset(recvMessage, '\0', strlen(recvMessage));

            struct namecompare namecompare;
            namecompare.name = user_name;
            namecompare.found = 0;
            namecompare.curruser_key = user_key;
            
            g_tree_foreach(user_tree, check_user, &namecompare);

            size = SSL_read(user->ssl, recvMessage, sizeof(recvMessage));
            if(size < 0){
                perror("Error reading password");
                exit(1);
            }
            recvMessage[size] = '\0';
    
            if(namecompare.found) {
                strcat(message, "You cannot register/login as the user '");
                strcat(message, user_name);
                strcat(message, "' because some user either has it as a username or nick.");
                size = SSL_write(user->ssl, message, strlen(message));
                if(size < 0) {
                    perror("Error writing to client");
                    exit(1);
                }
                return FALSE;
            }

            if(strlen(user_name) == 0) {
                strcat(message, "The username cannot be empty.");
                size = SSL_write(user->ssl, message, strlen(message));
                if(size < 0) {
                    perror("Error writing to client");
                    exit(1);
                }
                return FALSE;
            }

            if(strlen(user->username) != 0){
                char errorMsg[MAX_LENGTH];
                strcat(errorMsg, "You are already logged in as '");
                strcat(errorMsg, user->username);
                strcat(errorMsg, "'.");
                if(SSL_write(user->ssl, errorMsg, strlen(errorMsg)) < 0) {
                    perror("Error Writing to client\n");
                    exit(1);
                }
                return FALSE;
            }

            strncpy(password, recvMessage, sizeof(recvMessage));
            time_t now;
            time(&now);
            char buf[sizeof "2011-10-08T07:07:09Z"];
            memset(buf, 0, sizeof(buf));
            strftime(buf, sizeof buf, "%Y-%m-%dT%H:%M:%SZ", gmtime(&now));
            
            if(user->loginTryTime == 0){
                time(&user->loginTryTime);
            } else if(now - user->loginTryTime < 5){
                if(SSL_write(user->ssl, "Try again in a few seconds.", strlen("Try again in a few seconds.")) < 0) {
                    perror("Error Writing to client\n");
                    exit(1);
                }
                return FALSE;
            }

            GList *l;
            for(l = userinfo; l != NULL; l = l->next) {
                struct userstruct *userBoo = (struct userstruct *) l->data;
                char *username = (char *) userBoo->username;
                char *pw = (char *) userBoo->password;

                if(strcmp(username, user_name) == 0){
                    time(&user->loginTryTime);

                    if(strcmp(pw, password) == 0){
                        strncpy(user->username, user_name, MAX_USER_LENGTH);
                        strncpy(user->password, password, MAX_USER_LENGTH);
                        strcpy(user->nick_name, user_name);
                        if(SSL_write(user->ssl, "Successfully logged in.", strlen("Successfully logged in.")) < 0) {
                            perror("Error Writing to client\n");
                            exit(1);
                        }
                        fprintf(stdout, "%s : %s:%d %s %s \n", buf, inet_ntoa(user_key->sin_addr), user_key->sin_port, username, "authenticated");
                        fflush(stdout);
                        fprintf(fp, "%s : %s:%d %s %s \n", buf, inet_ntoa(user_key->sin_addr), user_key->sin_port, username, "authenticated");
                        fflush(fp);
                        return FALSE;
                    }
                    else {
                        user->loginTries = user->loginTries + 1;

                        if(user->loginTries > 2){
                            if(SSL_write(user->ssl, "Too many failed login tries, disconnecting.\n", strlen("Too many failed login tries, disconnecting.")) < 0) {
                                perror("Error Writing to client\n");
                                exit(1);
                            }
                            g_tree_remove(user_tree, user_key);
                            if(user->room_name != NULL) {
                                struct room *previous_room = g_tree_search(room_tree, search_strcmp, user->room_name);
                                previous_room->users = g_list_remove(previous_room->users, user_key);
                            }
                            SSL_shutdown(user->ssl);
                            close(user->connfd);
                            user->connfd = -1;
                            SSL_free(user->ssl);

                            fprintf(stdout, "%s : %s:%d %s %s \n", buf, inet_ntoa(user_key->sin_addr), user_key->sin_port, username, "authentication error");
                            fflush(stdout);
                            fprintf(fp, "%s : %s:%d %s %s \n", buf, inet_ntoa(user_key->sin_addr), user_key->sin_port, username, "authentication error");
                            fflush(fp);
                            fprintf(stdout, "%s : %s:%d %s \n", buf, inet_ntoa(user_key->sin_addr), user_key->sin_port,  "diconnected for too many login tries.");
                            fflush(stdout);
                            fprintf(fp, "%s : %s:%d %s \n", buf, inet_ntoa(user_key->sin_addr), user_key->sin_port,  "disconnected for too many login tries.");
                            fflush(fp);

                            return FALSE;
                        }
                        if(SSL_write(user->ssl, "Incorrect password.", strlen("Incorrect password.")) < 0) {
                            perror("Error Writing to client\n");
                            exit(1);
                        }
                        fprintf(stdout, "%s : %s:%d %s %s \n", buf, inet_ntoa(user_key->sin_addr), user_key->sin_port, username, "authentication error");
                        fflush(stdout);
                        fprintf(fp, "%s : %s:%d %s %s \n", buf, inet_ntoa(user_key->sin_addr), user_key->sin_port, username, "authentication error");
                        fflush(fp);
                        return FALSE;
                    }
                    break;
                }
            }

            if(strlen(user->nick_name) == 0) {
                strcpy(user->nick_name, user_name);
            }

            strncpy(user->username, user_name, MAX_USER_LENGTH);
            strncpy(user->password, password, MAX_USER_LENGTH);
            struct userstruct *userInformation = (struct userstruct *) malloc(sizeof(struct userstruct));
            memset(userInformation->username, '\0', MAX_USER_LENGTH);
            strcpy(userInformation->username, user_name);
            memset(userInformation->password, '\0', MAX_USER_LENGTH);
            strcpy(userInformation->password, password);
            userinfo = g_list_append(userinfo, userInformation);
            if(SSL_write(user->ssl, "Successfully registered.", strlen("Successfully registered.")) < 0) {
                perror("Error Writing to client\n");
                exit(1);
            }
            fprintf(stdout, "%s : %s:%d %s %s \n", buf, inet_ntoa(user_key->sin_addr), user_key->sin_port, user->username, "registered.");
            fflush(stdout);
            fprintf(fp, "%s : %s:%d %s %s \n", buf, inet_ntoa(user_key->sin_addr), user_key->sin_port, user->username, "registered");
            fflush(fp);

        } else if(strncmp(recvMessage, "/nick", 5) == 0) {
            if(strlen(user->username) == 0) {
                strcat(message, "You have to be authenticated to set your nickname. Use the command '/user 'username'' to register.");
                size = SSL_write(user->ssl, message, strlen(message));
                if(size < 0) {
                    perror("Error writing to client");
                    exit(1);
                }
            } else {
                char new_nick_name[MAX_LENGTH];
                memset(new_nick_name, '\0', sizeof(new_nick_name));
                int i = 5;
                while (recvMessage[i] != '\0' && isspace(recvMessage[i])) { i++; }
                strncpy(new_nick_name, recvMessage + i, sizeof(recvMessage));
                struct namecompare namecompare;
                namecompare.name = new_nick_name;
                namecompare.found = 0;
                namecompare.curruser_key = user_key;

                g_tree_foreach(user_tree, check_user, &namecompare);

                if(!namecompare.found) {
                    memset(user->nick_name, '\0', MAX_USER_LENGTH); 
                    if(strlen(new_nick_name) == 0) {
                        strcat(new_nick_name, "Anonymous");
                    }
                    strcat(user->nick_name, new_nick_name);
                    strcat(message, "You have succesfully set your nick as '");
                    strcat(message, new_nick_name);
                    strcat(message, "'.");
                    size = SSL_write(user->ssl, message, strlen(message));
                    if(size < 0) {
                        perror("Error writing to client");
                        exit(1);
                    }
                } else {
                    strcat(message, "You cannot choose the nick '");
                    strcat(message, new_nick_name);
                    strcat(message, "' because some user either has it as a username or nick.");
                    size = SSL_write(user->ssl, message, strlen(message));
                    if(size < 0) {
                        perror("Error writing to client");
                        exit(1);
                    }
                }
            }
        } else {
            if(user->room_name == NULL) {
                strcat(message, "You either have to be in a room or send a private message if you want somebody to recieve your message.");
                size = SSL_write(user->ssl, message, strlen(message));
                if(size < 0) {
                    perror("Error writing to client");
                    exit(1);
                }
            } else {
                struct room *the_room = g_tree_search(room_tree, search_strcmp, user->room_name);
                char _recvMessage[MAX_LENGTH];
                memset(_recvMessage, '\0', MAX_LENGTH);
                if(strlen(user->nick_name) != 0) {
                    strcat(_recvMessage, user->nick_name);
                } else {
                    char anonymous[MAX_LENGTH];
                    memset(anonymous, '\0', MAX_LENGTH);
                    strcat(anonymous, "Anonmymous");
                    strcat(_recvMessage, anonymous);
                }
                strcat(_recvMessage, ": ");
                strcat(_recvMessage, recvMessage);
                g_list_foreach(the_room->users, send_message_to_user, _recvMessage);
            }
        }
    }

    return FALSE;
} 

int main(int argc, char **argv) {
    signal(SIGINT, sigint_handler);
    fprintf(stdout, "SERVER INITIALIZING -- %d C00L 4 SCH00L!\n", argc);
    fflush(stdout);
    int listen_sock;
    struct sockaddr_in server;
    user_tree = g_tree_new_full(sockaddr_in_cmp, NULL, user_key_destroy, user_value_destroy);
    room_tree = g_tree_new_full(_strcmp, NULL, room_key_destroy, room_value_destroy);

    userinfo = NULL;

    /* Creating rooms. */
    char *room_name_1 = g_new0(char, 1);
    char *room_name_2 = g_new0(char, 1);
    char *room_name_3 = g_new0(char, 1);
    char *room_name_4 = g_new0(char, 1);
    struct room *room_1 = g_new0(struct room, 1);
    struct room *room_2 = g_new0(struct room, 1);
    struct room *room_3 = g_new0(struct room, 1);
    struct room *room_4 = g_new0(struct room, 1);
    strncpy(room_name_1, "Room1", strlen("Room1"));
    strncpy(room_name_2, "Room2", strlen("Room2"));
    strncpy(room_name_3, "Room3", strlen("Room3"));
    strncpy(room_name_4, "Room4", strlen("Room4"));
    room_1->room_name = room_name_1;
    room_2->room_name = room_name_2;
    room_3->room_name = room_name_3;
    room_4->room_name = room_name_4;
    room_1->users = NULL;
    room_2->users = NULL;
    room_3->users = NULL;
    room_4->users = NULL;
    g_tree_insert(room_tree, room_name_1, room_1);
    g_tree_insert(room_tree, room_name_2, room_2);
    g_tree_insert(room_tree, room_name_3, room_3);
    g_tree_insert(room_tree, room_name_4, room_4);
    
    //g_tree_foreach(room_tree, print_rooms, NULL);

    SSL_CTX *ctx = NULL;
    const SSL_METHOD *method = SSLv3_server_method();

    /* Initialize OpenSSL */
    /* Load encryption & hash algorithms for SSL */
    SSL_library_init();
    /* Load the error strings for good error reporting */
    SSL_load_error_strings();

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

    listen(listen_sock, 30);

    for (;;) {
        fd_set rfds;
        struct timeval tv;
        int retval;
        int highestFD = -1;
        tv.tv_sec = 5;
        tv.tv_usec = 0;

        FD_ZERO(&rfds);
        g_tree_foreach(user_tree, check_timeout, NULL);
        g_tree_foreach(user_tree, is_greater_fd, &highestFD);
        g_tree_foreach(user_tree, fd_set_nodes, &rfds);
        
        FD_SET(listen_sock, &rfds);
        if(listen_sock > highestFD) {
            highestFD = listen_sock;
        }
        
        retval = select(highestFD + 1, &rfds, (fd_set *) 0, (fd_set *) 0, &tv);

        /* Open file log file. */
        fp = fopen("src/httpd.log", "a+");
        if (retval == -1) {
            perror("select()");
        } else if (retval > 0) {
            if(FD_ISSET(listen_sock, &rfds)){
                struct sockaddr_in *addr = g_new0(struct sockaddr_in, 1);
                struct user *user = g_new0(struct user, 1);
                socklen_t len = sizeof(addr);
                user->connfd = accept(listen_sock, (struct sockaddr*) addr, &len); 
                user->room_name = NULL;
                memset(user->username, '\0', sizeof(user->username));
                memset(user->nick_name, '\0', sizeof(user->username));

                if(user->connfd < 0){
                    perror("Error accepting\n");
                    exit(1);
                }
                user->ssl = SSL_new(ctx);
                if(user->ssl == NULL){
                    perror("Connections SSL NULL\n");
                    exit(1);
                }
                SSL_set_fd(user->ssl, user->connfd);
                int accept = SSL_accept(user->ssl);
                if(accept < 0) {
                    perror("Accepting ssl error\n");
                    exit(1);
                }
                
                char welcome_message[MAX_LENGTH];
                memset(welcome_message, '\0', MAX_LENGTH);
                strcat(welcome_message, "Welcome! - Please authenticate youself with the command '/user <username>' before you start using the chat server.");
                if(SSL_write(user->ssl, welcome_message, strlen(welcome_message)) < 0){
                    perror("Error writing 'Welcome'\n");
                    exit(1);
                }
                time(&user->timeout);
                user->loginTries = 0;
                user->loginTryTime = 0;

                g_tree_insert(user_tree, addr, user);

                /* Creating the timestamp. */
                time_t now;
                time(&now);
                char buf[sizeof "2011-10-08T07:07:09Z"];
                memset(buf, 0, sizeof(buf));
                strftime(buf, sizeof buf, "%Y-%m-%dT%H:%M:%SZ", gmtime(&now));
                /* Write info to screen. */
                fprintf(stdout, "%s : %s:%d %s \n", buf, inet_ntoa(addr->sin_addr), addr->sin_port, "connected");
                fflush(stdout);
                /* Write info to file. */
                fprintf(fp, "%s : %s:%d %s \n", buf, inet_ntoa(addr->sin_addr), addr->sin_port, "connected");
                fflush(fp);
            }

            g_tree_foreach(user_tree, check_connection, &rfds);

            /* Close the logfile. */
            fclose(fp);
        } else {
            fprintf(stdout, "No message in five seconds.\n");
            fflush(stdout);
        }
    }
}
