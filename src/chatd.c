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
#include <openssl/engine.h>
#include <openssl/conf.h>
#include <openssl/sha.h>

/* Macros */
#define UNUSED(x) (void)(x)
#define MAX_CONNECTIONS 5
#define MAX_LENGTH 999
#define MAX_USER_LENGTH 48
#define TIMEOUT_SECONDS 300
#define HASH_ITERATION 5000

/* The GTree struct is an opaque data structure representing a balanced binary tree. 
 * This GTree, user_tree, represents such tree and contains information about user 
 * connections. Each node in the tree has a key and a value and maps the user's
 * address and port (sockaddr_in) to a 'user' struct that contains necessary 
 * information about the user and his/her connection. 
 */
static GTree* user_tree;

/* This GTree, room_tree, contains information about all rooms and connected users.
 * Each node in the tree has a key and a value and maps the room name 
 * to a 'room' struct that contains information about the room name and
 * a list of all users in the room. 
 */
static GTree* room_tree;

/* Filepointer for log file */
FILE *fp;

/* The file that stores user's password. */
FILE *password_fp;

/* The SSL_CTX object is created as a framework to establish TLS/SSL enabled connections. */
SSL_CTX *ctx = NULL;

/* The salt string that we use to prepend to the client's password before we re-hash it. */
const char *SALT = "BRANDONSTARK";

/* The 'user' struct contains information about a currently connected user. This 
 * information describes when he should timeout, how many times he has tried to 
 * log in, his connection file descriptor, SSL pointer and basic user credentials.*/
struct user {
    int connfd;
    SSL *ssl;
    time_t timeout;
    int loginTries;
    time_t loginTryTime;
    char *room_name;
    char nick_name[MAX_USER_LENGTH];
    char username[MAX_USER_LENGTH];
};

/* The 'room' struct contains information about a room in our chat server.
 * This information is the room name and a list of users in this room.
 */
struct room {
    char* room_name;
    GList *users;
};

/* The 'namecompare' struct is used when we traverse through our user_tree
 * to find a certain user.
 */
struct namecompare {
    char *name;
    int found;
    struct sockaddr_in *curruser_key;
};

/* The 'privatemessage' struct contains information about a user's username
 * and the message line to be sent as a private message to the user.
 */
struct privatemessage {
    char username[MAX_USER_LENGTH];
    char message[MAX_LENGTH + MAX_USER_LENGTH + sizeof("[PM]: ")];
};

/* A handler method that handles what should happen when a user terminates
 * the process, i.e. presses 'CTRL + c' (sends an INT signal). 
 */
void sigint_handler(int signum) {
    UNUSED(signum);
    /* Cleanup when the server has shut down. */
    /* Tree cleanup. */
    g_tree_destroy(user_tree);
    g_tree_destroy(room_tree);
    /* Other cleanup include SSL. */
    SSL_CTX_free(ctx);
    RAND_cleanup();
    ENGINE_cleanup();
    CONF_modules_unload(1);
    CONF_modules_free();
    EVP_cleanup();
    ERR_free_strings();
    ERR_remove_state(0);
    CRYPTO_cleanup_all_ex_data();
    
    exit(0);
}

/* A method that can be used to build instances of a GTree 
 * that indexes on the address of a connection. 
 */
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
    /* Return 0 if the two addresses were equal. */
    return 0;
}

/* A method that is used when sending a message to every user in a room.
 * It has the purpose of comparing one user via a user's address 
 * to another during a g_tree_search.
 */
int search_sockaddr_in_cmp(const void *addr1, const void *addr2) {
    const struct sockaddr_in *_addr1 = addr1;
    const struct sockaddr_in *_addr2 = addr2;

    int retval = sockaddr_in_cmp(_addr1, _addr2, NULL);
    
    if(retval == -1) return 1;
    if(retval == 1) return -1;
    else return 0;
}

/* A method that has the same functionality as strcmp, but returns a gint
 * that is necessary to be able to call g_tree_new_full correctly.
 */
gint _strcmp(const void *addr1, const void *addr2, gpointer user_data) {
    UNUSED(user_data);
    return strcmp(addr1, addr2);
}

/* A method that compares two strings together, in our case room names,
 * and returns the correct values in order for g_tree_search to work correctly.
 */
int search_strcmp(const void *addr1, const void *addr2) {
    const char *_addr1 = addr1;
    const char *_addr2 = addr2;
    int ret = strcmp(_addr1, _addr2);
    if(ret < 0) return 1;
    else if(ret > 0) return -1; 
    else return 0;
}

/* A method that is used to print out a user's port. 
 */
void print_users(gpointer data, gpointer user_data) {
    UNUSED(user_data);
    struct sockaddr_in *user = (struct sockaddr_in *) data;
    fprintf(stdout, "User: %d\n", user->sin_port);
    fflush(stdout);
}

/* A function to free the memory allocated for the key used when 
 * removing the entry from the room_tree GTree.
 */
void room_key_destroy(gpointer data) {
    char* room_name = (char *) data;
    g_free(room_name);
}

/* A function to free the memory allocated for the value used when 
 * removing the entry from the room_tree GTree.
 */
void room_value_destroy(gpointer data) {
    struct room *room = (struct room *) data;
    GList* list = room->users;
    while(list != NULL) {
        GList* next = list->next;
        struct sockaddr_in *addr = (struct sockaddr_in *) list->data;
        g_free(addr);
        room->users = g_list_delete_link(room->users, list);
        list = next;   
    }

    g_list_free(room->users);
    g_free(room);
}

/* A function to free the memory allocated for the key used when 
 * removing the entry from the user_tree GTree.
 */
void user_key_destroy(gpointer data) {
    struct sockaddr_in *addr = (struct sockaddr_in *) data;
    g_free(addr);
}

/* A function to free the memory allocated for the value used when 
 * removing the entry from the user_tree GTree.
 */
void user_value_destroy(gpointer data) {
    struct user *user = (struct user *) data;
    SSL_shutdown(user->ssl);
    close(user->connfd);
    SSL_free(user->ssl);
    g_free(user);     
}

/* A function used when iterating through all rooms via g_tree_foreach.
 * This function handles printing out a room and its users.
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
    /* Check if user has a user name. */
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
    /* Check if user is currently in a room. */
    if(user->room_name == NULL) {
        strcat(users, "No room.\n");
    } else {
        strcat(users, user->room_name);
        strcat(users, ".\n");
    }
    
    return FALSE;
}

/* A function that is used when we iterate through all users and checks
 * whether or not they should timeout, i.e. be kicked out of the chat
 * server due to inactivity.
 */
gboolean check_timeout(gpointer key, gpointer value, gpointer data) {
    UNUSED(data);
    struct sockaddr_in *user_key = (struct sockaddr_in *) key;
    struct user *user = (struct user *) value;
    time_t now;
    time(&now);
    
    /* User has timed out. */
    if(now - user->timeout > TIMEOUT_SECONDS){
        char buf[sizeof "2011-10-08T07:07:09Z"];
        memset(buf, 0, sizeof(buf));
        strftime(buf, sizeof buf, "%Y-%m-%dT%H:%M:%SZ", gmtime(&now));
        /* Write disconnect info to screen. */
        fprintf(stdout, "%s : %s:%d %s \n", buf, inet_ntoa(user_key->sin_addr), user_key->sin_port, "timed out.");
        fflush(stdout);
        /* Write disconnect info to log file. */
        fprintf(fp, "%s : %s:%d %s \n", buf, inet_ntoa(user_key->sin_addr), user_key->sin_port, "timed out.");
        fflush(fp);
        /* Remove the user from the tree. */
        g_tree_remove(user_tree, user_key);
    }

    return FALSE;
}
 
/* A function that is used when creating a new user.
 * The function checks if the new name (username) already exists. 
 */
gboolean check_user(gpointer key, gpointer value, gpointer data) {
    struct sockaddr_in *conn_key = (struct sockaddr_in *) key;
    struct user *user = (struct user *) value;    
    struct namecompare *namecompare = (struct namecompare *) data;

    if(sockaddr_in_cmp(conn_key, namecompare->curruser_key, NULL) != 0 && strlen(user->username) != 0 && strcmp(user->username, namecompare->name) == 0) {
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

/* A function that is used when we iterate through the user_tree. 
 * The function sets each user's connection file descriptor. 
 */
gboolean fd_set_nodes(gpointer key, gpointer value, gpointer data) {
    UNUSED(key);
    struct user *conn = (struct user *) value;
    fd_set *rfds = (fd_set *) data;
    FD_SET(conn->connfd, rfds);

    return FALSE;
} 

/* A function that is used when we iterate through the user_tree.
 * The function has the purpose of comparing users' connection file
 * descriptors in order to find the highest one. 
 */
gboolean is_greater_fd(gpointer key, gpointer value, gpointer data) {
    UNUSED(key);
    struct user *conn = (struct user *) value;
    int fd = *(int *) data;
    if(conn->connfd > fd) {
        *(int *)data = conn->connfd;
    }

    return FALSE;
} 

/* A function used to send some user a private message. It is called each time
 * when we iterate through our user_tree and if the receiving user matches 
 * a user in the user_tree we send him/her the private message.
 */
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

/* A function used when iterating through all users in a room.
 * It handles sending a message to all users in the room.
 */
void send_message_to_user(gpointer data, gpointer user_data) {
    struct sockaddr_in addr = *(struct sockaddr_in *) data;
    char *recvMessage = (char *) user_data;
    int size = 0;
    /* Searching for the user in our tree. */
    struct user *user = g_tree_search(user_tree, search_sockaddr_in_cmp, &addr);

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

/* The check_connection function is our largest and most important function
 * besides 'main' and handles all functionality regarding user input, i.e.
 * what should happen when a user types in an available command and the
 * appropriate parameters. It is called when we iterate through our user_tree.
 */
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
            perror("Error reading with SSL.\n");
            exit(1);
        }
        /* If we get a message of size equal to 0 than we know that the user have disconnect. */
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
            /* Write disconnect info to log file. */
            fprintf(fp, "%s : %s:%d %s \n", buf, inet_ntoa(user_key->sin_addr), user_key->sin_port, "disconnected");
            fflush(fp);

            /* If the user was in some room than we remove him from the room's users list. */
            if(user->room_name != NULL) {
                struct room *previous_room = g_tree_search(room_tree, search_strcmp, user->room_name);
                previous_room->users = g_list_remove(previous_room->users, user_key);
            }
            /* Remove the user from the user's tree. */
            g_tree_remove(user_tree, user_key);
            return FALSE;
        }
        recvMessage[size] = '\0';

        char message[MAX_LENGTH];
        memset(message, '\0', sizeof(message));
        int size = 0;
        /* If the user has no username, we know he has not logged in. If he tries to do anything 
         * other than logging in/signing up via the '/user' command we write an error message. */
        if(strlen(user->username) == 0) {
            if(strncmp(recvMessage, "/user", 5) != 0){
                if(SSL_write(user->ssl, "You have to log in or register with '/user <username>'", strlen("You have to log in or register with '/user <username>'")) < 0){
                    perror("Error Writing To Client");
                }
                return FALSE;
            }
        }
        /* If the user types in '/who' we list the names of all users available on the system. */
        if(strncmp(recvMessage, "/who", 4) == 0) {
            g_tree_foreach(user_tree, list_userinfo, &message);
            size = SSL_write(user->ssl, message, strlen(message));
            if(size < 0){
                perror("Error writing to client");
                exit(1);
            }
        } 
        /* If the user types in '/say' he sends another user a private message. */
        else if(strncmp(recvMessage, "/say", 4) == 0) {
            char user_name[MAX_USER_LENGTH];
            char message[MAX_LENGTH];
            /* messageLine is of the form '<username>[PM]: <message>' */
            char messageLine[MAX_USER_LENGTH + MAX_LENGTH + sizeof("[PM]: ")];
            memset(user_name, '\0', sizeof(user_name));
            memset(message, '\0', sizeof(message));
            memset(messageLine, '\0', sizeof(messageLine));
            
            /* The purpose of the next few lines are to parse the string received after
             * '/say' into the username and message. */
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

            /* Find the correct user and send him/her the private message. */
            g_tree_foreach(user_tree, send_private_message, pm);
        }
        /* If the user types in '/list' we list the names of all available public chat rooms. */ 
        else if(strncmp(recvMessage, "/list", 5) == 0) {
            g_tree_foreach(room_tree, list_roominfo, &message);
            size = SSL_write(user->ssl, message, strlen(message));
            if(size < 0) {
                perror("Error writing to client");
                exit(1);
            }
        } 
        /* If the user types in '/join' and a room name he will join the room with that name,
         * given that it exists. A client can only be a member of one chat room at a time.
         */
        else if(strncmp(recvMessage, "/join", 5) == 0) {
            char room_name[MAX_LENGTH];
            memset(room_name, '\0', sizeof(room_name));
            strncpy(room_name, recvMessage + 6, sizeof(recvMessage));
            /* Searching for the room in our room's tree. */
            struct room *the_room = g_tree_search(room_tree, search_strcmp, room_name);
            /* If we do not find the room we print a error message. */
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
                /* If the user was already in a room than we have to remove the user from his previous room's users list. */
                if(user->room_name != NULL) {
                    struct room *previous_room = g_tree_search(room_tree, search_strcmp, user->room_name);
                    previous_room->users = g_list_remove(previous_room->users, user_key);
                }
                    
                /* Setting the data. */
                user->room_name = the_room->room_name;
                the_room->users = g_list_append(the_room->users, user_key); 

                strcat(message, "You have succesfully joined '");
                strcat(message, room_name);
                strcat(message, "'.");
                size = SSL_write(user->ssl, message, strlen(message));
                if(size < 0) {
                    perror("Error writing to client");
                    exit(1);
                }
            }
        } 
        /* If the user types in '/user' and a username he can register as a user with that username,
         * or try to log in with that username if the username has already been registered. 
         * The password is used as a shared secret between client and server. A user is disconnected 
         * if the password does not match within three trials, and there is a delay between each attempt. 
         * The password is processed securely via hashing. */
        else if(strncmp(recvMessage, "/user", 5) == 0) {
            char user_name[MAX_USER_LENGTH];
            char password[MAX_USER_LENGTH];
            memset(user_name, '\0', MAX_USER_LENGTH);
            memset(password, '\0', MAX_USER_LENGTH);
            int i = 5;
            /* Escape whitespace. */
            while (recvMessage[i] != '\0' && isspace(recvMessage[i])) { i++; }
            strncpy(user_name, recvMessage + i, sizeof(recvMessage));
            memset(recvMessage, '\0', strlen(recvMessage));

            /* We use a struct to check if there is existing user with the same username. */
            struct namecompare namecompare;
            namecompare.name = user_name;
            namecompare.found = 0;
            namecompare.curruser_key = user_key;
            
            /* Searching for a user with the same username. If we found him than namecompare.found is set to 1. */
            g_tree_foreach(user_tree, check_user, &namecompare);

            size = SSL_read(user->ssl, recvMessage, sizeof(recvMessage));
            if(size < 0){
                perror("Error reading password");
                exit(1);
            }
            recvMessage[size] = '\0';
    
            /* A person can not log in or sign up as an already logged-in user. */
            if(namecompare.found) {
                strcat(message, "You cannot register/login as the user '");
                strcat(message, user_name);
                strcat(message, "' because some other user already has that username.");
                size = SSL_write(user->ssl, message, strlen(message));
                if(size < 0) {
                    perror("Error writing to client");
                    exit(1);
                }
                memset(recvMessage, '\0', strlen(recvMessage));
                return FALSE;
            }

            /* If the username is empty than we print out error message. */
            if(strlen(user_name) == 0) {
                strcat(message, "The username cannot be empty.");
                size = SSL_write(user->ssl, message, strlen(message));
                if(size < 0) {
                    perror("Error writing to client");
                    exit(1);
                }
                memset(recvMessage, '\0', strlen(recvMessage));
                return FALSE;
            }
            
            /* If the user that is trying to login/register has a username than that means that 
             * the user is already logged in. */
            if(strlen(user->username) != 0){
                char errorMsg[MAX_LENGTH];
                memset(errorMsg, '\0', sizeof(errorMsg));
                strcat(errorMsg, "You are already logged in as '");
                strcat(errorMsg, user->username);
                strcat(errorMsg, "'.");
                if(SSL_write(user->ssl, errorMsg, strlen(errorMsg)) < 0) {
                    perror("Error Writing to client\n");
                    exit(1);
                }
                memset(recvMessage, '\0', strlen(recvMessage));
                return FALSE;
            }

            /* Getting the password from the user to the 'password' array. */
            strncpy(password, recvMessage, sizeof(recvMessage)); 
            memset(recvMessage, '\0', strlen(recvMessage));
    
            char buf1[MAX_LENGTH], buf2[MAX_LENGTH];
            char the_password[MAX_LENGTH];
            memset(buf1, '\0', MAX_LENGTH);
            memset(buf2, '\0', MAX_LENGTH);
            memset(the_password, '\0', MAX_LENGTH);

            /* Adding our salt string to the password. */
            strncpy(the_password, SALT, strlen(SALT));
            strncat(the_password, password, strlen(password));
            
            /* The hash logic. */
            SHA256((unsigned char *) the_password, strlen(the_password), (unsigned char *)buf1);
            i = 0;
            for(; i < HASH_ITERATION; i++) {
                SHA256((unsigned char *)buf1, strlen(buf1), (unsigned char *) buf2);
                memset(buf1, '\0', strlen(buf1));
                strncpy(buf1, buf2, strlen(buf2));
                memset(buf2, '\0', strlen(buf2));
            }    

            /* Memsetting the memory for security reasons. */
            memset(password, '\0', sizeof(password));
            memset(the_password, '\0', sizeof(the_password));
            strncpy(password, buf1, strlen(buf1));
            memset(buf1, '\0', sizeof(buf1));

            time_t now;
            time(&now);
            char buf[sizeof "2011-10-08T07:07:09Z"];
            memset(buf, 0, sizeof(buf));
            strftime(buf, sizeof buf, "%Y-%m-%dT%H:%M:%SZ", gmtime(&now));
            
            /* Resetting the login try time if the user have not failed to login. */
            if(user->loginTryTime == 0){
                time(&user->loginTryTime);
            }
            /* The user have to wait between login tries. */
            else if(now - user->loginTryTime < 5){
                if(SSL_write(user->ssl, "Try again in a few seconds.", strlen("Try again in a few seconds.")) < 0) {
                    perror("Error Writing to client\n");
                    exit(1);
                }
                return FALSE;
            }

            GKeyFile *keyfile = g_key_file_new();
            /* Load the user's passwords to keyfile from our passwords file. */
            g_key_file_load_from_file(keyfile, "src/passwords.ini", G_KEY_FILE_NONE, NULL);
            /* Getting our user's password from the keyfile data structure. */
            gchar *get_password64 = g_key_file_get_string(keyfile, "passwords", user_name, NULL);

            /* If we did find a password matching the user name than we user is trying to login.  */
            if(get_password64 != NULL) {
                gsize plength;
                guchar *passwd = g_base64_decode(get_password64, &plength);

                /* Comparing the stored password to the user's typed in password. */
                if(strcmp((const char *) passwd, password) == 0) {
                    strncpy(user->username, user_name, MAX_USER_LENGTH);
                    strcpy(user->nick_name, user_name);
                    if(SSL_write(user->ssl, "Successfully logged in.", strlen("Successfully logged in.")) < 0) {
                        perror("Error Writing to client\n");
                        exit(1);
                    }
                    /* Printing authentication info to screen. */
                    fprintf(stdout, "%s : %s:%d %s %s \n", buf, inet_ntoa(user_key->sin_addr), user_key->sin_port, user_name, "authenticated");
                    fflush(stdout);
                    /* Printing authentication info to our log file. */
                    fprintf(fp, "%s : %s:%d %s %s \n", buf, inet_ntoa(user_key->sin_addr), user_key->sin_port, user_name, "authenticated");
                    fflush(fp);
                    g_key_file_free(keyfile);
                    return FALSE;
                } else {
                    /* If the password was not correct we increment the login tries. */
                    user->loginTries = user->loginTries + 1;

                    /* */
                    if(user->loginTries > 3) {
                        if(SSL_write(user->ssl, "Too many failed login tries, disconnecting.\n", strlen("Too many failed login tries, disconnecting.")) < 0) {
                            perror("Error Writing to client\n");
                            exit(1);
                        }
                        
                        /* If the  */
                        if(user->room_name != NULL) {
                            struct room *previous_room = g_tree_search(room_tree, search_strcmp, user->room_name);
                            previous_room->users = g_list_remove(previous_room->users, user_key);
                        }

                        /* Printing authentication error to screen. */
                        fprintf(stdout, "%s : %s:%d %s %s \n", buf, inet_ntoa(user_key->sin_addr), user_key->sin_port, user_name, "authentication error");
                        fflush(stdout);
                        /* Printing authentication error to log file */
                        fprintf(fp, "%s : %s:%d %s %s \n", buf, inet_ntoa(user_key->sin_addr), user_key->sin_port, user_name, "authentication error");
                        fflush(fp);
                        /* Printing disconnect message to screen. */
                        fprintf(stdout, "%s : %s:%d %s \n", buf, inet_ntoa(user_key->sin_addr), user_key->sin_port,  "disconnected for too many login tries.");
                        fflush(stdout);
                        /* Printing disconnect message to log file. */
                        fprintf(fp, "%s : %s:%d %s \n", buf, inet_ntoa(user_key->sin_addr), user_key->sin_port,  "disconnected for too many login tries.");
                        fflush(fp);

                        /*  */
                        g_tree_remove(user_tree, user_key);

                        g_key_file_free(keyfile);
                        return FALSE;
                    }
                    if(SSL_write(user->ssl, "Incorrect password.", strlen("Incorrect password.")) < 0) {
                        perror("Error Writing to client\n");
                        exit(1);
                    }
                    fprintf(stdout, "%s : %s:%d %s %s \n", buf, inet_ntoa(user_key->sin_addr), user_key->sin_port, user_name, "authentication error");
                    fflush(stdout);
                    fprintf(fp, "%s : %s:%d %s %s \n", buf, inet_ntoa(user_key->sin_addr), user_key->sin_port, user_name, "authentication error");
                    fflush(fp);
                    g_key_file_free(keyfile);
                    return FALSE;
                }
            }

            if(strlen(user->nick_name) == 0) {
                strcpy(user->nick_name, user_name);
            }

            strncpy(user->username, user_name, strlen(user_name));
            strncpy(user->nick_name, user_name, strlen(user_name));

            password_fp = fopen("src/passwords.ini", "w");
            gchar *passwd64 = g_base64_encode((const guchar *) password, strlen(password));
            g_key_file_set_string(keyfile, "passwords", user_name, passwd64);
            gsize length;
            gchar *keyfile_string = g_key_file_to_data(keyfile, &length, NULL);
            fprintf(password_fp, "%s", keyfile_string);
            g_free(keyfile_string);
            g_free(passwd64);
            g_key_file_free(keyfile);
            fclose(password_fp);

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
                strcat(_recvMessage, user->username);
                strcat(_recvMessage, " [");
                strcat(_recvMessage, user->nick_name);
                strcat(_recvMessage, "]: ");
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

    ctx = NULL;
    const SSL_METHOD *method = SSLv3_server_method();
    /* Initialize OpenSSL */
    /* Load encryption & hash algorithms for SSL */
    SSL_library_init();
    /* Load the error strings for good error reporting */
    SSL_load_error_strings();

    ctx = SSL_CTX_new(method);    

    if(!ctx) {
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
