# Setup

## Running the server

When running the server we assume that the *port* number is a argument to the server. We also have the absolute path of the *certificate* and *key* files hardcoded in the *macros* section in the program.

For example:

```./src/chatd $(/labs/tsam15/my_port)```

## Running the client

When running the client we assume that the *port* number is a argument to the server. We also have the absolute paht of the *pem file* hardcoded in the *macros* section in the program.

For example:

```./src/chat $(/labs/tsam15/my_port)```

## Other useful information

It is probably best to mention that we have hardcoded four rooms in the server. The rooms that can be join are as follows:

1. Room1

2. Room2

3. Room3

4. Room4

To join them the user can use the command */join <roomname>* as stated in the requirement.

The only command that we added to the server that were not mentioned in the requirements is the */nick <nickname>* command. That command will change user's nickname.

# Questions

## Question 5
### Where are the passwords stored?

**Answer:** The passwords are stored in the file *passwords.ini* which is stored in our *src* folder. The only time the passwords are in memory is when the hashed string is read from SSL_read and later rehashed. The passwords are stored in the data structure *GKeyFile* while we are processing the login and registration. Then the data structure is freed. 

### Where are the salt strings stored?

**Answer:** The salt strings are stored in memory in both client and server as a *static char pointer*.

### Why do you send the plain text password/hashed password?

**Answer:** We send the password hashed because we don't want the plain text password in the server's memory at any point in time, we do this so that if someone gets read access to the server's data he can never see the user's plain-text password. 

### What are the security implications of your decision?

**Answer:** The plain-text password is never in the server's memory. The hashed password is encrypted over the network using SSL. The server re-hashes the password for storage so that a hacker cannot use the hashed password from the client to log in to his account. All users and their re-hashed passwords are stored in the *passwords.ini* file and are only in memory of the server when login and registration are in progress. We hash the password in the client 5001 times before sending it over SSL. In the server it is also re-hashed 5001 times. All in-memory data is memset before returning from login and registration. The client sends his login information first as plain-text username wit a SSL_write and then with another SSL_write only sending the password. The password is only read in login and registration. 

## Question 6
### Should private messages be logged?

**Answer:** No, there is no implementation in our server where we would ever need to use the logged private messages. Therefore we see no reason to log the private messages unless we would want some hacker to try to access them and have another *Vodafone Scandal* on our hands.

### If so, what should be logged about private messages?

**Answer:** We see no benign reason to log the private messages, see above.

### What are the consequences of your decisions?

**Answer:** Unwanted access to old messages is not an option. There is no history of any messages making our system trustworthy. There is no added overhead to the log file.
