# Questions

## Question 5
### Where are the passwords stored?

**Answer:** The passwords are stored in the file *passwords.ini* which is stored in our *src* folder. The only time the passwords are in memory is when the hashed string is read from SSL_read and later rehashed. The passwords are stored in the data structure *GKeyFile* while we are processing the login and registration. Then the data structure is freed. 

### Where are the salt strings stored?

**Answer:** The salt strings are stored in memory in both client and server as a *static char pointer*.

### Why do you send the plain text password/hashed password?

**Answer:** 

### What are the security implications of your decision?

**Answer:** 

## Question 6
### Should private messages be logged?

**Answer:** 

### If so, what should be logged about private messages?

**Answer:** 

### What are the consequences of your decisions?

**Answer:** 
