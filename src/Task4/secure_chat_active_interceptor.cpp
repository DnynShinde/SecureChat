#include <stdio.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <thread>

// C++ Libraries
#include <iostream>
#include <string>
#include <arpa/inet.h>

// OpenSSL libraries
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>

#define MAX 1024
#define DEFAULT_PORT 8080
#define CLIENT_PORT 12001
#define SERVER_PORT 12002
#define SA struct sockaddr

using namespace std;

// Variables
int sockfd, connfd, new_sockfd;
struct sockaddr_in addr, new_addr;
struct timeval timeout;
socklen_t addr_len = sizeof(addr);
socklen_t new_addr_len = sizeof(new_addr);
char buff[MAX];
bool isClient;

SSL_CTX* new_ssl_context;
SSL_CTX*ssl_context;
SSL *ssl, *new_ssl;
BIO *new_bio, *new_out, *bio, *out;

// Function to get IP address from hostname
string getIPAddress(const char* hostname) {
    struct hostent *host_entry;
    struct in_addr **addr_list;

    if ((host_entry = gethostbyname(hostname)) == NULL) {
        herror("gethostbyname");
        exit(EXIT_FAILURE);
    }

    addr_list = (struct in_addr **)host_entry->h_addr_list;

    // Return the first IP address
    return inet_ntoa(*addr_list[0]);
}

// function to clear buffer 
void clearBuffer(char* buffer, size_t size) {
    memset(buffer, 0, size);
}


int generateCookieCallback(SSL *ssl_context, unsigned char *session_cookie, unsigned int *cookie_len) {
    memcpy(session_cookie, "ses_co", 6);
    *cookie_len = 6;
    return 1;
}

int verifyCookieCallback(SSL *ssl_context, const unsigned char *session_cookie, unsigned int cookie_len) {
    return 1;
}

// Function to send a message to the socket
void sendMessageToSocket(const string& s) {
    sendto(sockfd, s.c_str(), s.length(), MSG_CONFIRM, (const struct sockaddr*)&addr, addr_len);
}

// Function to receive a message from the socket
string receiveMessageFromSocket(bool printit) {
    char received[MAX];
    int n = recvfrom(sockfd, received, MAX - 1, MSG_WAITALL, (struct sockaddr*)&addr, &addr_len);
    received[n] = '\0';

    if (printit)
        printf("Message received : %s\n", received);

    return string(received);
}

// Function to write to SSL
void writeToSSL(const std::string& message) {
    SSL_write(ssl, message.c_str(), message.length());
}

// Function to load certificates for SSL
void loadCertificates() {
    const char* certificate;
    const char* privateKey;

    if (isClient) {
        certificate = "fakealice_cert.pem";
        privateKey = "fakealicekey.pem";
    } else {
        certificate = "bob_cert.pem";
        privateKey = "bob.pem";
    }

    // Load Certificate and Private Key
    if (SSL_CTX_use_certificate_file(ssl_context, certificate, SSL_FILETYPE_PEM) <= 0 ||
        SSL_CTX_use_PrivateKey_file(ssl_context, privateKey, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        cout << "Error loading certificate or private key\n";
        exit(EXIT_FAILURE);
    }

    // Verify private key
    if (!SSL_CTX_check_private_key(ssl_context)) {
        cout << "Private Key Verification failed!\n";
        exit(EXIT_FAILURE);
    }

    cout << "Private key loaded and verified successfully!\n";

    // Load CAfile and verify
    const char* CAfile = "ca_chain.pem";
    if (!SSL_CTX_load_verify_locations(ssl_context, CAfile, NULL)) {
        ERR_print_errors_fp(stderr);
        cout << "CA verification failed\n";
        exit(EXIT_FAILURE);
    }

    // Client/Server Certificate verification
    SSL_CTX_set_verify(ssl_context, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);

    // Set the cipher list
    if (SSL_CTX_set_cipher_list(ssl_context, "ECDHE-RSA-AES256-GCM-SHA384") != 1) {
        ERR_print_errors_fp(stderr);
        cout << "Error setting cipher list\n";
        exit(EXIT_FAILURE);
    }

    // Enable SSL_OP_NO_TICKET to disable session tickets
    SSL_CTX_set_options(ssl_context, SSL_OP_NO_TICKET);
}

// Function to initialize OpenSSL
void initializeOpenSSL() {
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
    ERR_load_crypto_strings();

    ssl_context = SSL_CTX_new(DTLS_method());
    if (!ssl_context) {
        perror("Error creating SSL context");
        exit(EXIT_FAILURE);
    }

    SSL_CTX_set_min_proto_version(ssl_context, DTLS1_2_VERSION);

    SSL_CTX_set_security_level(ssl_context, 1);
    SSL_CTX_set_verify(ssl_context, SSL_VERIFY_PEER, NULL);
    SSL_CTX_set_session_cache_mode(ssl_context, SSL_SESS_CACHE_OFF);

    if (!isClient) {
        SSL_CTX_set_cookie_generate_cb(ssl_context, generateCookieCallback);
        SSL_CTX_set_cookie_verify_cb(ssl_context, &verifyCookieCallback);
        bio = BIO_new_dgram(sockfd, BIO_NOCLOSE);
        BIO_ctrl(bio, BIO_CTRL_DGRAM_SET_RECV_TIMEOUT, 0, &timeout);
        if (!bio) {
            cout << "Error in creating bio";
            exit(EXIT_FAILURE);
        }
    }

    loadCertificates();
}

// Function to show supported cipher suites
void showSupportedCipherSuites() {
    STACK_OF(SSL_CIPHER)* ciphers = SSL_get_ciphers(ssl);
    if (ciphers) {
        cout << "Supported Cipher Suites by Client:" << endl;
        for (int i = 0; i < sk_SSL_CIPHER_num(ciphers); i++) {
            const SSL_CIPHER *cipher = sk_SSL_CIPHER_value(ciphers, i);
            const char *name = SSL_CIPHER_get_name(cipher);
            cout << "- " << name << endl;
        }
    } else {
        cout << "No supported cipher suites found." << endl;
    }
}

// Function to print selected cipher suite
void printSelectedCipherSuite() {
    const char* cipher = SSL_get_cipher(ssl);
    if (cipher) {
        cout << "Selected Cipher Suite: " << cipher << endl;
    }
    else {
        cout << "Failed to retrieve selected cipher suite." << endl;
    }
}

// Function to perform SSL handshake
void doSSLHandshake() {
    // Now doing handshake
    ssl = SSL_new(ssl_context);

    if (isClient == true) {
        SSL_set_fd(ssl, sockfd);
        int res = SSL_connect(ssl);
        if (res <= 0) {
            ERR_print_errors_fp(stderr);
            int error = SSL_get_error(ssl, res);
            std::cerr << "Error in SSL_connect! \n  --";
            cout << " Error : " << error << endl;
            exit(EXIT_FAILURE);
        }
    } else {
        bio = BIO_new_dgram(sockfd, BIO_NOCLOSE);
        BIO_ctrl(bio, BIO_CTRL_DGRAM_SET_RECV_TIMEOUT, 0, &timeout);
        if (!bio) {
            cout << "Error in creating bio";
            exit(EXIT_FAILURE);
        }
        SSL_set_bio(ssl, bio, bio);

        int res = DTLSv1_listen(ssl, (BIO_ADDR*)&addr);
        if (res < 0) {
            cout << "Error in connecting to Client";
            ERR_print_errors_fp(stderr);
            exit(EXIT_FAILURE);
        }
        SSL_accept(ssl);
    }
}

// Function to receive messages on the server side
void receiveMessagesServer() {
    while (true) {
        int bytes = SSL_read(ssl, buff, sizeof(buff));
        if (bytes <= 0) {
            ERR_print_errors_fp(stderr);
            break;
        }
        buff[bytes] = '\0';
        cout << "Message from Client: " << buff << endl;

        if (strncmp(buff, "exit", 4) == 0) {
            cout << "Connection Closed!\n";
            break;
        }
    }
}

// Function to receive messages on the client side
void receiveMessagesClient() {
    while (true) {
        int bytes = SSL_read(ssl, buff, sizeof(buff));
        if (bytes <= 0) {
            ERR_print_errors_fp(stderr);
            break;
        }
        buff[bytes] = '\0';
        cout << "Message from Server: " << buff << endl;

        if (strncmp(buff, "exit", 4) == 0) {
            cout << "Connection Closed!\n";
            break;
        }
    }
}


/*---------------------------Everything for the Active MITM Attack----------------------------------------*/

int new_generateCookieCallback(SSL *new_ssl_context, unsigned char *new_session_cookie, unsigned int *new_cookie_len) {
    memcpy(new_session_cookie, "ses_co", 6);
    *new_cookie_len = 6;
    return 1;
}

int new_verifyCookieCallback(SSL *new_ssl_context, const unsigned char *new_session_cookie, unsigned int new_cookie_len) {
    return 1;
}

// Function to send a message to the socket
void new_sendMessageToSocket(const string& s) {
    sendto(new_sockfd, s.c_str(), s.length(), MSG_CONFIRM, (const struct sockaddr*)&new_addr, new_addr_len);
}

// Function to receive a message from the socket
string new_receiveMessageFromSocket(bool printit) {
    char received[MAX];
    int n = recvfrom(new_sockfd, received, MAX - 1, MSG_WAITALL, (struct sockaddr*)&new_addr, &new_addr_len);
    received[n] = '\0';

    if (printit)
        printf("Message received : %s\n", received);

    return string(received);
}

// Function to write to SSL
void new_writeToSSL(const std::string& message) {
    SSL_write(new_ssl, message.c_str(), message.length());
}

// Function to load certificates for SSL
void new_loadCertificates() {
    const char* certificate;
    const char* privateKey;

    if (isClient) {
        certificate = "alice_cert.pem";
        privateKey = "alice.pem";
    } else {
        certificate = "fakebob_cert.pem";
        privateKey = "fakebobkey.pem";
    }

    // Load Certificate and Private Key
    if (SSL_CTX_use_certificate_file(new_ssl_context, certificate, SSL_FILETYPE_PEM) <= 0 ||
        SSL_CTX_use_PrivateKey_file(new_ssl_context, privateKey, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        cout << "Error loading certificate or private key\n";
        exit(EXIT_FAILURE);
    }

    // Verify private key
    if (!SSL_CTX_check_private_key(new_ssl_context)) {
        cout << "Private Key Verification failed!\n";
        exit(EXIT_FAILURE);
    }

    cout << "Private key loaded and verified successfully!\n";

    // Load CAfile and verify
    const char* CAfile = "ca_chain.pem";
    if (!SSL_CTX_load_verify_locations(new_ssl_context, CAfile, NULL)) {
        ERR_print_errors_fp(stderr);
        cout << "CA verification failed\n";
        exit(EXIT_FAILURE);
    }

    // Client/Server Certificate verification
    SSL_CTX_set_verify(new_ssl_context, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);

    // Set the cipher list
    if (SSL_CTX_set_cipher_list(new_ssl_context, "ECDHE-RSA-AES256-GCM-SHA384") != 1) {
        ERR_print_errors_fp(stderr);
        cout << "Error setting cipher list\n";
        exit(EXIT_FAILURE);
    }

    // Enable SSL_OP_NO_TICKET to disable session tickets
    SSL_CTX_set_options(new_ssl_context, SSL_OP_NO_TICKET);
}

// Function to initialize OpenSSL
void new_initializeOpenSSL() {
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
    ERR_load_crypto_strings();

    new_ssl_context= SSL_CTX_new(DTLS_method());
    if (!new_ssl_context) {
        perror("Error creating SSL context");
        exit(EXIT_FAILURE);
    }

    SSL_CTX_set_min_proto_version(new_ssl_context, DTLS1_2_VERSION);

    SSL_CTX_set_security_level(new_ssl_context, 1);
    SSL_CTX_set_verify(new_ssl_context, SSL_VERIFY_PEER, NULL);
    SSL_CTX_set_session_cache_mode(new_ssl_context, SSL_SESS_CACHE_OFF);

    if (!isClient) {
        SSL_CTX_set_cookie_generate_cb(new_ssl_context, new_generateCookieCallback);
        SSL_CTX_set_cookie_verify_cb(new_ssl_context, &new_verifyCookieCallback);
        new_bio = BIO_new_dgram(new_sockfd, BIO_NOCLOSE);
        BIO_ctrl(new_bio, BIO_CTRL_DGRAM_SET_RECV_TIMEOUT, 0, &timeout);
        if (!new_bio) {
            cout << "Error in creating bio";
            exit(EXIT_FAILURE);
        }
    }

    new_loadCertificates();
}

// Function to show supported cipher suites
void new_showSupportedCipherSuites() {
    STACK_OF(SSL_CIPHER)* ciphers = SSL_get_ciphers(new_ssl);
    if (ciphers) {
        cout << "Supported Cipher Suites by Client:" << endl;
        for (int i = 0; i < sk_SSL_CIPHER_num(ciphers); i++) {
            const SSL_CIPHER *cipher = sk_SSL_CIPHER_value(ciphers, i);
            const char *name = SSL_CIPHER_get_name(cipher);
            cout << "- " << name << endl;
        }
    } else {
        cout << "No supported cipher suites found." << endl;
    }
}

// Function to print selected cipher suite
void new_printSelectedCipherSuite() {
    const char* cipher = SSL_get_cipher(new_ssl);
    if (cipher) {
        cout << "Selected Cipher Suite: " << cipher << endl;
    }
    else {
        cout << "Failed to retrieve selected cipher suite." << endl;
    }
}

// Function to perform SSL handshake
void new_doSSLHandshake() {
    // Now doing handshake
    new_ssl = SSL_new(new_ssl_context);

    if (isClient == true) {
        SSL_set_fd(new_ssl, new_sockfd);
        int res = SSL_connect(new_ssl);
        if (res <= 0) {
            ERR_print_errors_fp(stderr);
            int error = SSL_get_error(new_ssl, res);
            std::cerr << "Error in SSL_connect! \n  --";
            cout << " Error : " << error << endl;
            exit(EXIT_FAILURE);
        }
    } else {
        new_bio = BIO_new_dgram(new_sockfd, BIO_NOCLOSE);
        BIO_ctrl(new_bio, BIO_CTRL_DGRAM_SET_RECV_TIMEOUT, 0, &timeout);
        if (!new_bio) {
            cout << "Error in creating bio";
            exit(EXIT_FAILURE);
        }
        SSL_set_bio(new_ssl, new_bio, new_bio);

        int res = DTLSv1_listen(new_ssl, (BIO_ADDR*)&new_addr);
        if (res < 0) {
            cout << "Error in connecting to Client";
            ERR_print_errors_fp(stderr);
            exit(EXIT_FAILURE);
        }
        SSL_accept(new_ssl);
    }
}

// Function to receive messages on the server side
void new_receiveMessagesServer() {
    while (true) {
        int bytes = SSL_read(new_ssl, buff, sizeof(buff));
        if (bytes <= 0) {
            ERR_print_errors_fp(stderr);
            break;
        }
        buff[bytes] = '\0';
        cout <<endl<< "Message from Client: " << buff << endl;
        cout<<"Enter message to send:";
        if (strncmp(buff, "exit", 4) == 0) {
            cout << "Connection Closed!\n";
            break;
        }
    }
}


// Function to receive messages on the client side
void new_receiveMessagesClient() {
    while (true) {
        int bytes = SSL_read(new_ssl, buff, sizeof(buff));
        if (bytes <= 0) {
            ERR_print_errors_fp(stderr);
            break;
        }
        buff[bytes] = '\0';
        cout<< "Message from Server: " << buff << endl;
        
        if (strncmp(buff, "exit", 4) == 0) {
            cout << "Connection Closed!\n";
            break;
        }
    }
}

/*----------------------------------------End functions for active MITM attack-------------------------------------------*/



// Function to start the server
void startServer() {
    isClient = false;
    struct sockaddr_in server_addr;

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(DEFAULT_PORT);

    // Getting IP address for the hostname
    const string ip = getIPAddress("bob1");
    const char* IP = ip.c_str();  // Declare and assign value to IP variable

    // Convert IP address string to network format
    server_addr.sin_addr.s_addr = inet_addr(IP);

    socklen_t server_addr_len = sizeof(server_addr);

    if (bind(sockfd, (SA*)&server_addr, server_addr_len) != 0) {
        perror("socket bind failed");
        exit(EXIT_FAILURE);
    }
    else
        cout << "Socket successfully binded. Server Listening on PORT : " << DEFAULT_PORT << endl << endl;

    // Processing Initial Message
    if (receiveMessageFromSocket(true) != "chat_hello") {
        cerr << "Failed to receive chat_hello" << endl;
        exit(EXIT_FAILURE);
    }
    cout << "Sending chat_reply_ok" << endl;
    sendMessageToSocket("chat_reply_ok");
    
    if (receiveMessageFromSocket(true) != "chat_START_SSL") {
        cerr << "Failed to receive chat_START_SSL" << endl;
        exit(EXIT_FAILURE);
    }
    cout << "Sending chat_START_SSL_ACK" << endl;
    sendMessageToSocket("chat_START_SSL_ACK");

    // Initializing OpenSSL
    cout << " Initializing OpenSSL \n";
    initializeOpenSSL();
    cout << "OpenSSL initialized successfully!\n\n";

    // Doing Handshake
    cout << " Doing DTLS handshake \n";
    doSSLHandshake();

    printSelectedCipherSuite(); 

    cout << " DTLS connection established!\n";

    if (SSL_get_peer_certificate(ssl) && SSL_get_verify_result(ssl) == X509_V_OK)
        cout << "Client Certificate Verified! \n";

    bool loop = true;
    thread receiveThread(receiveMessagesServer);
    cout << "Enter message to send:"<<endl;
    while (loop) {
        string userInput;
        getline(cin, userInput);
        writeToSSL(userInput);
        if (userInput == "exit") {
            sendMessageToSocket("exit");
            break;
        }
    }
}



// Function to start the client
void startClient(const char* IP) {
    isClient = true;

    new_addr.sin_family = AF_INET;
    new_addr.sin_port = htons(DEFAULT_PORT);
    new_addr.sin_addr.s_addr = inet_addr(IP);
    

    // Connect Socket
    if (connect(new_sockfd, (struct sockaddr*)&new_addr, sizeof(new_addr)) < 0) {
        perror("Error in connecting socket from client");
        exit(EXIT_FAILURE);
    }

    cout<<"Client Connected to the: "<<IP<<":"<<DEFAULT_PORT<<endl;

    // Processing Initial Messages
    cout << "Sending chat_hello" << endl;
    new_sendMessageToSocket("chat_hello");
    if (new_receiveMessageFromSocket(true) != "chat_reply_ok") {
        cerr << "Failed to receive chat_reply_ok" << endl;
        exit(EXIT_FAILURE);
    }

    cout << "Sending chat_START_SSL" << endl;
    new_sendMessageToSocket("chat_START_SSL");

    if (new_receiveMessageFromSocket(true) != "chat_START_SSL_ACK") {
         cerr << "Failed to receive chat_START_SSL_ACK" << endl;
        

        cerr << "Failed to receive chat_START_SSL_ACK" << endl;
        exit(EXIT_FAILURE);
    }

    // Initializing OpenSSL
    cout << " Initializing OpenSSL \n";
    new_initializeOpenSSL();
    cout << "OpenSSL initialized successfully!\n\n";

    // Doing Handshake
    new_doSSLHandshake();

    // Show supported cipher suites
    new_showSupportedCipherSuites();

    // Print the selected cipher suit
    new_printSelectedCipherSuite();
    
    cout << "DTLS connection established!\n";

    if (SSL_get_peer_certificate(ssl) && SSL_get_verify_result(new_ssl) == X509_V_OK)
        cout << "Server Certificate Verified! \n";

    bool loop = true;
    thread receiveThread(new_receiveMessagesClient);
    cout<<"Enter message to send:";
    while (loop) {
        string userInput;
        
        getline(cin, userInput);
        new_writeToSSL(userInput);
        if (userInput == "exit") {
            new_sendMessageToSocket("exit");
            break;
        }
    }
}

void trudyServer(){
isClient = false;
    struct sockaddr_in trudy_server_addr;

    trudy_server_addr.sin_family = AF_INET;
    trudy_server_addr.sin_port = htons(DEFAULT_PORT);

    // Getting IP address for the hostname
    const string ip = getIPAddress("trudy1");
    const char* IP = ip.c_str();  // Declare and assign value to IP variable

    // Convert IP address string to network format
    trudy_server_addr.sin_addr.s_addr = inet_addr(IP);

    socklen_t trudy_server_addr_len = sizeof(trudy_server_addr);

    if (bind(new_sockfd, (SA*)&trudy_server_addr, trudy_server_addr_len) != 0) {
        perror("socket bind failed");
        exit(EXIT_FAILURE);
    }
    else
        cout << "Socket successfully binded. Trudy Server Listening on PORT : " << DEFAULT_PORT << endl << endl;

    // Processing Initial Message
    if (new_receiveMessageFromSocket(true) != "chat_hello") {
        cerr << "Failed to receive chat_hello" << endl;
        exit(EXIT_FAILURE);
    }
    cout << "Sending chat_reply_ok" << endl;
    new_sendMessageToSocket("chat_reply_ok");
    
    if (new_receiveMessageFromSocket(true) != "chat_START_SSL") {
        cerr << "Failed to receive chat_START_SSL" << endl;
        exit(EXIT_FAILURE);
    }
    cout << "Sending chat_START_SSL_ACK" << endl;
    new_sendMessageToSocket("chat_START_SSL_ACK");

    cout<<"Establishing connection between Client & Trudy"<<endl;

    // Initializing OpenSSL
    cout << " Initializing OpenSSL \n";
    new_initializeOpenSSL();
    cout << "OpenSSL initialized successfully!\n\n";

    // Doing Handshake
    cout << " Doing DTLS handshake \n";
    new_doSSLHandshake();

    new_printSelectedCipherSuite(); 

    cout << " DTLS connection established between Client & Trudy!\n";

    if (SSL_get_peer_certificate(ssl) && SSL_get_verify_result(ssl) == X509_V_OK)
        cout << "Client Certificate Verified! \n";

    return;
}

void trudyClient(const char* IP){
    isClient = true;

    addr.sin_family = AF_INET;
    addr.sin_port = htons(DEFAULT_PORT);
    addr.sin_addr.s_addr = inet_addr(IP);
    
    cout<<"Establishing connection between Trudy and Server"<<endl;
    // Connect Socket
    if (connect(sockfd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("Error in connecting socket from client");
        exit(EXIT_FAILURE);
    }

    cout<<"Client Connected to the: "<<IP<<":"<<DEFAULT_PORT<<endl;

    // Processing Initial Messages
    cout << "Sending chat_hello" << endl;
    sendMessageToSocket("chat_hello");
    if (receiveMessageFromSocket(true) != "chat_reply_ok") {
        cerr << "Failed to receive chat_reply_ok" << endl;
        exit(EXIT_FAILURE);
    }

    cout << "Sending chat_START_SSL" << endl;
    sendMessageToSocket("chat_START_SSL");

    if (receiveMessageFromSocket(true) != "chat_START_SSL_ACK") {
         cerr << "Failed to receive chat_START_SSL_ACK" << endl;
        

        cerr << "Failed to receive chat_START_SSL_ACK" << endl;
        exit(EXIT_FAILURE);
    }

    // Initializing OpenSSL
    cout << " Initializing OpenSSL \n";
    initializeOpenSSL();
    cout << "OpenSSL initialized successfully!\n\n";

    // Doing Handshake
    doSSLHandshake();
    

    // Show supported cipher suites
    showSupportedCipherSuites();

    // Print the selected cipher suit
    printSelectedCipherSuite();
    
    cout << "DTLS connection established between Trudy & Server!\n";

    if (SSL_get_peer_certificate(ssl) && SSL_get_verify_result(ssl) == X509_V_OK)
        cout << "Server Certificate Verified! \n";
}

void start_trudy(const char* client, const char* server){

// Establish DTLS Connection with Client & Trudy
    trudyServer();

// Establish DTLS Connection between Trudy & Server
    const string ip = getIPAddress(server);
    trudyClient(ip.c_str());
        
    while (true) {
        string messageFromClient;
        string messageFromServer;
        int new_bytes = SSL_read(new_ssl, buff, sizeof(buff));
        if(new_bytes<=0){
            ERR_print_errors_fp(stderr);
            break;
        }
        buff[new_bytes] = '\0';
        cout << "Message from Client: " <<buff <<endl;
        messageFromClient+= buff;
        // sending message to the server
        writeToSSL(messageFromClient);
        
        clearBuffer(buff, sizeof(buff));

        int bytes = SSL_read(ssl, buff, sizeof(buff));
        if(bytes<=0){
            ERR_print_errors_fp(stderr);
            break;
        }
        buff[bytes] = '\0';
        cout << "Message from Server: " <<buff <<endl;
        messageFromServer+= buff;

        // Writing back to the client
        new_writeToSSL(messageFromServer);
    }
}


int main(int argc, char **argv) {
    // Checking command line arguments
    if (argc < 2 || (strcmp(argv[1], "-s") != 0 && strcmp(argv[1], "-c") != 0 && strcmp(argv[1], "-d") != 0)) {
        printf("Usage: %s <-s | -c> [hostname]\n", argv[0]);
        return 1;
    }

    // Initializing socket
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    new_sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("Socket creation failed");
        return 1;
    }
    printf("Socket successfully created.\n");

    bzero(&addr, sizeof(addr));
    bzero(&new_addr, sizeof(new_addr));

    // Starting server or client based on command line arguments
    if (strcmp(argv[1], "-s") == 0)
        startServer();
    else if (strcmp(argv[1], "-c") == 0 && argc == 3) {
        const char* hostname = argv[2];
        const string ip = getIPAddress(hostname);
        startClient(ip.c_str());
    } else if(strcmp(argv[1], "-d") == 0 && argc ==4) {
       const char* ServerIP = argv[2];
       const char* ClientIP = argv[3];
        start_trudy(argv[2], argv[3]);
    }else{
         printf("Invalid arguments.\n");
        return 1;
    }

    return 0;
}
