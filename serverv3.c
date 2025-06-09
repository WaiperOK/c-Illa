#include <iostream>
#include <fstream>
#include <string>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <cstring>
#include <map>
#include <sstream>
#include <thread>
#include <vector>
#include <mutex>
#include <openssl/sha.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <ctime>
#include <algorithm>

std::map<std::string, std::string> users = {
    {"admin", "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"}, // "password"
    {"user", "12dff74e2fe2cf1c172e0a77a7d04217f8d51e4d0c37923f8f281eb61b90e6f8"}   // example
};

std::map<std::string, bool> protected_files = {
    {"secret.txt", true},
    {"confidential.dat", true}
};

std::mutex client_mutex;
std::ofstream log_file("server.log", std::ios::app);

std::string get_current_time()
{
    std::time_t now = std::time(nullptr);
    char buffer[80];
    std::strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", std::localtime(&now));
    return std::string(buffer);
}

void log(const std::string &message)
{
    std::lock_guard<std::mutex> lock(client_mutex);
    log_file << "[" << get_current_time() << "] " << message << std::endl;
    log_file.flush();
}

std::string sha256(const std::string &str)
{
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char *>(str.c_str()), str.size(), hash);

    std::ostringstream oss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i)
        oss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];

    return oss.str();
}

bool authenticate(const std::string &username, const std::string &password)
{
    bool auth_success = users.count(username) && users[username] == sha256(password);
    if (auth_success)
        log("Authentication successful for user: " + username);
    else
        log("Authentication failed for user: " + username);
    return auth_success;
}

void send_file_stream(int sock, const std::string &filename)
{
    std::ifstream file(filename, std::ios::binary);
    if (!file)
    {
        log("File not found: " + filename);
        std::string response = "HTTP/1.0 404 Not Found\r\n\r\nERROR: File not found\n";
        send(sock, response.c_str(), response.size(), 0);
        return;
    }

    log("Sending file: " + filename);
    std::string header = "HTTP/1.0 200 OK\r\n\r\n";
    send(sock, header.c_str(), header.size(), 0);

    char buffer[4096];
    while (file.read(buffer, sizeof(buffer)) || file.gcount() > 0)
        send(sock, buffer, file.gcount(), 0);

    log("File sent successfully: " + filename);
}

void handle_client(int sock, SSL *ssl)
{
    char buffer[1024];
    memset(buffer, 0, sizeof(buffer));
    ssize_t len = SSL_read(ssl, buffer, sizeof(buffer) - 1);
    if (len <= 0)
    {
        log("Client disconnected or SSL_read error: " + std::to_string(len));
        SSL_free(ssl);
        close(sock);
        return;
    }
    buffer[len] = '\0';

    log("Received request: " + std::string(buffer));

    std::istringstream req_stream(buffer);
    std::string line, filename, username, password;
    bool first_line = true;

    while (std::getline(req_stream, line))
    {
        if (first_line)
        {
            first_line = false;
            size_t start = line.find(' ') + 1;
            size_t end = line.find(' ', start);
            filename = line.substr(start, end - start);
            if (filename[0] == '/') filename = filename.substr(1);
            log("Requested file: " + filename);
        }
        else if (line.rfind("Auth: ", 0) == 0)
        {
            std::istringstream auth_stream(line.substr(6));
            std::getline(auth_stream, username, ':');
            std::getline(auth_stream, password);
            log("Auth header received for user: " + username);
        }
    }

    if (protected_files.count(filename) && protected_files[filename] && !authenticate(username, password))
    {
        log("Unauthorized access attempt to file: " + filename);
        std::string response = "HTTP/1.0 401 Unauthorized\r\n\r\nERROR: Unauthorized\n";
        SSL_write(ssl, response.c_str(), response.size());
        SSL_free(ssl);
        close(sock);
        return;
    }

    send_file_stream(sock, filename);
    SSL_free(ssl);
    close(sock);
}

SSL_CTX *initialize_ssl()
{
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();

    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx)
    {
        log("SSL_CTX_new() failed");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (!SSL_CTX_use_certificate_file(ctx, "cert.pem", SSL_FILETYPE_PEM))
    {
        log("Failed to load certificate file");
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        exit(EXIT_FAILURE);
    }

    if (!SSL_CTX_use_PrivateKey_file(ctx, "key.pem", SSL_FILETYPE_PEM))
    {
        log("Failed to load private key file");
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        exit(EXIT_FAILURE);
    }

    return ctx;
}

int main()
{
    SSL_CTX *ctx = initialize_ssl();

    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd == -1)
    {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }

    sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(4433);
    addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(server_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0)
    {
        perror("bind failed");
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    if (listen(server_fd, SOMAXCONN) < 0)
    {
        perror("listen failed");
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    log("Server started on port 4433");

    while (true)
    {
        sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        int client_fd = accept(server_fd, (struct sockaddr *)&client_addr, &client_len);
        if (client_fd < 0)
        {
            perror("accept failed");
            continue;
        }

        SSL *ssl = SSL_new(ctx);
        SSL_set_fd(ssl, client_fd);

        if (SSL_accept(ssl) <= 0)
        {
            log("SSL handshake failed");
            ERR_print_errors_fp(stderr);
            SSL_free(ssl);
            close(client_fd);
            continue;
        }

        std::thread(handle_client, client_fd, ssl).detach();
    }

    close(server_fd);
    SSL_CTX_free(ctx);
    return 0;
}
