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
#include <openssl/ssl.hics.h>
#include <openssl/err.h>
#include <ctime>

std::map<std::string, std::string> users = {
    {"admin", "5e884898da28047151d0e56f5fbfc1..."},
    {"user", "12dff74e2fe2cf1c172..."}}; // SHA-256 hashed passwords

std::map<std::string, bool> protected_files = {
    {"secret.txt", true},
    {"confidential.dat", true}};

std::mutex client_mutex;
std::ofstream log_file("server.log", std::ios::app);

// Функция для получения текущего времени в формате строки
std::string get_current_time() {
    std::time_t now = std::time(nullptr);
    char buffer[80];
    std::strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", std::localtime(&now));
    return std::string(buffer);
}

void log(const std::string &message) {
    std::lock_guard<std::mutex> lock(client_mutex);
    log_file << "[" << get_current_time() << "] " << message << std::endl;
    log_file.flush(); // Сразу записываем в файл
}

std::string sha256(const std::string &str) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char *>(str.c_str()), str.size(), hash);

    std::ostringstream oss;
    for (unsigned char c : hash)
        oss << std::hex << (int)c;

    return oss.str();
}

bool authenticate(const std::string &username, const std::string &password) {
    bool auth_success = users.count(username) && users[username] == sha256(password);
    if (auth_success) {
        log("Authentication successful for user: " + username);
    } else {
        log("Authentication failed for user: " + username);
    }
    return auth_success;
}

void send_file_stream(int sock, const std::string &filename) {
    std::ifstream file(filename, std::ios::binary);
    if (!file) {
        log("File not found: " + filename);
        std::string response = "HTTP/1.0 404 Not Found\r\n\r\nERROR: File not found\n";
        send(sock, response.c_str(), response.size(), 0);
        return;
    }

    log("Sending file: " + filename);
    std::string header = "HTTP/1.0 200 OK\r\n\r\n";
    send(sock, header.c_str(), header.size(), 0);

    char buffer[4096];
    while (file.read(buffer, sizeof(buffer)) || file.gcount() > 0) {
        send(sock, buffer, file.gcount(), 0);
    }
    log("File sent successfully: " + filename);
}

void handle_client(int sock, SSL *ssl) {
    char buffer[1024];
    memset(buffer, 0, sizeof(buffer));
    ssize_t len = SSL_read(ssl, buffer, sizeof(buffer) - 1);
    if (len <= 0) {
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

    while (std::getline(req_stream, line)) {
        if (first_line) {
            first_line = false;
            filename = line.substr(4, line.find(' ', 4) - 4);
            log("Requested file: " + filename);
        }
        else if (line.rfind("Auth: ", 0) == 0) {
            std::istringstream auth_stream(line.substr(6));
            std::getline(auth_stream, username, ':');
            std::getline(auth_stream, password);
            log("Auth header received for user: " + username);
        }
    }

    if (protected_files.count(filename) && protected_files[filename] && !authenticate(username, password)) {
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

SSL_CTX *initialize_ssl() {
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();

    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx) {
        log("SSL_CTX_new() failed");
        std::cerr << "SSL_CTX_new() error\n";
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (!SSL_CTX_use_certificate_file(ctx, "cert.pem", SSL_FILETYPE_PEM)) {
        log("Failed to load certificate file: cert.pem");
        std::cerr << "Failed to load certificate file\n";
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        exit(EXIT_FAILURE);
    }

    if (!SSL_CTX_use_PrivateKey_file(ctx, "key.pem", SSL_FILETYPE_PEM)) {
        log("Failed to load private key file: key.pem");
        std::cerr << "Failed to load private key file\n";
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        exit(EXIT_FAILURE);
    }

    if (!SSL_CTX_check_private_key(ctx)) {
        log("Private key does not match the certificate public key");
        std::cerr << "Private key does not match the certificate public key\n";
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        exit(EXIT_FAILURE);
    }

    log("SSL context initialized successfully");
    return ctx;
}

int main() {
    // Проверка открытия файла логов
    if (!log_file.is_open()) {
        std::cerr << "Failed to open log file\n";
        return 1;
    }

    log("Starting server...");

    SSL_CTX *ctx = initialize_ssl();

    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        log("socket() error: " + std::to_string(errno));
        std::cerr << "socket() error\n";
        return 1;
    }

    // Установка опции SO_REUSEADDR для повторного использования порта
    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(8443); // Используем порт 8443 вместо 443, чтобы не требовать прав root
    if (bind(server_fd, (sockaddr *)&addr, sizeof(addr)) < 0) {
        log("bind() error: " + std::to_string(errno));
        std::cerr << "bind() error\n";
        return 1;
    }
    if (listen(server_fd, 5) < 0) {
        log("listen() error: " + std::to_string(errno));
        std::cerr << "listen() error\n";
        return 1;
    }

    log("Secure server started on port 8443");
    std::cout << "Secure server started on port 8443\n";

    std::vector<std::thread> threads;

    while (true) {
        int sock = accept(server_fd, nullptr, nullptr);
        if (sock < 0) {
            log("accept() error: " + std::to_string(errno));
            std::cerr << "accept() error\n";
            continue;
        }

        log("New client connected, socket fd: " + std::to_string(sock));

        SSL *ssl = SSL_new(ctx);
        SSL_set_fd(ssl, sock);
        if (SSL_accept(ssl) <= 0) {
            log("SSL_accept() failed");
            ERR_print_errors_fp(stderr);
            SSL_free(ssl);
            close(sock);
            continue;
        }

        log("SSL handshake completed for client, socket fd: " + std::to_string(sock));

        {
            std::lock_guard<std::mutex> lock(client_mutex);
            threads.emplace_back(handle_client, sock, ssl);
        }

        // Очистка завершенных потоков
        threads.erase(
            std::remove_if(threads.begin(), threads.end(),
                [](std::thread &t) { return !t.joinable(); }),
            threads.end());
    }

    for (auto &thread : threads) {
        if (thread.joinable())
            thread.join();
    }

    SSL_CTX_free(ctx);
    close(server_fd);
    log("Server shutdown");
    return 0;
}
