#include <cerrno>
#include <chrono>
#include <thread>

int accept_with_retry(int server_fd)
{
    const int max_retries = 5;
    int retry_count = 0;

    while (true)
    {
        int sock = accept(server_fd, nullptr, nullptr);
        if (sock >= 0)
            return sock;

        if (errno == EAGAIN || errno == EINTR)
        {
            if (retry_count++ >= max_retries)
            {
                std::cerr << "Max retry attempts reached, skipping...\n";
                return -1;
            }
            std::cerr << "Temporary network issue, retrying...\n";
            std::this_thread::sleep_for(std::chrono::milliseconds(100)); // Короткая пауза перед повторной попыткой
            continue;
        }
        else
        {
            std::cerr << "accept() error: " << strerror(errno) << "\n";
            return -1;
        }
    }
}

int main()
{
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0)
    {
        std::cerr << "socket() error\n";
        return 1;
    }

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(4000);
    if (bind(server_fd, (sockaddr *)&addr, sizeof(addr)) < 0)
    {
        std::cerr << "bind() error\n";
        return 1;
    }
    if (listen(server_fd, 5) < 0)
    {
        std::cerr << "listen() error\n";
        return 1;
    }
    std::cout << "Server started on port 4000\n";

    while (true)
    {
        int sock = accept_with_retry(server_fd);
        if (sock < 0)
            continue; // Пропускаем ошибочное соединение, но продолжаем работу

        std::cout << "Client connected\n";
        // Обработка запроса...
        close(sock);
    }

    close(server_fd);
    return 0;
}