#include "net-sink.h"
#include <string.h>
#include <iostream>
#include <unistd.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <atomic>
#include <thread>
#include <stdlib.h>
#include <signal.h>
#include "sniff-config.h"
#include <string>
#include "concurrentqueue.h"
#include <functional>

using std::string;


moodycamel::ConcurrentQueue<char *> log_queue;

std::atomic<bool> is_connected{ false };
// bool is_connected = false;
std::atomic<int> sockfd{ 0 };
// int sockfd = 0;
FILE *outstream_tcp = NULL;
string tcp_host;
int tcp_port;


void print_to_file(char* log_item);
bool parse_addr(const string addr, string &host, int &port);
void reconnect(string host, int port);
void send_log(string host, int port);

void tcp_sink_init(const char* addr) {
    string str_addr(addr);
    string host;
    int port;
    if (!parse_addr(str_addr, host, port)) {
        // perror("the tcp server addr error");
        fprintf(stderr, "the tcp server addr error");
        exit(-1);
    }
    tcp_host = host;
    tcp_port = port;

    string filename(config_get_logdir());
    if (filename == string("stdout")) {
        outstream_tcp = stdout;
    } else {
        filename += "/sql_query.log";
        outstream_tcp = fopen(filename.c_str(), "a+");
        if (outstream_tcp == NULL) {
            // std::cerr << "open file " << filename << " failed!" << std::endl;
            perror("tcp_sink_init,open file failed1");
        }
    }

    // printf("hello debug 1\n");

    // int sockfd;
    std::thread start_connect_thread(std::bind(&reconnect, host, port));
    start_connect_thread.detach();

    std::thread send_log_thread(std::bind(&send_log, host, port));
    send_log_thread.detach();
    // send_log(host, port);
    // send(socket_fd, send_buf, strlen(send_buf), MSG_NOSIGNAL);
    // signal(SIGPIPE, SIG_IGN);
}

bool parse_addr(const string addr, std::string &host, int &port) {
    auto pos = addr.find(":", 0);
    if (pos != string::npos) {
        host = addr.substr(0, pos);
        port = std::stoi(addr.substr(pos + 1, addr.length() - pos -1));
        return true;
    } else {
        return false;
    }
}

void reconnect(string host, int port) {
    sockfd.store(socket(AF_INET, SOCK_STREAM, 0));
    if (sockfd.load() == -1) {
        fprintf(stderr, "create socket error, errno:%d", errno);
        exit(-1);
    }

    int optval = 1;
    int sockret;
    sockret = setsockopt(sockfd.load(), SOL_SOCKET, SO_KEEPALIVE, &optval, sizeof(int));//使用KEEPALIVE
    if (sockret == -1) {
        fprintf(stderr, "setsockopt SO_KEEPALIVE error,errno:%d", errno);
        exit(-1);
    }
    sockret = setsockopt(sockfd.load(), IPPROTO_TCP, TCP_NODELAY, &optval, sizeof(int));//禁用NAGLE算法
    if (sockret == -1) {
        fprintf(stderr, "setsockopt TCP_NODELAY error,errno:%d", errno);
        exit(-1);
    }

    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = inet_addr(host.c_str());

    while (!is_connected.load()) {
        int ret = ::connect(sockfd.load(), (struct sockaddr*)&addr, sizeof(addr));
        if (ret < 0) {
            std::cout << "connect " << host << ":" << port << " failed, trying to reconnect..." << std::endl;
            usleep(3000 * 1000);
        } else {
            is_connected.store(true);
            std::cout << "connect " << host << ":" << port << " success!" << std::endl;
            break;
        }
    }
}

void send_log(std::string host, int port) {
    char *log_item = nullptr;
    while (true) {
        if (log_queue.try_dequeue(log_item) && log_item != nullptr) {
            if (strlen(log_item) == 0 || strlen(log_item) >= 2048) {
                std::cout << "wrong length: " << strlen(log_item) << std::endl;
                usleep(2000);
                continue;
            }
            if (is_connected.load()) {
                int ret = send(sockfd.load(), log_item, strlen(log_item), MSG_NOSIGNAL);
                if (ret <= 0) {
                    std::cout << "send failed!" << std::endl;
                    print_to_file(log_item);
                    delete [] log_item;

                    ::close(sockfd.load());
                    is_connected.store(false);
                    std::thread reconnect_thread(std::bind(&reconnect, host, port));
                    reconnect_thread.detach();
                }
#ifdef _CS_DEBUG_
                else
                {
                    fprintf(stdout, "send success: %s", log_item);
                    fflush(stdout);
                }
#endif
            } else {
                print_to_file(log_item);
                delete [] log_item;
            }
        }
        usleep(2000);
    }
}

void print_to_file(char* log_item) {
    if (outstream_tcp == NULL) {
        fprintf(stdout, "%s", log_item);
    } else {
        fprintf(outstream_tcp, "%s", log_item);
    }
}