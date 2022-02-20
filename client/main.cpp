/*************************************************************************
    > File Name: main.cpp
    > Author: hsz
    > Brief:
    > Created Time: Sat 12 Feb 2022 08:16:31 PM CST
 ************************************************************************/

#include "client.h"
#include <utils/utils.h>
#include <log/log.h>
#include <assert.h>
#include <string.h>
#include <iostream>
#include <string>
#include <unordered_map>
#include <thread>
#include <functional>
#include <mutex>
#include <sys/epoll.h>

using namespace std;

#define LOG_TAG "P2P_Client_Main"

#define UDP_PORT 8000
#define UDP_SERVER_PORT 6100
#define UDP_SERVER_IP "39.106.218.123"

std::string localIP = getLocalAddress()[0];

std::unordered_map<int, Peer_Info> gPeerInfoMap;
std::unordered_map<int, Peer_Info> gConnectedPeerInfoMap;
uint32_t gPeerCount;
std::mutex gMutex;

static int udpSock = -1;

int create_udp_socket(uint16_t port);

void send_peer_info(P2PClient &client)
{
    P2P_Request req;
    req.flag = P2P_FLAG_SEND_PEER_INFO;
    strcpy(req.peer_info.peer_name, PEER_NAME);

    int ret = client.send((char *)&req, sizeof(req));
    LOGD("send 0x%x over. %d\n", P2P_FLAG_SEND_PEER_INFO, ret);

    if (udpSock < 0) {
        udpSock = create_udp_socket(UDP_PORT);
        LOG_ASSERT(udpSock > 0, "send_peer_info()");
    }

    P2P_Response res;
    int recvSize = client.recv(&res, sizeof(P2P_Response));
    LOGD("%s() recvSize = %d\n", __func__, recvSize);

    sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr(UDP_SERVER_IP);
    addr.sin_port = htons(UDP_SERVER_PORT);

    if (recvSize == sizeof(P2P_Response)) {
        LOGI("%s() flag: %d; status code: %d; msg: %s\n", __func__, res.flag, res.statusCode, res.msg);
        ret = ::sendto(udpSock, res.conn.uuid, UUID_SIZE, 0, (sockaddr *)&addr, sizeof(sockaddr_in));
        LOGD("ret %d", ret);
        return;
    }

    LOGE("%s() error.", __func__);
}

int get_peer_info(P2PClient &client)
{
    P2P_Request req;
    req.flag = P2P_FLAG_GET_PEER_INFO;

    int ret = client.send((char *)&req, sizeof(P2P_Request));
    LOGD("%s() send 0x%x over. %d\n", __func__, P2P_FLAG_GET_PEER_INFO, ret);

    char buf[128] = {0};
    int recvSize = client.recv(buf, sizeof(P2P_Response));
    if (recvSize < 0) {
        LOGE("%s() recv error. [%d,%s]\n", __func__, errno, strerror(errno));
        return -1;
    }
    P2P_Response *res = (P2P_Response *)buf;
    ret = res->number;

    LOGD("get_peer_info() recv response: 0x%x; %d; %s; %d", res->flag, res->statusCode, res->msg, res->number);
    if (res->flag == P2P_FLAG_RESPONSE_GET_PEER_INFO && res->statusCode == 200) {
        gPeerCount = 0;
        gPeerInfoMap.clear();
        for (int i = 0; i < res->number; ++i) {
            memset(buf, 0, sizeof(buf));
            recvSize = client.recv(buf, sizeof(Peer_Info));
            LOGD("%s() recv size = %d, %zu", __func__, recvSize, sizeof(Peer_Info));
            if (recvSize == (int)sizeof(Peer_Info)) {
                Peer_Info *info = (Peer_Info *)buf;
                in_addr addr;
                addr.s_addr = info->host_binary;
                std::string uuid;
                char fmt[128] = {0};
                for (size_t j = 0; j < sizeof(info->peer_uuid); ++j) {
                    sprintf(fmt, "0x%02x ", info->peer_uuid[j]);
                    uuid.append(fmt);
                }
                LOGI("%s [%s:%d] %s", info->peer_name,
                    inet_ntoa(addr), ntohs(info->port_binary), uuid.c_str());
                gPeerInfoMap.insert(std::make_pair(gPeerCount++, *info));
            }
        }
    }

    return ret;
}

int connect_to_peer(P2PClient &client, uint32_t index)
{
    if (index <= 0) {
        LOGD("invalid index");
        return -1;
    }

    if (index > gPeerCount) {
        LOGE("invalid index");
        return -1;
    }
    const auto &it = gPeerInfoMap.find(index - 1);
    const Peer_Info &info = it->second;

    P2P_Request req;
    req.flag = P2P_FLAG_CONNECT_TO_PEER;
    memcpy(req.peer_info.peer_uuid, info.peer_uuid, UUID_SIZE);

    assert(client.send(&req, sizeof(req)) > 0 && "connect_to_peer");

    sockaddr_in serverAddr;
    socklen_t len;
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(UDP_SERVER_PORT);
    serverAddr.sin_addr.s_addr = inet_addr(UDP_SERVER_IP);

    usleep(200 * 1000);
    int ret = sendto(udpSock, info.peer_uuid, sizeof(info.peer_uuid), 0, (sockaddr *)&serverAddr, sizeof(serverAddr));
    if (ret <= 0) {
        LOGE("sendto error. [%d,%s]", errno, strerror(errno));
        return -1;
    }

    LOGI("sendto %s:%d success. %d", UDP_SERVER_IP, UDP_SERVER_PORT, ret);

    uint8_t buf[128] = {0};
    ret = ::recvfrom(udpSock, buf, sizeof(buf), 0, (sockaddr *)&serverAddr, &len);
    LOGD("ret = %d", ret);
    if (ret > 0) {
        LOGI("success connect: [%s:%d] %s", inet_ntoa(serverAddr.sin_addr), ntohs(serverAddr.sin_port), buf);
    }

    return udpSock;
}

int create_udp_socket(uint16_t port)
{
    int udpSock = ::socket(AF_INET, SOCK_DGRAM, 0);
    if (udpSock < 0) {
        LOGE("socket error. [%d,%s]", errno, strerror(errno));
        return -1;
    }

    LOGI("local ip: %s", localIP.c_str());

    sockaddr_in addr;
    memset(&addr, 0, sizeof(sockaddr_in));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = inet_addr(localIP.c_str());

    int ret = ::bind(udpSock, (sockaddr *)&addr, sizeof(addr));
    if (ret < 0) {
        LOGE("bind error. [%d,%s]", errno, strerror(errno));
        return ret;
    }

    int reUse = 1;
    setsockopt(udpSock, SOL_SOCKET, SO_REUSEADDR, &reUse, sizeof(reUse));
    struct timeval tv_out;
    tv_out.tv_sec = 2;
    tv_out.tv_usec = 0;
    setsockopt(udpSock, SOL_SOCKET, SO_SNDTIMEO, &tv_out, sizeof(tv_out));
    //setsockopt(udpSock, SOL_SOCKET, SO_RCVTIMEO, &tv_out, sizeof(tv_out));
    return udpSock;
}

void thread_loop(P2PClient &client)
{
    while (1) {
        LOGI("Enter function number:\n");
        int num = 0;
        scanf("%d", &num);

        switch (num) {
        case 1: // get all peer info
            get_peer_info(client);
            break;
        case 2:
            LOGI("which peer you want to connect\n");
            scanf("%d", &num);
            connect_to_peer(client, num);
        default:
            LOGW("invalid function number");
            break;
        }
    }
}

#define EPOLL_VEC_SIZE 16

void setnonblock(int fd)
{
    uint32_t flag = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flag | O_NONBLOCK);
}

int main(int argc, char **argv)
{
    P2PClient client;
    client.connect();
    send_peer_info(client);

    int epollFd = epoll_create(EPOLL_VEC_SIZE);
    LOG_ASSERT(epollFd > 0, "epoll_create error. [%d,%s]", errno, strerror(errno));

    int udpSock = create_udp_socket(8500);  // 与对端建立连接所用
    assert(udpSock > 0);

    epoll_event evs[EPOLL_VEC_SIZE];

    epoll_event ev;
    setnonblock(client.mSocket);
    ev.data.fd = client.mSocket;
    ev.events = EPOLLET | EPOLLIN;
    epoll_ctl(epollFd, EPOLL_CTL_ADD, client.mSocket, &ev);

    setnonblock(udpSock);
    ev.data.fd = udpSock;
    ev.events = EPOLLET | EPOLLIN;
    epoll_ctl(epollFd, EPOLL_CTL_ADD, udpSock, &ev);

    while (true) {
        int nev = epoll_wait(epollFd, evs, EPOLL_VEC_SIZE, 1000);
        LOG_ASSERT(nev >= 0, "epoll_wait error. [%d,%S]", errno, strerror(errno));
        LOGD("event number %d", nev);
        if (nev == 0) {
            if (get_peer_info(client) > 0) {
                int num;
                LOGI("which peer you want to connect\n");
                scanf("%d", &num);
                connect_to_peer(client, num);
            }
        }

        for (int i = 0; i < nev; ++i) {
            auto &event = evs[i];
            LOGI("event fd %d", event.data.fd);
            if (event.data.fd == client.mSocket) {  // TCP服务发送的建立连接请求
                P2P_Response res;
                int ret = client.recv(&res, sizeof(res), MSG_PEEK);
                LOGI("%s() recv size %d, flag = 0x%x", __func__, ret, res.flag);
                if (ret > 0 && res.flag == P2P_FLAG_RESPONSE_CONNECT_TO_ME) {
                    P2P_Connect conn = res.conn;
                    uint32_t host = ntohl(conn.host_binary);
                    uint16_t port = ntohs(conn.port_binary);
                    LOGI("peer: %s:%d [%s:%d]", inet_ntoa({conn.host_binary}), ntohs(conn.port_binary),
                        inet_ntoa({host}), ntohs(port));
                    sockaddr_in addr;
                    addr.sin_addr.s_addr = conn.host_binary;
                    addr.sin_family = AF_INET;
                    addr.sin_port = conn.port_binary;

                    sendto(udpSock, "hello world!", 12, 0, (sockaddr *)&addr, sizeof(addr));
                    client.recv(&res, sizeof(res));
                }
            }

            if (event.data.fd == udpSock) {
                sockaddr_in addr;
                socklen_t len;
                char buf[128] = {0};
                int ret = recvfrom(udpSock, buf, sizeof(buf), 0, (sockaddr *)&addr, &len);
                LOGI("ret = %d", ret);
                if (ret > 0) {
                    LOGI("buf = %s", buf);
                }
            }
        }
    }

    return 0;
}
