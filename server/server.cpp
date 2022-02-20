/*************************************************************************
    > File Name: server.cpp
    > Author: hsz
    > Brief:
    > Created Time: Wed 09 Feb 2022 10:12:27 PM CST
 ************************************************************************/

#include "server.h"
#include <utils/Buffer.h>
#include <utils/string8.h>
#include <crypto/md5.h>
#include <assert.h>
#include <log/log.h>
#include <sys/epoll.h>
#include <unordered_map>
#include <map>
#include <string>
#include <time.h>
#include <sys/time.h>
#include <sys/uio.h>

#define LOG_TAG "TcpServer"
#define DEFAULT_TCP_SERVER_LISTEN_PORT 6000
#define EPOLL_SIZE  1024

struct PeerInfo {
    uint8_t         uuid[UUID_SIZE];
    std::string     md5Key;
    std::string     peer_name;

    uint32_t        ip;         // 网络字节序ip
    uint32_t        port;       // 网络字节序port

    uint32_t        udpIP;      // udp网络字节序ip
    uint32_t        udpPort;    // udp网络字节序port
    int             sockFd;

    PeerInfo &operator=(const PeerInfo &info)
    {
        if (&info == this) {
            return *this;
        }

        memmove(this->uuid, info.uuid, UUID_SIZE);
        this->md5Key    = info.md5Key;
        this->peer_name = info.peer_name;
        this->ip        = info.ip;
        this->port      = info.port;
        this->sockFd    = info.sockFd;

        return *this;
    }

    bool operator>(const PeerInfo &info)
    {
        int ret = memcmp(this->uuid, info.uuid, UUID_SIZE);

        return ret > 0;
    }

    bool operator<(const PeerInfo &info)
    {
        int ret = memcmp(this->uuid, info.uuid, UUID_SIZE);
        return ret < 0;
    }
};

struct UUID {
    UUID(const uint8_t *id)
    {
        memcpy(this->uuid, id, UUID_SIZE);
    }
    uint8_t uuid[UUID_SIZE];

    UUID &operator=(const uint8_t *id)
    {
        memcpy(this->uuid, id, UUID_SIZE);
        return *this;
    }

    bool operator>(const UUID &info)
    {
        int ret = memcmp(this->uuid, info.uuid, UUID_SIZE);

        return ret > 0;
    }

    bool operator<(const UUID &info)
    {
        int ret = memcmp(this->uuid, info.uuid, UUID_SIZE);
        return ret < 0;
    }
};


std::unordered_map<int, PeerInfo>       gPeerInfoMap;
std::unordered_map<int, sockaddr_in>    gConnectedPeerAddressMap;

int GenUUID(const eular::String8 &cname, PeerInfo &info)
{
    struct timespec tv;
    if (clock_gettime(CLOCK_MONOTONIC, &tv) != 0) {
        LOGE("clock_gettime error. [%d,%s]", errno, strerror(errno));
        return 0;
    }

    uint64_t ms = tv.tv_sec * 1000 + tv.tv_nsec / 1000 / 1000;
    eular::String8 buf = eular::String8::format("%lu+%s", ms, cname.c_str());
    info.md5Key = buf.toStdString();
    eular::Md5 md5;
    uint8_t *out = info.uuid;
    memset(out, 0, UUID_SIZE);
    md5.encode(out, (const uint8_t *)buf.c_str(), buf.length());
    printf("GenUUID(): ");
    for (int i = 0; i < UUID_SIZE; ++i) {
        printf("0x%02x ", out[i]);
    }
    printf("\n");
    return 1;
}

TcpServer::TcpServer() :
    mEpoll(-1)
{
    mSocket = ::socket(AF_INET, SOCK_STREAM, 0);
    assert(mSocket > 0 && "socket error.");

    sockaddr_in saddr;
    saddr.sin_family = AF_INET;
    saddr.sin_port = htons(DEFAULT_TCP_SERVER_LISTEN_PORT);
    saddr.sin_addr.s_addr = inet_addr("172.25.12.215");

    int flag = 1;
    setsockopt(mSocket, SOL_SOCKET, SO_REUSEADDR, &flag, sizeof(flag));
    int ret = ::bind(mSocket, (sockaddr *)&saddr, sizeof(sockaddr_in));
    if (ret < 0) {
        LOGE("%s() bind error. [%d,%s]\n", __func__, errno, strerror(errno));
        return;
    }
    ret = ::listen(mSocket, 128);
    if (ret < 0) {
        LOGE("%s() listen error. [%d,%s]\n", __func__, errno, strerror(errno));
    }

    LOGD("%d listening.", mSocket);
}

TcpServer::~TcpServer()
{
    if (mSocket > 0) {
        close(mSocket);
        mSocket = -1;
    }

    if (mEpoll > 0) {
        close(mEpoll);
    }
}

int TcpServer::main_loop()
{
    mEpoll = epoll_create(EPOLL_SIZE);
    if (mEpoll < 0) {
        LOGE("epoll_create error. [%d,%s]", errno, strerror(errno));
        return -1;
    }

    epoll_event epolls[EPOLL_SIZE];
    epoll_event event;
    event.data.fd = mSocket;
    event.events = EPOLLET | EPOLLIN;
    epoll_ctl(mEpoll, EPOLL_CTL_ADD, mSocket, &event);

    while (true) {
        int nevs = epoll_wait(mEpoll, epolls, EPOLL_SIZE, -1);
        if (nevs < 0) {
            LOGE("epoll_wait error. [%d,%s]", errno, strerror(errno));
            break;
        }

        for (int i = 0; i < nevs; ++i) {
            const auto &ev = epolls[i];
            if (ev.data.fd == mSocket && ev.events & EPOLLIN) {
                sockaddr_in caddr;
                socklen_t caddr_size = sizeof(sockaddr_in);
                int clientFd = ::accept(mSocket, (sockaddr *)&caddr, &caddr_size);
                if (clientFd <= 0) {
                    LOGE("accept error. [%d,%s]", errno, strerror(errno));
                } else {
                    LOGD("accept success. %d [%s:%d]", clientFd, inet_ntoa(caddr.sin_addr), ntohs(caddr.sin_port));
                    setnonblock(clientFd);
                    event.data.fd = clientFd;
                    event.events = EPOLLET | EPOLLIN;
                    epoll_ctl(mEpoll, EPOLL_CTL_ADD, clientFd, &event);
                    gConnectedPeerAddressMap.insert(std::make_pair(clientFd, caddr));
                }
                continue;
            }

            if (ev.events & EPOLLHUP) {
                LOGI("%s() %d client quit.", __func__, ev.data.fd);
                peer_quit(ev.data.fd);
                continue;
            }

            if (ev.events & EPOLLIN) {
                process_read_event(ev.data.fd);
            }
        }
    }

    return 0;
}

void TcpServer::setnonblock(int fd)
{
    uint32_t flag = fcntl(fd, F_GETFL, 0);
    ::fcntl(fd, F_SETFL, flag | O_NONBLOCK);
}

/**
 * @brief 接收发来的客户端自己的信息
 * 
 * @param cfd 
 * @return int 
 */
int TcpServer::process_read_event(int cfd)
{
    LOGD("%s() fd %d", __func__, cfd);
    uint8_t buf[128] = {0};

    int readSize = ::recv(cfd, buf, sizeof(P2P_Request), 0);
    if (readSize == 0) {
        LOGI("%s() %d client quit.", __func__, cfd);
        peer_quit(cfd);
        return 0;
    }
    if (readSize < 0) {
        if (errno != EAGAIN) {
            LOGE("read error. [%d,%s]", errno, strerror(errno));
            ::send(cfd, "send error", strlen("send error"), 0);
            P2P_Response res;
            res.flag = P2P_FLAG_RESPONSE_GET_PEER_INFO;
            res.statusCode = 404;
            strcpy(res.msg, "recv error");
            ::send(cfd, (char *)&res, sizeof(res), 0);

            return -1;
        }
    }

    if (readSize < sizeof(P2P_Request)) {
        return -1;
    }

    P2P_Request *pinfo = (P2P_Request *)buf;
    LOGD("peer flag: 0x%x", pinfo->flag);
    switch (pinfo->flag) {
    case P2P_FLAG_SEND_PEER_INFO:   // 发送peer信息
        {
            PeerInfo info;
            memset(&info, 0, sizeof(info));
            int ret = GenUUID(pinfo->peer_info.peer_name, info);
            const auto &it = gConnectedPeerAddressMap.find(cfd);
            LOG_ASSERT(it != gConnectedPeerAddressMap.end(), "cannot be null");

            info.ip = it->second.sin_addr.s_addr;
            info.port = it->second.sin_port;
            info.peer_name = pinfo->peer_info.peer_name;
            info.sockFd = cfd;

            P2P_Response res;
            if (ret) {
                res.flag = P2P_FLAG_RESPONSE_SEND_PEER_INFO;
                res.statusCode = 200;
                memcpy(res.conn.uuid, info.uuid, UUID_SIZE);
                strcpy(res.msg, "OK");
            } else {
                res.flag = P2P_FLAG_RESPONSE_SEND_PEER_INFO;
                res.statusCode = 502;
                strcpy(res.msg, "Server Error");
            }
            if (::send(cfd, (char *)&res, sizeof(res), 0) < 0) {
                LOGE("send error. [%d,%s]", errno, strerror(errno));
            }

            LOGD("send to peer over. waiting for recvfrom");
            sockaddr_in peerAddr;
            memset(&peerAddr, 0, sizeof(peerAddr));
            socklen_t len = sizeof(sockaddr_in);
            uint8_t peer_uuid[UUID_SIZE] = {0};
            ret = mUdpSrv.recvfrom(peer_uuid, UUID_SIZE, &peerAddr, &len);
            if (ret < 0) {
                LOGE("recvfrom error. [%d,%s]", errno, strerror(errno));
            }
            if (ret == UUID_SIZE && memcmp(info.uuid, peer_uuid, UUID_SIZE) == 0) {
                LOGD("P2P_FLAG_SEND_PEER_INFO recv peer send uuid. tcp --- %d:%d udp --------- [(%d)%s:%d]",
                    info.ip, info.port, peerAddr.sin_addr.s_addr, 
                    inet_ntoa(peerAddr.sin_addr), ntohs(peerAddr.sin_port));
                info.udpIP = peerAddr.sin_addr.s_addr;
                info.udpPort = peerAddr.sin_port;
            }
            gPeerInfoMap.insert(std::make_pair(cfd, info));
        }
        break;
    case P2P_FLAG_GET_PEER_INFO:    // 获取所有peer信息
        {
            P2P_Response response;
            response.flag = P2P_FLAG_RESPONSE_GET_PEER_INFO;
            response.statusCode = 200;
            strcpy(response.msg, "OK");
            response.number = gPeerInfoMap.size() - 1;
            ::send(cfd, &response, sizeof(P2P_Response), 0);

            Peer_Info pinfo;
            for (const auto &it : gPeerInfoMap) {
                if (it.second.sockFd == cfd) {
                    continue;
                }

                pinfo.host_binary = it.second.ip;
                pinfo.port_binary = it.second.port;
                LOGD("*************[%s:%d]*************", inet_ntoa({it.second.ip}), ntohs(it.second.port));
                strncpy(pinfo.peer_name, it.second.peer_name.c_str(), sizeof(pinfo.peer_name));
                memcpy(pinfo.peer_uuid, it.second.uuid, UUID_SIZE);

                int sendSize = ::send(cfd, &pinfo, sizeof(Peer_Info), 0);
                LOGD("P2P_FLAG_GET_PEER_INFO send to %d, send size %d", cfd, sendSize);
                memset(&pinfo, 0, sizeof(Peer_Info));
            }
        }
        break;
    case P2P_FLAG_CONNECT_TO_PEER:  // 连接对端
        {
            uint8_t peer_uuid[UUID_SIZE] = {0};
            memcpy(peer_uuid, pinfo->peer_info.peer_uuid, UUID_SIZE);
            P2P_Response res;

            int peerFd = 0;
            for (auto it : gPeerInfoMap) {
                if (memcmp(peer_uuid, it.second.uuid, UUID_SIZE) == 0) {
                    peerFd = it.second.sockFd;
                    break;
                }
            }

            if (peerFd == 0) {
                res.flag = P2P_FLAG_RESPONSE_CONNECT_TO_PEER;
                res.statusCode = 301;
                strncpy(res.msg, "Please Refresh", sizeof(res.msg));
                ::send(cfd, &res, sizeof(res), 0);
                return 0;
            }

            const auto &connectingPeerInfo = gPeerInfoMap.find(cfd);
            const auto &peerIt = gPeerInfoMap.find(peerFd);
            LOGD("%s[%d] want to connect to %s[%d]", connectingPeerInfo->second.peer_name.c_str(), cfd,
                    peerIt->second.peer_name.c_str(), peerFd);

            uint8_t uuid[UUID_SIZE];
            sockaddr_in addr;
            memset(&addr, 0, sizeof(addr));
            socklen_t len = sizeof(sockaddr_in);
            int recvLen = mUdpSrv.recvfrom(uuid, sizeof(uuid), &addr, &len);

            LOGI("recvLen = %d [%s:%d]", recvLen, inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));
            if (memcmp(uuid, peer_uuid, UUID_SIZE) == 0) {
                LOGI("uuid一致");
            } else {
                LOGI("uuid 不一致");
            }

            P2P_Connect conn;
            conn.host_binary = addr.sin_addr.s_addr;
            conn.port_binary = addr.sin_port;
            memcpy(conn.peer_name, connectingPeerInfo->second.peer_name.c_str(), sizeof(conn.peer_name));
            memcpy(conn.uuid, connectingPeerInfo->second.uuid, UUID_SIZE);

            res.flag = P2P_FLAG_RESPONSE_CONNECT_TO_ME;
            res.statusCode = 200;
            res.conn = conn;

            ::send(peerFd, &res, sizeof(P2P_Response), 0);
        }
        break;
    default:
        break;
    }

    LOGI("%s() end", __func__);
    return 0;
}

int TcpServer::peer_quit(int fd)
{
    epoll_ctl(mEpoll, EPOLL_CTL_DEL, fd, nullptr);
    gConnectedPeerAddressMap.erase(fd);
    auto it = gPeerInfoMap.find(fd);
    LOG_ASSERT(it != gPeerInfoMap.end(), "");

    return gPeerInfoMap.erase(fd);
}