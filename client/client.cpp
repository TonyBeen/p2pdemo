/*************************************************************************
    > File Name: client.cpp
    > Author: hsz
    > Brief:
    > Created Time: Sat 12 Feb 2022 07:24:23 PM CST
 ************************************************************************/

#include "client.h"
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <utils/exception.h>
#include <log/log.h>

#define LOG_TAG "P2P_Client"

#define INVALID_SOCKET (-1)

P2PClient::P2PClient() :
    mSocket(INVALID_SOCKET)
{
    mSocket = ::socket(AF_INET, SOCK_STREAM, 0);
    if (mSocket < 0) {
        throw eular::Exception("socket error");
    }

    LOGD("socket handle %d\n", mSocket);
}

P2PClient::~P2PClient()
{
    if (mSocket != INVALID_SOCKET) {
        close(mSocket);
        mSocket = INVALID_SOCKET;
    }
}

bool P2PClient::connect()
{
    sockaddr_in saddr;
    memset(&saddr, 0, sizeof(sockaddr_in));
    saddr.sin_family = AF_INET;
    saddr.sin_addr.s_addr = inet_addr(DEFAULT_SERVER_IP);
    saddr.sin_port = htons(DEFAULT_SERVER_PORT);

    int ret = ::connect(mSocket, (sockaddr *)&saddr, sizeof(saddr));
    if (ret < 0) {
        LOGE("connect error. [%d,%s]", errno, strerror(errno));
        return false;
    }

    int flag = 1;
    setsockopt(mSocket, SOL_SOCKET, SO_REUSEADDR, &flag, sizeof(flag));
    struct timeval tv_out;
    tv_out.tv_sec = 2;
    tv_out.tv_usec = 0;
    setsockopt(mSocket, SOL_SOCKET, SO_RCVTIMEO, &tv_out, sizeof(tv_out));
    setsockopt(mSocket, SOL_SOCKET, SO_SNDTIMEO, &tv_out, sizeof(tv_out));

    LOGI("connect to %s:%d success", DEFAULT_SERVER_IP, DEFAULT_SERVER_PORT);
    return true;
}


int P2PClient::send(const void *buf, int buflen)
{
    if (mSocket == INVALID_SOCKET) {
        LOGE("invalid socket");
        return -1;
    }

    int ret = ::send(mSocket, buf, buflen, 0);
    if (ret < 0) {
        LOGE("send error. [%d,%s]", errno, strerror(errno));
    }

    return ret;
}

int P2PClient::recv(void *buf, int buflen, int flag)
{
    if (mSocket == INVALID_SOCKET) {
        LOGE("invalid socket");
        return -1;
    }

    int ret = ::recv(mSocket, buf, buflen, flag);
    return ret;
}