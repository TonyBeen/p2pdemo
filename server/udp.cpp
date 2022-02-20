/*************************************************************************
    > File Name: udp.cpp
    > Author: hsz
    > Brief:
    > Created Time: Tue 15 Feb 2022 09:36:24 AM CST
 ************************************************************************/

#include "udp.h"
#include <assert.h>
#include <sys/time.h>
#include <utils/exception.h>

#define DEFAULT_LOCAL_IP "172.25.12.215"

UdpServer::UdpServer() :
    mSocketUdp(-1)
{
    assert(build() == 0);
    if (mSocketUdp > 0) {
        int reUse = 1;
        int ret = setsockopt(mSocketUdp, SOL_SOCKET, SO_REUSEADDR, &reUse, sizeof(reUse));
        struct timeval tv_out;
        tv_out.tv_sec = 2;
        tv_out.tv_usec = 0;
        ret = setsockopt(mSocketUdp, SOL_SOCKET, SO_SNDTIMEO, &tv_out, sizeof(tv_out));
        ret = setsockopt(mSocketUdp, SOL_SOCKET, SO_RCVTIMEO, &tv_out, sizeof(tv_out));
    }
}

UdpServer::~UdpServer()
{
    if (mSocketUdp > 0) {
        close(mSocketUdp);
        mSocketUdp = -1;
    }
}

int UdpServer::build()
{
    mSocketUdp = ::socket(AF_INET, SOCK_DGRAM, 0);
    if (mSocketUdp < 0) {
        throw eular::Exception("socket error");
    }

    sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr(DEFAULT_LOCAL_IP);
    addr.sin_port = htons(DEFAULT_P2P_UDP_PORT);

    int code = ::bind(mSocketUdp, (sockaddr *)&addr, sizeof(addr));
    return code;
}

int UdpServer::recvfrom(void *buf, size_t bufLen, sockaddr_in *addr, socklen_t *addrLen)
{
    if (mSocketUdp < 0) {
        return -1;
    }

    return ::recvfrom(mSocketUdp, buf, bufLen, 0, (sockaddr *)addr, addrLen);
}

int UdpServer::sendto(const void *buf, size_t bufLen, sockaddr_in *addr, socklen_t addrLen)
{
    if (mSocketUdp < 0) {
        return -1;
    }

    return ::sendto(mSocketUdp, buf, bufLen, 0, (sockaddr *)addr, addrLen);
}
