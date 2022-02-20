/*************************************************************************
    > File Name: udp.h
    > Author: hsz
    > Brief:
    > Created Time: Tue 15 Feb 2022 09:36:18 AM CST
 ************************************************************************/

#ifndef __P2P_UDP_H__
#define __P2P_UDP_H__

#include "protocol.h"
#include <stdint.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <unistd.h>

#define DEFAULT_P2P_UDP_PORT 6100

class UdpServer
{
public:
    UdpServer();
    ~UdpServer();

    int build();
    int recvfrom(void *buf, size_t bufLen, sockaddr_in *addr, socklen_t *addrLen);
    int sendto(const void *buf, size_t bufLen, sockaddr_in *addr, socklen_t addrLen);

private:
    int mSocketUdp;
};


#endif // __P2P_UDP_H__
