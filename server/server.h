/*************************************************************************
    > File Name: server.h
    > Author: hsz
    > Brief:
    > Created Time: Wed 09 Feb 2022 10:12:22 PM CST
 ************************************************************************/

#ifndef __P2P_SERVER_H__
#define __P2P_SERVER_H__

#include "protocol.h"
#include "udp.h"
#include <string.h>
#include <errno.h>
#include <error.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <unistd.h>

class TcpServer {
public:
    TcpServer();
    ~TcpServer();

    int main_loop();
    void setnonblock(int fd);

protected:
    int process_read_event(int cfd);
    int peer_quit(int fd);

private:
    int     mSocket;
    int     mEpoll;
    UdpServer   mUdpSrv;
};


#endif // __P2P_SERVER_H__