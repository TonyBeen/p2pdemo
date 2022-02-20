/*************************************************************************
    > File Name: client.h
    > Author: hsz
    > Brief:
    > Created Time: Sat 12 Feb 2022 07:24:19 PM CST
 ************************************************************************/

#ifndef __P2P_CLIENT_H__
#define __P2P_CLIENT_H__

#include "protocol.h"
#include <stdio.h>
#include <stdint.h>
#include <sys/uio.h>

#define DEFAULT_SERVER_PORT 6000
#define DEFAULT_SERVER_IP   "39.106.218.123"
#define PEER_NAME           "eular"

class P2PClient
{
public:
    P2PClient();
    ~P2PClient();

    bool connect();

    int send(const void *buf, int buflen);
    int recv(void *buf, int buflen, int flag = 0);

    int mSocket;
};


#endif // __P2P_CLIENT_H__
