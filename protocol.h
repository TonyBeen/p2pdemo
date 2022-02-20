/*************************************************************************
    > File Name: protocol.h
    > Author: hsz
    > Brief:
    > Created Time: Wed 09 Feb 2022 10:13:39 PM CST
 ************************************************************************/

#ifndef __P2P_PROTOCOL_H__
#define __P2P_PROTOCOL_H__

// #pragma pack(1)

#include <stdio.h>
#include <stdint.h>
#include <string>

#define __attribute_packed__        __attribute__((packed))

#define UUID_SIZE 16
#define PEER_NAME_SIZE 32

#define P2P_FLAG_SEND_PEER_INFO     0x10        // 发送本机信息
#define P2P_FLAG_GET_PEER_INFO      0x20        // 获取所有客户端信息
#define P2P_FLAG_CONNECT_TO_PEER    0x30        // 请求连接某一客户端

#define P2P_RESPONSE                0x1000
#define P2P_FLAG_RESPONSE_SEND_PEER_INFO    (P2P_RESPONSE + 1)      // 服务端响应客户端发送的信息
#define P2P_FLAG_RESPONSE_GET_PEER_INFO     (P2P_RESPONSE + 2)      // 服务端响应获取客户端信息
#define P2P_FLAG_RESPONSE_CONNECT_TO_PEER   (P2P_RESPONSE + 3)      // 服务端响应客户端请求连接
#define P2P_FLAG_RESPONSE_CONNECT_TO_ME     (P2P_RESPONSE + 4)      // 服务器响应对端有人要建立连接

// 服务端响应获取客户端结构体
typedef struct __Peer_Info {
    uint32_t        host_binary;                // 网络字节序二进制IP
    uint16_t        port_binary;                // 网络字节序端口号
    uint8_t         peer_uuid[UUID_SIZE];       // 对端在服务器中的ID
    char            peer_name[PEER_NAME_SIZE];  // 根据flag确定是对端名字还是本机名字
} __attribute__((packed)) Peer_Info;
static const size_t Peer_Info_Size = sizeof(Peer_Info);

// 服务端通知对端建立连接结构体
typedef struct __P2P_Connect {
    uint8_t     uuid[UUID_SIZE];
    uint32_t    host_binary;
    uint16_t    port_binary;
    char        peer_name[PEER_NAME_SIZE];
} __attribute__((packed)) P2P_Connect;
static const size_t P2P_Connect_Size = sizeof(P2P_Connect);

// 发送给服务端结构体
typedef struct __P2P_Request {
    uint16_t    flag;           // 请求种类
    Peer_Info   peer_info;
} __attribute__((packed)) P2P_Request;
static const size_t P2P_Request_Size = sizeof(P2P_Request);

// 服务端响应结构体
typedef struct __P2P_Response {
    uint16_t    flag;
    uint16_t    statusCode;
    char        msg[64];
    int32_t     number;     // 后面有多少个Peer_Info
    P2P_Connect conn;
} __attribute__((packed)) P2P_Response;
static const size_t P2P_Response_Size = sizeof(P2P_Response);

// 客户端与客户端结构体
typedef struct __P2P_Peer_2_Peer {

} __attribute__((packed)) P2P_Peer_2_Peer;

#endif // __P2P_PROTOCOL_H__
