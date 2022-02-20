/*************************************************************************
    > File Name: main.cpp
    > Author: hsz
    > Brief:
    > Created Time: Wed 09 Feb 2022 10:12:33 PM CST
 ************************************************************************/

#include <iostream>
#include "server.h"
using namespace std;

int main(int argc, char **argv)
{
    TcpServer tcp;
    
    return tcp.main_loop();
}
