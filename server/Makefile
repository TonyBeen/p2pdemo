# g++ server.cpp main.cpp -o p2pServer -leularcrypto -lutils -llog -Wall -I..
CC = g++

CPPFLAG = -std=c++11 -Wall

SRC_LIST := \
	udp.cpp		\
	server.cpp 	\
	main.cpp	\

OBJ_LIST := \
	udp.o		\
	server.o 	\
	main.o		\

LIB = -lutils -llog -leularcrypto

INCLUDE =  -I. -I..

default : p2pServer 

p2pServer : $(OBJ_LIST)
	$(CC) $^ -o $@ $(LIB)
	rm -rf $(OBJ_LIST)

%.o : %.cpp
	$(CC) -c $^ -o $@ $(INCLUDE) $(CPPFLAG)

.PHONY : \
	clean default p2pServer

clean:
	rm -rf $(OBJ_LIST)