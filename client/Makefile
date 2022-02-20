# g++ server.cpp main.cpp -o p2pServer -leularcrypto -lutils -llog -Wall -I..
CC = g++

CPPFLAG = -std=c++11 -Wall

SRC_LIST := \
	client.cpp 	\
	main.cpp	\

OBJ_LIST := \
	client.o 	\
	main.o		\

LIB = -lutils -llog -leularcrypto -lpthread

INCLUDE =  -I. -I..

default : p2pclient

p2pclient : $(OBJ_LIST)
	$(CC) $^ -o $@ $(LIB)
	rm -rf $(OBJ_LIST)

%.o : %.cpp
	$(CC) -c $^ -o $@ $(INCLUDE) $(CPPFLAG)

.PHONY : \
	clean default p2pclient

clean:
	rm -rf $(OBJ_LIST)