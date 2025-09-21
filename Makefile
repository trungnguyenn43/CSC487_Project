Sequence: SDES.o Server Client Test

Server: Server.o 
	g++ -o Server  Server.o SDES.o

Server.o: Server.c 
	g++ -c -g -std=c++11 Server.c

Client: Client.o
	g++ -o Client  Client.o 

Client.o: Client.c
	g++ -c -g -std=c++11 Client.c	

SDES.o: SDES.c SDES.h
	g++ -c -g -std=c++11 SDES.h SDES.c 

Test: Test.o SDES.o
	g++ -o Test Test.o SDES.o

Test.o: Test.c SDES.h
	g++ -c -g -std=c++11 Test.c

clean:
	rm -f Server Client *.o
