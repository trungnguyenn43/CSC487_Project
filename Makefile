Sequence: Server Client

Server: Server.o 
	g++ -o Server  Server.o 

Server.o: Server.c
	g++ -c -g -std=c++11 Server.c

Client: Client.o
	g++ -o Client  Client.o 

Client.o: Client.c
	g++ -c -g -std=c++11 Client.c	

SDES: SDES.o
	g++ -o SDES SDES.c

SDES.o: SDES.c
	g++ -c -g -std=c++11 SDES.c

clean:
	rm -f Server Client *.o
