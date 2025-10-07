
bmper: bmper.o
	g++ -o bmper bmper.o SDES.o

bmper.o: SDES.o bmper.c 
	g++ -c -g -std=c++11 bmper.c

Server: Server.o SDES.o SDES.o DiffHellman.o
	g++ -o Server Server.o SDES.o DiffHellman.o

Server.o: Server.c 
	g++ -c -g -std=c++11 Server.c

Client: DiffHellman.o Client.o SDES.o DiffHellman.o
	g++ -o Client Client.o DiffHellman.o

Client.o: Client.c
	g++ -c -g -std=c++11 Client.c	

DiffHellman.o: DiffHellman.c DiffHellman.h
	g++ -c -g -std=c++11 DiffHellman.c DiffHellman.h

SDES.o: SDES.c SDES.h
	g++ -c -g -std=c++11 SDES.h SDES.c 

clean:
	rm -f Server Client *.o
