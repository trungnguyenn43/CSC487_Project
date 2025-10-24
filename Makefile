
Driver: Driver.o UtilFunction.o DiffHellman.o
	g++ -o Driver Driver.o UtilFunction.o DiffHellman.o

Driver.o: Driver.c
	g++ -c -g -std=c++11 Driver.c

UtilFunction.o: UtilFunction.c UtilFunction.h
	g++ -c -g -std=c++11 UtilFunction.c UtilFunction.h

CBCHash: CBCHash.o SDES.o
	g++ -o CBCHash CBCHash.o SDES.o

CBCHash.o: CBCHash.c
	g++ -c -g -std=c++11 CBCHash.c

Server: Server.o SDES.o SDES.o DiffHellman.o
	g++ -o Server Server.o SDES.o DiffHellman.o

Server.o: Server.c 
	g++ -c -g -std=c++11 Server.c

Client: Client.o DiffHellman.o SDES.o 
	g++ -o Client Client.o DiffHellman.o SDES.o

Client.o: Client.c
	g++ -c -g -std=c++11 Client.c	

DiffHellman.o: DiffHellman.c DiffHellman.h
	g++ -c -g -std=c++11 DiffHellman.c DiffHellman.h

SDES.o: SDES.c SDES.h
	g++ -c -g -std=c++11 SDES.h SDES.c 

clean:
	rm -f Server Client *.o
