
Driver: Driver.o UtilFunction.o DiffHellman.o SDES.o
	g++ -o Driver Driver.o UtilFunction.o DiffHellman.o SDES.o

Driver.o: Driver.c
	g++ -c -g -std=c++11 Driver.c

CBCHash: CBCHash.o UtilFunction.o SDES.o
	g++ -o CBCHash CBCHash.o UtilFunction.o SDES.o

CBCHash.o: CBCHash.c 
	g++ -c -g -std=c++11 CBCHash.c

Server: Server.o SDES.o SDES.o DiffHellman.o UtilFunction.o
	g++ -o Server Server.o SDES.o DiffHellman.o UtilFunction.o

Server.o: Server.c 
	g++ -c -g -std=c++11 Server.c

Client: Client.o DiffHellman.o SDES.o UtilFunction.o
	g++ -o Client Client.o DiffHellman.o SDES.o UtilFunction.o

Client.o: Client.c
	g++ -c -g -std=c++11 Client.c	

UtilFunction.o: UtilFunction.c UtilFunction.h 
	g++ -c -g -std=c++11 UtilFunction.c UtilFunction.h 

DiffHellman.o: DiffHellman.c DiffHellman.h
	g++ -c -g -std=c++11 DiffHellman.c DiffHellman.h

SDES.o: SDES.c SDES.h
	g++ -c -g -std=c++11 SDES.h SDES.c 

clean:
	rm -f Server Client *.o
