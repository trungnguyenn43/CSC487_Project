
Driver: Driver.o UtilFunction.o DiffHellman.o SDES.o Certs.o
	g++ -o Driver Driver.o UtilFunction.o DiffHellman.o SDES.o Certs.o

Server: Server.o SDES.o SDES.o DiffHellman.o UtilFunction.o Certs.o
	g++ -o Server Server.o SDES.o DiffHellman.o UtilFunction.o Certs.o

Client: Client.o DiffHellman.o SDES.o UtilFunction.o Certs.o
	g++ -o Client Client.o DiffHellman.o SDES.o UtilFunction.o Certs.o

Server.o: Server.c
	g++ -c -g -std=c++11 Server.c

Client.o: Client.c
	g++ -c -g -std=c++11 Client.c

Driver.o: Driver.c
	g++ -c -g -std=c++11 Driver.c

Certs.o: Certs.h Certs.c 
	g++ -c -g -std=c++11 Certs.h Certs.c 

UtilFunction.o: UtilFunction.c UtilFunction.h 
	g++ -c -g -std=c++11 UtilFunction.c UtilFunction.h

DiffHellman.o: DiffHellman.c DiffHellman.h
	g++ -c -g -std=c++11 DiffHellman.c DiffHellman.h

SDES.o: SDES.c SDES.h
	g++ -c -g -std=c++11 SDES.h SDES.c 

clean:
	rm -f Server Client *.o *h.gch
