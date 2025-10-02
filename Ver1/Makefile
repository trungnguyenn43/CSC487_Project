driver: DriverFile

DriverFile: Driver.o SDES.o
	g++ -o Driver Driver.o SDES.o

Driver.o: Driver.c
	g++ -c -g -std=c++11 Driver.c

Server: Server.o SDES.o
	g++ -o Server Server.o SDES.o

Server.o: Server.c 
	g++ -c -g -std=c++11 Server.c

Client: Client.o
	g++ -o Client Client.o 

Client.o: Client.c
	g++ -c -g -std=c++11 Client.c	


SDES.o: SDES.c SDES.h
	g++ -c -g -std=c++11 SDES.h SDES.c 

clean:
	rm -f Driver Server Client *.o
