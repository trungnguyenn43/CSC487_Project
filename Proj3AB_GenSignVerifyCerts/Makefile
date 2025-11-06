
Driver: Driver.o UtilFunction.o DiffHellman.o SDES.o Certs.o
	g++ -o Driver Driver.o UtilFunction.o DiffHellman.o SDES.o Certs.o

Driver.o: Driver.c
	g++ -c -g -std=c++11 Driver.c

Certs.o: Certs.c Certs.h 
	g++ -c -g -std=c++11 Certs.c Certs.h

UtilFunction.o: UtilFunction.c UtilFunction.h 
	g++ -c -g -std=c++11 UtilFunction.c UtilFunction.h

DiffHellman.o: DiffHellman.c DiffHellman.h
	g++ -c -g -std=c++11 DiffHellman.c DiffHellman.h

SDES.o: SDES.c SDES.h
	g++ -c -g -std=c++11 SDES.h SDES.c 

clean:
	rm -f Server Client *.o
