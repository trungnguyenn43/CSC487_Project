
output: Main.o
	g++ -o output Main.o

Main.o: Main.c
	g++ -c -g -std=c++11 Main.c

SDES.o: SDES.c
	g++ -c -g -std=c++11 SDES.c

clean:
	rm -f output Main.o