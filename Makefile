all:
	g++ *.cpp tasks/*.cpp -o task -lbcc -lpthread
run: all
	sudo ./task