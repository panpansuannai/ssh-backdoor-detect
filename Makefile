all:
	g++ *.cpp tasks/*.cpp -o task -lbcc -lpthread -lspdlog
run: all
	sudo ./task