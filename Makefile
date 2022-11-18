all:
	g++ *.cpp tasks/*.cpp -o task -lbcc -lpthread -llog4cplus
run: all
	./task
format:
	clang-format --style=file -i *.cpp *.h */*.cpp */*.h
