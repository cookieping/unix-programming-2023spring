CXX		= g++
CFLAGS	= -shared -fPIC -ldl -std=c++17

sandbox:
	chmod +x launcher
	rm -f sandbox.so index.html* elfResult.txt
	rm -rf logFiles
	mkdir logFiles
	$(CXX) -o sandbox.so $(CFLAGS) sandbox.cpp

clean:
	rm -f sandbox.so elfResult.txt index.html*
	rm -rf logFiles