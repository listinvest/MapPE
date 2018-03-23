build: 
	i686-w64-mingw32-g++-win32 -static-libgcc -static-libstdc++ MapPE.cpp -o MapPE.exe
	go build -ldflags "-s -w" -o mappe MapPE.go
