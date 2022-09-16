# TCP Sniffer
## Task description
Implement a simple C application which analyzes traffic on a given network interface and reports to stdout all successful and failed connections.
Use libpcap to sniff traffic.

## Must have dependencies
1. `gcc` compiler that supports `-std=gnu11` flag. 
`gcc (Ubuntu 9.4.0-1ubuntu1~20.04.1) 9.4.0` was used while developing
2. `libpcap`
3. `cmake 3.16.3` or higher
4. `Ubuntu`. This project was developed and tested on the WSL v2 Ubuntu-20.04  

## Optional dependencies to build unit tests
Unit test target is optional and might be skipped if libcheck is not found on your system
1. `libm`
2. `libpthread`
3. `librt`
4. `libsubunit`
5. `valgrind` (if found on system, a separate ctest target is to be created to run the test program under valgrind with memchecks enabled)

## How to build and run project
1. Clone the master brach locally
2. Configure project via cmake.
In this example a Debug configuration build is to be built in the build folder.
Cmake would create folder if it doesn't exist
```
cmake --config Debug -S . -B build
```
3. Build project
```
cmake --build build
```
4. Start tcp_sniffer
```
sudo ./build/tcp_sniffer eth0
```

## Example output:
![image](https://user-images.githubusercontent.com/22596843/190789158-299d5300-da6e-4035-ab1d-12bfad45fee5.png)
