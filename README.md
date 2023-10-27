[![License: New BSD](https://img.shields.io/github/license/larthia/nethuns?color=blue&label=License)](https://opensource.org/licenses/BSD-3-Clause)
[![Release](https://img.shields.io/github/v/tag/larthia/nethuns?color=blue&label=Release)](https://github.com/larthia/nethuns/releases/latest)
[![Hits](https://hits.seeyoufarm.com/api/count/incr/badge.svg?url=https%3A%2F%2Fgithub.com%2Flarthia%2Fnethuns&count_bg=%2379C83D&title_bg=%23555555&icon=&icon_color=%23E7E7E7&title=Hits&edge_flat=false)](https://hits.seeyoufarm.com)
[![Contributors](https://img.shields.io/github/contributors/larthia/nethuns?color=green&label=Contributors)](https://github.com/larthia/nethuns/graphs/contributors)
[![Commits since v0.1](https://img.shields.io/github/commits-since/larthia/nethuns/v0.1/master?color=green&label=Commits%20since%20v0.1)](https://github.com/larthia/nethuns/commits/master)
[![Last commit](https://img.shields.io/github/last-commit/larthia/nethuns?label=Last%20commit)](https://github.com/larthia/nethuns/commits/master)

# Nethuns: a unified API for fast and portable network programming

# Introduction

Nethuns is a software library written in C that provides a unified API to access and manage low-level network operations over different underlying network I/O frameworks, and consequently operating systems. The design of Nethuns originates from the practical requirement of developing portable network applications with extremely high data rate target. Instead of re-writing the applications to match the underlying network I/O engines available over the different operating systems, Nethuns offers a unified abstraction layer that allows programmers to implement their applications regardless of the underlying technology. Therefore, network applications that use the Nethuns library only need to be re-compiled to run on top of a different engine (chosen in the set of the ones available for the OS), with no need for code adaptation.

Nethuns would like to fill the lack of a *unified network abstraction* in the software domain, which is instead present in the hardware domain thanks to [P4](https://p4.org/). Nethuns should play a similar role to that entrusted to the [pcap](https://www.tcpdump.org/) library in the past. In addition, it adds support for recent technologies such as [AF_XDP](https://www.kernel.org/doc/Documentation/networking/af_xdp.rst) and concurrency. Of course, all of this is provided to network programmers while minimizing the overhead, in order not to impact the performance of native underlying network I/O frameworks. The API exposed by Nethuns recalls the interface of UNIX sockets to make immediate and simple its adoption to experienced network programmers.

Nethuns fully supports:

* AF_PACKET and [AF_XDP](https://www.kernel.org/doc/Documentation/networking/af_xdp.rst) sockets for fast packet handling over Linux
* the [netmap](https://github.com/luigirizzo/netmap) framework for fast packet I/O over Linux and FreeBSD
* the [pcap](https://www.tcpdump.org/) library for use in BSD, MacOS and Windows operating systems


# Nethuns basic API

Create a new socket using the options in `opt`
```
sock = nethuns_open(opt)
```
Bind the socket to a specific queue/any queue of `dev`
```
nethuns_bind(sock, dev, queue)
```
Get the next unprocessed received packet
```
pktid = nethuns_recv(sock, &pkthdr, &pkt)
```
Return a buffer previously obtained from `nethuns_recv()`
```
nethuns_release(sock, pktid)
```
Queue up `pkt` for transmission
```
nethuns_send(sock, pkt, size)
```
Send all queued up packets
```
nethuns_flush(sock)
```
Unbind the device and destroy the socket
```
nethuns_close(sock)
```


# Dependencies

The Nethuns library relies on the following dependencies:

* **a C compiler**
* **a C++ compiler** with support to C++17 (for tests compilation)
* **libpcap** library ([https://github.com/the-tcpdump-group/libpcap](https://github.com/the-tcpdump-group/libpcap))
* **libbpf** library, needed to enable AF_XDP support ([https://github.com/libbpf/libbpf](https://github.com/libbpf/libbpf))
* **netmap** library, needed to enable netmap support ([https://github.com/luigirizzo/netmap](https://github.com/luigirizzo/netmap))

<!--libelf dependency (on clearlinux: swupd bundle-add devpkg-elfutils)-->


# Building the library

The Nethuns library has to be built against any of the available underlying engines before you can use it. Assuming to be on a Linux distribution, the build process can be done by executing the following steps from inside the main directory of the project:
```
mkdir build && cd build
ccmake ..
```
At this point, a configuration menu should appear to the user, which can select one or more network I/O frameworks to build among those available, as well as set up some other building options (see an example below).
```
CMAKE_BUILD_TYPE                 Release
CMAKE_INSTALL_PREFIX             /usr/local
LIBPCAP_INCLUDE_DIR              /usr/include
LIBPCAP_LIBRARY                  /usr/lib/x86_64-linux-gnu/libpcap.a
NETHUNS_OPT_BUILTIN_PCAP_READER  OFF
NETHUNS_OPT_LIBPCAP              ON
NETHUNS_OPT_NETMAP               ON
NETHUNS_OPT_TPACKET_V3           OFF
NETHUNS_OPT_XDP                  ON
```

Press `c` to process the configuration files with the current options, `enter` to set the value of a given option, `g` to generate the build files and exit, `q` to quit `ccmake` without generating build files. Once the build files have been generated with the correct options, the library can be finally built and installed (the default path is `/usr/local`) by issuing the commands:
```
cmake .
make -j<#cores>
sudo make install
```

# Using Nethuns as a Submodule in CMake Projects

You can utilize the Nethuns library without the need for system-wide installation by configuring it as a submodule within your CMake project. 
To achieve this, you should include the following CMake commands in your project:

```cmake
add_subdirectory(libs/Nethuns)

set(USE_LOCAL_NETHUNS on)
include(${CMAKE_BINARY_DIR}/libs/Nethuns/Nethuns.cmake)

include_directories(${NETHUNS_INCLUDE_DIRS})
target_link_libraries(your_binary ${NETHUNS_LIBRARY_DIRS})
```

- The first command ensures that Nethuns is built alongside your project. You will need to select the desired sockets to enable during compilation and which ones your application will effectively use.
- Setting the variable `USE_LOCAL_NETHUNS` to "on" instructs the Nethuns.cmake script to use the locally built version instead of the system-installed one.
- The `include()` directive, which typically points to `/usr/local/share/nethuns/Nethuns.cmake`, should now be directed to the locally generated version during your project's configuration.

- The last two directives are the same ones you would use even if you were to utilize the system-installed version, as they contain all the necessary paths for including the headers and linking the libraries.

# Building the examples

A whole suite of tests can be found under the `/test` directory in this repository. These examples can be used as a starting point to understand how to use the Nethuns API. To develop a new application that uses Nethuns operations, you need to include the header file `nethuns/nethuns.h`.

To build the tests, you first need to select the engine you actually intend to use among the ones built with the library. After the configuration has been generated, you can use `cmake` as done in the previous steps to compile the library. This translates in executing the following steps from inside the main directory of the project:
```
cd test
ccmake .
cmake .
make -j<#cores>
```

## Testing packet transmission

To test packet transmission you can use the user-space application called `nethuns-send` ([source code](https://github.com/larthia/nethuns/blob/master/test/src/send.cpp)). The application can be run with the following options:
```
Usage:  nethuns-send [ options ]
Use --help (or -h) to see full option list and a complete description.

Required options: 
            [ -i <ifname> ]      set network interface 
Other options: 
            [ -b <batch_sz> ]    set batch size 
            [ -n <nsock> ]       set number of sockets 
            [ -m ]               enable multithreading 
            [ -z ]               enable send zero-copy 
```
The default batch size for packet transmission is 1 (no batching). The number of sockets to use can be specified, and by default is 1. If multithreading is enabled, and there is more than one socket in use, each socket is handled by a separated thread. Moreover, zero-copy mode can be enabled; by default, the classic send that requires a copy is used.

To test this application, we can use two server machines PC1 and PC2: PC1 generates traffic at the highest possible rate by running the `nethuns-send` application, and PC2 is used as a traffic receiver running the [`pkt-gen`](https://github.com/luigirizzo/netmap/tree/master/apps/pkt-gen) Netmap application in receiver mode.

This is an example of how to run some tests; notice that, `ix0` must be replaced with the name of the interface, and also other options can be used.

In this case, the transmission is set up to use batch size of 64 packets, and the zero copy option is enabled.
```
PC1:~/nethuns/test$ ./nethuns-send -i ix0 -b 64 -z
```
`pkt-gen` is used here in its simplest form, to receive packets and print statistics.
```
PC2$ pkt-gen -i ix0 -f rx
```

## Testing packet capture

To test packet capture you can use the user-space application called `nethuns-meter`([source code](https://github.com/larthia/nethuns/blob/master/test/src/meter.cpp)). The application can be run with the following options:
```
Usage:  nethuns-meter [ options ]
Use --help (or -h) to see full option list and a complete description.

Required options: 
            [ -i <ifname> ]      set network interface 
Other options: 
            [ -n <nsock> ]       set number of sockets 
            [ -m ]               enable multithreading 
            [ -s <sockid> ]      enable per socket stats 
            [ -d ]               enable extra debug printing 
```
The number of sockets to use can be specified (by default, it is 1). If multithreading is enabled, and there is more than one socket in use, each socket is handled by a separated thread. Moreover, some other options are available for tuning the printing of statistics for a given socket, and other information for debug purposes.

To test this application, we can use two server machines PC1 and PC2: PC1 generates traffic at the highest possible rate by running the [`pkt-gen`](https://github.com/luigirizzo/netmap/tree/master/apps/pkt-gen) Netmap application in transmission mode, and PC2 is used as a traffic receiver running the `nethuns-meter` application.

This is an example of how to run some tests; notice that, `ix0` must be replaced with the name of the interface, and also other options can be used.

In this case, `pkt-gen` is used here in its simplest form to send a stream of packets.
```
PC1:$ pkt-gen -i ix0 -f tx
```
The receiving part is set up to capture all the arriving packets by using a single socket. You can also enable multi-queue packet capture here by using more than one socket, and possibly enabling multi-threading.

To use multiple sockets, you need to *i)* set up the NIC on the receiver PC2 accordingly (to use a given number of queues equal to the number of sockets you intend to use), and also *ii)* use the `pkt-gen` options for generating packets with (at least) different destination IP addresses, so that the receiving network interface can spread incoming packets equally among the available hardware queues.
```
PC2~/nethuns/test$ ./nethuns-meter -i ix0
```


# Practical use cases

## Traffic generator: nmreplay over Nethuns ([source code](https://github.com/larthia/nethuns/blob/master/test/src/nmreplay.c))

A traffic generator has been implemented by porting over Nethuns the [`nmreplay`](https://github.com/luigirizzo/netmap/tree/master/apps/nmreplay) application from the Netmap project. The generator can replay packets from a pcap file at the desired speed, with the possibility of adding configurable packet delays and losses.

The "nethunized" `nmreplay` user-space application has been included in the `/test` directory in this repository and can be run with the following command line options:
```
nmreplay    [-f pcap-file]            set pcap file to replay
            [-i netmap-interface]     set interface to use as output
            [-b batch size]           set max batch size for tx
            [-B bandwidth]            set bandwidth to use for tx
            [-D delay]                add additional delay to packet tx
            [-L loss]                 simulate packet/bit errors
            [-w wait-link]            set wait (seconds) before tx
            [-v]                      enable verbose mode
```
The default batch size for packet transmission is 1 (no batching).

To test this application, we can use two server machines PC1 and PC2: PC1 replays a pcap file at the highest possible rate by running the "nethunized" `nmreplay`, and PC2 is used as a traffic receiver, running for example the `pkt-gen` Netmap application in rx mode or the `nethuns-meter` application.

## Open vSwitch (OVS) over Nethuns ([source code](https://github.com/giuseppelettieri/ovs/tree/nethuns))

The user-space datapath of OVS accesses network ports through a generic “netdev” interface that defines methods for (batched) rx and tx operations. Available netdev implementations include DPDK and AF_XDP and are available in the official [OVS repository](https://github.com/openvswitch/ovs). To port the OVS software switch over Nethuns, a new `netdev-nethuns` device has been implemented.

To test the OVS application with the `netdev-nethuns` device, backed by either the `AF_XDP` or the `netmap` engines, we can use two server machines PC1 and PC2. PC1 runs an OVS bridge over two 40 Gbps links (connecting the two machines in our testbed configuration), and PC2 sends minimally sized packets on the first link and measures the packets per second received from the second link.


# Using the library to implement a brand new application

So, how can you start using the Nethuns library to implement your own
application from scratch?

1. You need to include the `nethuns.h` header file and use the abstractions provided by the [Nethuns API](https://github.com/larthia/nethuns#nethuns-basic-api) in your network application. You can start by having a look to the source code of the examples available in the `/test` directory of the project.

2. Once the application is implemented, you need to build it. You can work on a machine like the ones we used in our experiments, where you previously compiled and installed the Nethuns library. Compiling the application is required before its execution can begin.

    The underlying framework to be used can be set as a compilation option. This is as simple as initializing the MACRO `NETHUNS_SOCKET` to a value in the range $[0, 3]$ where:
    * $0$ means LIBPCAP
    * $1$ means NETMAP
    * $2$ means XDP
    * $3$ means TPACKET_V3
	
	As an example, if you want to use Netmap, you can set up in your application Makefile
	```
	-DNETHUNS_SOCKET=1
	```

3. You are now all set up to run your application over the selected
underlying network engine!


# About the license

This work is licensed under the 3-Clause BSD License (New BSD License).

`SPDX-License-Identifier: BSD-3-Clause`


# Cite our work

Interested people can cite our work by using the following reference:
```
@article{10.1145/3544912.3544917,
    author = {Bonelli, Nicola and Del Vigna, Fabio and Fais, Alessandra and Lettieri, Giuseppe and Procissi, Gregorio},
    title = {{Programming Socket-Independent Network Functions with Nethuns}},
    year = {2022},
    issue_date = {April 2022},
    publisher = {Association for Computing Machinery},
    address = {New York, NY, USA},
    volume = {52},
    number = {2},
    issn = {0146-4833},
    url = {https://doi.org/10.1145/3544912.3544917},
    doi = {10.1145/3544912.3544917},
    journal = {SIGCOMM Computer Communication Review},
    month = {jun},
    pages = {35–48},
    numpages = {14},
    keywords = {programming abstraction, high-speed packet processing, OS independence, software data plane, socket independence}
}
```

You can also have a look at the [dedicated page](https://www.growkudos.com/publications/10.1145%25252F3544912.3544917/) available on the [Kudos Research Showcase](https://info.growkudos.com/discover-showcase) platform.


# Credits

## Authors

* Nicola Bonelli

## Contributors

* Fabio Del Vigna
* Alessandra Fais
* Giuseppe Lettieri
* Gregorio Procissi