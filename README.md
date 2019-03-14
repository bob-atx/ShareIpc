# ShareIpc - Shared Memory System
ShareIpc is a brokerless shared memory library of semantically consistent functions for communicating between threads and processes.  ShareIpc is a thread-safe, GNU/Linux/pthreads C package (32/64) and not suitable for MS Windows or macOS.

The ShareIpc library is built as a single source file and is compiled using cmake.

To install and build:
```
git clone https://github.com/bob-atx/ShareIpc.git
cd ShareIpc/build
cmake ..
make
sudo make install
```

The following components work seamlessly across threads and processes. 

## Lists
  + Queue
  + Stack
  + Ring
  
## Memory Pools
  + Heap 
  + Dynamic
  + Fixed
  
## Hash Tables
  + Read, write, delete, read-modify-write
  + Fast state based transactions
  + Callbacks inline or as threads
  + Notification on updates
  
## Shared Memory

## Synchronization
+ Mutex, read/write, condition variables (CV)
+ CV signaling and callbacks
+ Simple file locking

## Timers

## Threads
  
  

