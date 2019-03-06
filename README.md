# ShareIpc - Shared Memory System
Tms is a brokerless, peer-to-peer shared memory library of semantically consistent functions for communicating between threads and processes. 

The following components work seamlessly across threads and processes. 

## Lists
  + Queue
  + Stack
  + Ring

### List Example
```c
Process A
  TmsListCreate("ListA", ...);
  lista = TmsListOpen("ListA", ...);
  data = TmsListAlloc(lista, size, ...);
  (fill in data)
  TmsListWrite(lista, data);
  TmsFree(data);

Process B
  lista = TmsListOpen("ListA", ...);
  data = TmsListRead(lista, ...);
  (process data)
  TmsFree(data);
  ```
## Memory Pools
  + Heap 
  + Dynamic
  + Fixed
  
## Hash Tables
  + Read, write, delete, read-modify-write
  + Fast state based transactions
  + Callbacks inline or as threads
  
  

