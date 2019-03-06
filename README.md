# ShareIpc - Shared Memory System
Tms is a brokerless, peer-to-peer shared memory library of semantically consistent functions for communicating between threads and processes. 

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
  + Read Modify Write
  + State Based
  
## Example
```c
Process A
  TmsListCreate("ListA", ...);
  lista = TmsListOpen("ListA", ...);
  data = TmsListAlloc(lista, size, ...);
  Prepare(data);
  TmsListWrite(lista, data);
  TmsFree(data);

Process B
  lista = TmsListOpen("ListA", ...);
  data = TmsListRead(lista, ...);
  Process(data);
  TmsFree(data).
  ```
