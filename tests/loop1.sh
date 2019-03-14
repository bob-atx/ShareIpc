#!/bin/bash
rm -f core
rm -f junk
rm -f /dev/shm/tms*
killall ltest
i=0;
while true; do ./ltest |& tee junk; grep FAIL junk; if [ $? -eq 0 ]; then echo ERROR; break; else printf "PASS %d  \r" $i; fi; (( i++ )); done

