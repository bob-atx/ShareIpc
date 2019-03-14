#!/bin/bash
rm -f junk; i=0; while true; do ./ltest &> junk; grep FAIL junk; if [ $? -eq 0 ]; then echo ERROR; break; else printf "PASS %d  \r" $i; fi; (( i++ )); done

