#!/bin/bash
valgrind  --leak-check=full --tool=memcheck --show-reachable=yes --num-callers=20 --track-fds=yes src/chatd $(/labs/tsam15/my_port) /home/hir.is/thorkell12/pa3/src/fd.crt /home/hir.is/thorkell12/pa3/src/fd.key /home/hir.is/thorkell12/pa3/src/CAfile.pem

