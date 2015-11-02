#!/bin/bash
valgrind --tool=memcheck src/chat localhost $(/labs/tsam15/my_port) /home/hir.is//pa3/src/fd.crt /home/hir.is/thorkell12/pa3/src/fd.key /home/hir.is/thorkell12/pa3/src/CAfile.pem 
