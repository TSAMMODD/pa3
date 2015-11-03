#!/bin/bash
valgrind --tool=memcheck --leak-check=full --show-leak-kinds=all src/chat localhost $(/labs/tsam15/my_port) /home/hir.is/danielb13/Tolvusamskipti/tsam15/pa3/src/fd.crt /home/hir.is/danielb13/Tolvusamskipti/tsam15/pa3/src/fd.key /home/hir.is/danielb13/Tolvusamskipti/tsam15/pa3/src/CAfile.pem
