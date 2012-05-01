gcc -o tab_hash tab_hash.c -pg
./tab_hash
gprof tab_hash > result.txt
