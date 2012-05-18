gcc -o tab_hash tab_hash.c -pg
#./tab_hash > test1.csv
#sleep 1
#./tab_hash > test2.csv
#sleep 1
#./tab_hash > test3.csv
#sleep 1
#./tab_hash > test4.csv
#sleep 1
#./tab_hash > test5.csv
#python combine_data.py
#cat result.csv
./tab_hash