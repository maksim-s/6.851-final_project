import csv
import re

result1 = 'test1.csv'
result2 = 'test2.csv'
result3 = 'test3.csv'
result4 = 'test4.csv'
result5 = 'test5.csv'
i = 0
array1 = []
array2 = []
array3 = []
array4 = []
array5 = []
with open(result1, 'rb') as f:
    reader = csv.reader(f)
    try:
        array1 = [row[0] for row in reader]
    except csv.Error, e:
        sys.exit('file %s, line %d: %s' % (filename, reader.line_num, e))

with open(result2, 'rb') as f:
    reader = csv.reader(f)
    try:
        array2 = [row[0] for row in reader]
    except csv.Error, e:
        sys.exit('file %s, line %d: %s' % (filename, reader.line_num, e))

with open(result3, 'rb') as f:
    reader = csv.reader(f)
    try:
        array3 = [row[0] for row in reader]
    except csv.Error, e:
        sys.exit('file %s, line %d: %s' % (filename, reader.line_num, e))

with open(result4, 'rb') as f:
    reader = csv.reader(f)
    try:
        array4 = [row[0] for row in reader]
    except csv.Error, e:
        sys.exit('file %s, line %d: %s' % (filename, reader.line_num, e))
with open(result5, 'rb') as f:
    reader = csv.reader(f)
    try:
        array5 = [row[0] for row in reader]
    except csv.Error, e:
        sys.exit('file %s, line %d: %s' % (filename, reader.line_num, e))

result = []

for i in xrange(len(array1)):
    result.append([array1[i],array2[i],array3[i],array4[i],array5[i]])


with open('result.csv', 'wb') as f:
    writer = csv.writer(f)
    writer.writerows(result)
