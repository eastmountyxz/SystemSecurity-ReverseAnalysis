#coding:utf-8
#By:Eastmount CSDN 2023-05-31
import csv
import re
import os

csv.field_size_limit(500 * 1024 * 1024)
filename = "AAAA_result.csv"
writename = "AAAA_result_final.csv"
fw = open(writename, mode="w", newline="")
writer = csv.writer(fw)
writer.writerow(['no', 'type', 'md5', 'api'])
with open(filename,encoding='utf-8') as fr:
    reader = csv.reader(fr)
    no = 1
    for row in reader: #['no','type','md5','api']
        tt = row[1]
        md5 = row[2]
        api = row[3]
        #print(no,tt,md5,api)
        #api空值的过滤
        if api=="" or api=="api":
            continue
        else:
            writer.writerow([str(no),tt,md5,api])
            no += 1
fr.close()
