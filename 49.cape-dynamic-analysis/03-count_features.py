#coding:utf-8
#By:Eastmount CSDN 2023-04-10
import csv
import re
import os
import json
from jsonsearch import JsonSearch
import shutil

def getAllFiles(targetDir):
    listFiles = os.listdir(targetDir)
    return listFiles

apt = "AAAA"
aptname = apt + "-Result"
filenames = getAllFiles(aptname)
print(len(filenames))

writename = apt + "_result.csv"
fw = open(writename, mode="w", newline="")
writer = csv.writer(fw)
writer.writerow(['no', 'apt', 'md5', 'api'])

i = 0
while i<len(filenames):
    #打开json文件
    name = aptname + "\\" + filenames[i]
    print(name)
    api_str = ""
    md5 = filenames[i].split(".")[0]
    with open(name, encoding='utf-8') as fp:
        #特征解析
        data = json.load(fp)
        behavior = data["behavior"]
        jsondata = JsonSearch(object=behavior, mode='j')
        api = jsondata.search_all_value(key="api")
        print("特征数量:", len(api))
        print(api)

        #特征存储
        k = 0
        while k<len(api):
            value = str(api[k])
            api_str += value + ";"
            k += 1
        else:
            print("提取成功")
            #print(api_str)
    i += 1
    #文件存储
    writer.writerow([str(i), apt, md5, api_str])
    print("------------------------------\n\n")
fw.close()
