#coding:utf-8
#By:Eastmount CSDN 2023-04-10
import csv
import re
import os
import json
from jsonsearch import JsonSearch

def getAllFiles(targetDir):
    listFiles = os.listdir(targetDir)
    return listFiles

#-------------------------1.判断指定文件-----------------------------
aptname = "AAAA"
filenames = getAllFiles(aptname)
#['203', '204', ...,'277', '278']

i = 0
count = 0  #样本数量
while i<len(filenames):
    #判断该文件夹中是否存在reports件夹 eg:Aggah\277\reports
    filename = aptname + "\\" + filenames[i] + "\\reports"
    print(filename)
    if os.path.exists(filename):
        #report.html report.json report.pdf summary-report.html
        for n in os.listdir(filename):
            if n=="report.json":
                #----------------------2.提取MD5名称------------------
                jsonfile = filename + "\\report.json"
                print(jsonfile)
                with open(jsonfile) as fp:
                    data = json.load(fp)
                    print(data.keys())
                count += 1
    i += 1
    
print("Cape沙箱成功提取样本特征数量:", count)
