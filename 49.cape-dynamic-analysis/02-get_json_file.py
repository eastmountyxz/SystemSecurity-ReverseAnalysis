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

#-------------------------1.判断指定文件-----------------------------
aptname = "AAAA"
writename = aptname + "-Result"
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
                htmlfile = filename + "\\report.html"
                print(jsonfile)
                with open(jsonfile) as fp:
                    data = json.load(fp)
                    #print(data.keys())
                    target = data["target"]
                    #print(target)
                    
                    #查找name对应的值
                    jsondata = JsonSearch(object=target,mode='j')
                    name = jsondata.search_all_value(key='name')
                    md5 = name[0].split(".")[0]
                    print(md5) #fb41ec1ea500beae2a7d5d373ebb906b.bin
                    
                    #-----------------3.文件写入--------------------
                    if not os.path.exists(writename):
                        os.mkdir(writename)
                    fname = writename + "\\" + md5 + ".json"
                    shutil.copy(jsonfile, fname)
                    fname = writename + "\\" + md5 + ".html"
                    shutil.copy(htmlfile, fname)
                count += 1
    i += 1
    
print("Cape沙箱成功提取样本特征数量:", count)
