#coding:utf-8
#By:Eastmount CSDN 2023-03-14
import os
import json

def getAllFiles(targetDir):
    listFiles = os.listdir(targetDir)
    return listFiles

apt_path = r"D:\capa\result"
apt_name = ['AAAA']

i = 0
while i<len(apt_name):
    file_name = apt_path + "\\" + str(apt_name[i])
    print(file_name)

    files = getAllFiles(file_name)
    for name in files:
        jsonName = file_name + "\\" +  str(name)
        print(jsonName)

        #打开json文件
        with open(jsonName) as fp:
            data = json.load(fp)
            #print(data)
            print(data.keys())
            #dict_keys(['meta', 'rules'])
            #包含meta和rules两大块内容 静态行为及API在rules部分

            #提取ATT&CK特征
            behavior = data["rules"]
            print(behavior)

        break
    i += 1
    break
