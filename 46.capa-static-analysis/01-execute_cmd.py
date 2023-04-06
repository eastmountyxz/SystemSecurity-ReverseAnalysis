#coding: utf-8
#By:Eastmount CSDN 2023-03-14
import os

def getAllFiles(targetDir):
    listFiles = os.listdir(targetDir)
    return listFiles

apt_path = r"D:\capa\dataset"
apt_name = ['AAAA','BBBB','CCCC','DDDD']
i = 0
while i<len(apt_name):
    file_name = apt_path + "\\" + str(apt_name[i])
    print(file_name)
    files = getAllFiles(file_name)

    #创建输出文件夹
    write_path = r"D:\capa\result"
    write_name = write_path + "\\" + str(apt_name[i])
    print(write_name)
    if not os.path.exists(write_name):
        os.mkdir(write_name)

    #循环提取静态特征
    for name in files:
        peName = file_name + "\\" + name
        print(peName)
        name = os.path.splitext(name)[0]
        jsonName = write_name + "\\" + name + ".json"
        print(jsonName)
        break
    i += 1
    break
