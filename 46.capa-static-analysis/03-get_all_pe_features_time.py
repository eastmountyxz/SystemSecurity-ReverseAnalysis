#By:Eastmount CSDN 2023-03-14
#coding: utf-8
import os
import time
from func_timeout import func_timeout
from func_timeout import FunctionTimedOut
from multiprocessing import Process

def getAllFiles(targetDir):
    listFiles = os.listdir(targetDir)
    return listFiles

def runCAPA(peName,jsonName):
    #cmd = "cd D://capa & capa.exe -vv " + str(peName) + " -j > " + jsonName + " & cmd"
    cmd = "cd D://capa & capa.exe -vv " + str(peName) + " -j > " + jsonName
    print(cmd)
    os.system(cmd)

#超时判定
def mytest(peName,jsonName):
    runCAPA(peName,jsonName)
    
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
        
        #超时判定
        try:
            func_timeout(10, mytest, args=(peName,jsonName, ))
        except FunctionTimedOut as e:
            print(e)
            print('子程序超时')
        print("-----------------------------\n\n")
    i += 1
    break
