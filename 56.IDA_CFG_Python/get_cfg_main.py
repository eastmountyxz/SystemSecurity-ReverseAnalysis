# coding: utf-8
# By:Eastmount & LJC 2024-05-10
import os

#完整路径跨目录调用
IDA_PATH = r"C:\Software\IDAPro7.5\ida.exe"
IDA64_PATH = r"C:\Software\IDAPro7.5\ida64.exe"
analyser = r"D:\test_cfg\get_sample_cfg.py"

#命令行脚本批量获取样本cfg
def analyse_module(sample_list, sample_name):
    ida_exe = IDA_PATH
    for i in range(len(sample_list)):
        sample = sample_list[i]
        name = sample_name[i]
        cmd = " ".join([ida_exe, f"-c -A -S" + '"' + analyser + ' ' + name + '"',  sample])
        print(cmd)
        os.system(cmd)

    return True

if __name__ == '__main__':
    #批量样本地址
    file_path = r'D:\test_cfg\sample'
    sample_name = os.listdir(file_path)
    sample_list = []
    for i in range(len(sample_name)):
        sample = file_path + '\\' + sample_name[i]
        print(sample)
        sample_list.append(sample)

    analyse_module(sample_list, sample_name)
    print("over!!!")
