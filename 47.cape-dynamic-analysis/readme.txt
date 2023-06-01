Cape沙箱安装基本步骤：

第一步， 在任意文件夹中运行"sudo virtualbox"，现在已经安装了一个Win7 X64专业版虚拟机。

```python
sudo virtualbox
```

第二步， 进入/opt/CAPEv2/文件夹，运行"sudo python3 cuckoo.py"。

```python
cd /opt/CAPEv2
sudo python3 cuckoo.py
```

第三步， 在/opt/CAPEv2/文件夹下运行"sudo python3 utils/process.py -p7 auto"，参数代表优先级划分，输入多个样本时，沙箱会优先运行高优先级样本。

```python
cd /opt/CAPEv2/
sudo python3 utils/process.py -p7 auto
```

第四步，在/opt/CAPEv2/web目录下(由于环境依赖的问题，必须由指向该文件夹的shell运行该命令)，运行"sudo python3 manage.py runserver 127.0.0.1:8088"(该虚拟机的8080端口已被占用，端口可自己指定)。

```python
cd /opt/CAPEv2/web
sudo python3 manage.py runserver 127.0.0.1:8088
```
