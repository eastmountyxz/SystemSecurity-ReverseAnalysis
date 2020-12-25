# encoding:  utf-8

key = "AKA"
name = "Eastmount"

#获取用户名长度
nameLen = len(name)
print(u'获取用户名长度:')
print(nameLen)

#用户名长度乘以0x17CFB得到结果
res = nameLen * 0x17CFB
print(u'用户名长度乘以0x17CFB:')
print(res)

#将结果加上用户名的第一个字符的ASCII
print(name[0], ord(name[0]))
res = res + ord(name[0])
print(u'结果加上用户名第一个字符的ASCII:')
print(res)

#转换为十进制 省略

#拼接序列号
key = key + str(res)
print(u'最终结果:')
print(key)
