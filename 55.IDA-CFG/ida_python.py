##################################
# idaapi
##################################
get_inf_structure() # info = get_inf_structure(), info.is32bit(), info.procName是处理器架构
FlowChart(get_func(ea)) #
##################################
# idautils
##################################
Functions() # 列出所有的函数，返回的是一个迭代器，其中的所有元素都是函数起始地址
Strings() # 列出所有字符串，每个字符串都有ea, length和strtype属性
Names() # 所有的name，包括函数名，字符串名
##################################
# ida_auto
##################################
auto_wait() # 批量处理脚本时用的，等待自动分析完成再进行分析，尽可能加，否则脚本可能无法完整执行
##################################
# ida_bytes
##################################
ida_bytes.get_byte(ea) # 获取一个字节
ida_bytes.get_word(ea) # 获取两个字节
ida_bytes.get_dword(ea) # 获取四个字节
# 修改数据类型，相当于手动操作时在对应位置按"D"
# 这里也可以循环操作，比如一大块内存都是通过bytes表示的，需要换成8bit、16bit或32bit表示可以这样
create_byte(ea, 1)
create_16bit_data(ea, 2) # 第二个参数搞不懂有啥用，就按字节数保持不变通过循环实现吧
create_32bit_data(ea, 4)
##################################
# ida_funcs
##################################
get_func(ea) # 返回当前地址对应的函数的一些信息，其中start_ea是起始地址，end_ea是结束地址
get_func_name(ea) # 获取这个地址对应的函数名
##################################
# ida_nalt
##################################
get_root_filename() # 获取当前二进制文件的名字
get_imagebase() # 获取加载基址
##################################
# ida_pro
##################################
qexit(code) # 退出当前界面，相当于exit
##################################
# ida_search
##################################
find_text(ea, 0, 0, string, ida_search.SEARCH_DOWN) # ea是地址，string是要找的字符，其它的不动就行
# 要跳到下一个位置需要如此更新: ea = idc.next_head(ea)
##################################
# ida_ua
##################################
create_insn(ea) # 将ea开始的数据转化为代码，注意得先用create_byte把所有数据都转成byte，否则不能用
##################################
# ida_xref
##################################
get_first_fcref_to(addr) # 找到第一个引用addr的地址，没有则返回-1(也可能是BADADDR=2^32 - 1)
get_next_fcref_to(addr)  # 调用上面的函数之后可以一直调用直到返回-1
get_first_cref_to(addr)  # 找第一个代码引用
get_next_cref_to(addr)
get_first_dref_to(addr)  # 找第一个数据引用
get_next_dref_to(addr)
##################################
# idc
##################################
find_func_end(ea)         # 给定一个IDA能够识别的函数的开头，返回函数结尾
prev_head(ea)             # ea位置上一条指令的地址(只能看相邻的地址，不能看跳转过来的位置)
next_head(ea)             # 下一条指令的地址
get_operand_type(ea, n)   # ea是指令地址，n代表第几个参数，感觉这个没啥用
get_operand_value(ea, n)  # 获取参数的值
get_strlit_content(ea)    # 获取ea位置的字符串，估计这个库在写的时候漏了一个l
print_insn_mnem(ea)       # 打印操作码，实用的多，要是一个地址没有数据，那么就会返回空字符串(即''，而不是None)
print_operand(ea, n)      # 打印操作数，n从0开始(第0个不是操作码，而是第一个操作数)，超出下标的是空字符串''
