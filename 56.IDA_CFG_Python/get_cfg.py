#coding: utf-8
# By:Eastmount & LJC 2024-05-10
import idaapi
import ida_gdl
import idautils
import idc

def main():

    functions = idautils.Functions()
    
    for func_ea in functions:
        func_name = idc.get_func_name(func_ea)
        func = idaapi.get_func(func_ea)
        start_ea = idc.get_func_attr(func_ea, FUNCATTR_START)
        end_ea = idc.get_func_attr(func_ea, FUNCATTR_END)
        gdl_file_name = "CFG_{}.gdl".format(func_name)
        flowchart = idc.gen_flow_graph(gdl_file_name, "cfg", start_ea, end_ea, CHART_GEN_GDL)
        if flowchart:
            print("CFG for function {} has been saved as {}".format(func_name, gdl_file_name))
        else:
            print("Failed to save CFG for function {}".format(func_name))

if __name__ == "__main__":
    idaapi.auto_wait()
    main()
    idc.qexit(0)
