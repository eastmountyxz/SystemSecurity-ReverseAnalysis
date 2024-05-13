#coding: utf-8
# By:Eastmount & LJC 2024-05-10
import idautils
import ida_gdl
import idaapi
import idc
import time

#根据样本最小地址和最大地址生成整个样本的cfg
def main(name):
    start_ea = ida_ida.inf_get_min_ea()
    end_ea = ida_ida.inf_get_max_ea()
    print(start_ea)
    print(end_ea)
    filename = '{}_cfg.gdl'.format(name)
    flowchart = idc.gen_flow_graph(filename, "cfg", start_ea, end_ea, CHART_GEN_GDL)
    print(flowchart)
    time.sleep(5)

if __name__ == "__main__":
    idaapi.auto_wait()
    main(idc.ARGV[1])
    idc.qexit(0)
