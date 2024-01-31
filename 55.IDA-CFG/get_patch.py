from idc import GetDisasm, print_insn_mnem, get_operand_value
from ida_bytes import next_head
from ida_bytes import patch_byte
start = 0x798
end = 0xf67
ea = start
while ea < end:
	old_ea = ea
	instr1 = GetDisasm(ea)
	op1 = print_insn_mnem(ea)
	ea = next_head(ea, end)
	instr2 = GetDisasm(ea)
	op2 = print_insn_mnem(ea)
	if (op1 = 'jb' and op2 = 'jnb') or (op1 = 'jnb' and op2 = 'jb'):
		value1 = get_operand_value(old_ea, 0)
		value2 = get_operand_value(ea, 0)
		if value1 = value2:
			print(hex(old_ea), instr1)
			print(hex(ea), instr2)
			print(hex(value1), hex(value2))
			print('-' * 30)
			old_ea = next_head(ea, end)
			ea = value1
			
			for i in range(old_ea, ea):
			patch_byte(i, 0x90) # 填充对应位置的数据
