from binaryninja.function import Variable
from binaryninja.mediumlevelil import MediumLevelILInstruction, SSAVariable
from binaryninja import MediumLevelILOperation

class AccessInfo(object):
	def __init__(self, offset, size, var_type=None):
		self.offset = offset
		self.size = size
		self.type = var_type

	def __eq__(self, other):
		if type(self) != type(other):
			return False
		if self.offset != other.offset:
			return False
		if self.size != other.size:
			return False
		if self.type != other.type:
			return False
		return True

	def __repr__(self):
		return "AccessInfo offset: {} size : {} type : {}".format(self.offset, self.size, self.type)

def recurse_for_derefs(instr):
	derefs = []
	if not isinstance(instr, MediumLevelILInstruction):
		return []
	if instr.operation == MediumLevelILOperation.MLIL_LOAD_SSA:
		return [instr]
	for operand in instr.operands:
		derefs.extend(recurse_for_derefs(operand))
	return derefs

def is_complex_add(add_expr):
	for op in add_expr.operands:
		if isinstance(op, MediumLevelILInstruction):
			if op.operation == MediumLevelILOperation.MLIL_ADD:
				return True
	return False

def get_access_info_from_deref(deref):
	if deref.operation != MediumLevelILOperation.MLIL_LOAD_SSA:
		return None
	if deref.src.operation == MediumLevelILOperation.MLIL_ADD:
		if is_complex_add(deref.src):
			return None
		for op in deref.src.operands:
			if op.operation == MediumLevelILOperation.MLIL_CONST:
				return AccessInfo(op.value.value, deref.size)
	elif deref.src.operation == MediumLevelILOperation.MLIL_VAR_SSA:
		return AccessInfo(0, deref.size)
	return None

def get_access_info_from_deref_assignment(deref):
	if deref.dest.operation == MediumLevelILOperation.MLIL_ADD:
		if is_complex_add(deref.dest):
			return None
		for op in deref.dest.operands:
			if op.operation == MediumLevelILOperation.MLIL_CONST:
				return AccessInfo(op.value.value, deref.size)
	elif deref.dest.operation == MediumLevelILOperation.MLIL_VAR_SSA:
		return AccessInfo(0, deref.size)

class InstructionHandler(object):
	def __init__(self, instruction):
		self.instruction = instruction

	def get_variables(self):
		return self.instruction.vars_read + self.instruction.vars_written

	def get_ssa_variables(self):
		return self.instruction.ssa_form.vars_read + self.instruction.ssa_form.vars_written

	def get_ssa_form_of_variable(self, variable):
		variables = self.get_ssa_variables()
		for current_var in variables:
			if variable.name == current_var.var.name:
				return current_var
		return None

	def is_ssa_direct_assignment(self):
		if self.instruction.operation != MediumLevelILOperation.MLIL_SET_VAR_SSA:
			return False
		if self.instruction.src.operation != MediumLevelILOperation.MLIL_VAR_SSA:
			return False
		return True

	def get_ssa_direct_assignment_source(self):
		if self.is_ssa_direct_assignment() == False:
			return None
		return self.instruction.src.operands[0]

	def get_access_info_for_ssa_var(self, var):
		rhs = self.get_rhs_access_info_for_ssa_var(var)
		lhs = self.get_lhs_access_info_for_ssa_var(var)
		rhs.extend(lhs)
		filtered = set(r for r in rhs if r is not None)
		return list(filtered)

	def get_lhs_access_info_for_ssa_var(self, var):
		if self.instruction.operation != MediumLevelILOperation.MLIL_STORE_SSA:
			return []
		var_list = self.instruction.dest.vars_read + self.instruction.dest.vars_written
		if var not in var_list: return []
		info = get_access_info_from_deref_assignment(self.instruction)
		if self.instruction.src.operation != MediumLevelILOperation.MLIL_VAR_SSA:
			return [info]
		info.type = self.instruction.src.src.var.type
		return [info]

	def get_rhs_access_info_for_ssa_var(self, var):
		if self.instruction.operation != MediumLevelILOperation.MLIL_SET_VAR_SSA:
			return []
		info_list = []
		derefs = recurse_for_derefs(self.instruction.src)
		for deref in derefs:
			variables = deref.vars_read + deref.vars_written
			if var in variables:
				info = get_access_info_from_deref(deref)
				if info is not None and info not in info_list:
					info_list.append(info)
		return info_list