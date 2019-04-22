from instruction_handler import InstructionHandler
from binaryninja import log_debug
from binaryninja.types import Type, Structure
class Structor(object):

	def __init__(self, ssa_var, mlil_function):
		self.function = mlil_function.non_ssa_form
		self.ssa_function = mlil_function.ssa_form
		self.variables = self.search_for_variables(ssa_var)
		self.access_info = self.get_const_accesses()
		self.structure = self.create_struct()

	def search_for_variables(self, ssa_var, ignore=set()):
		variables = set([ssa_var])
		definition = self.ssa_function.get_ssa_var_definition(ssa_var)
		uses = self.ssa_function.get_ssa_var_uses(ssa_var)
		log_debug("uses: {}".format(uses))
		log_debug("def of {}: {}".format(ssa_var, definition))
		if definition is not None:
			def_info = InstructionHandler(definition)
			if def_info.is_ssa_direct_assignment():
				def_var = def_info.get_ssa_direct_assignment_source()
				if def_var != None and def_var not in ignore:
					variables.add(def_var)
					result = self.search_for_variables(def_var, ignore=variables)
					variables = variables.union(result)
		for use in uses:
			use_info = InstructionHandler(use)
			log_debug("use of {}: {}".format(ssa_var, use))
			if use_info.is_ssa_direct_assignment():
				if ignore == use_info.get_ssa_direct_assignment_source():
					continue
				use_var = use.dest
				result = self.search_for_variables(use_var, ignore=variables)
				variables = variables.union(result)
		return variables

	def get_const_accesses(self):
		accesses = list()
		for var in self.variables:
			uses = self.ssa_function.get_ssa_var_uses(var)
			for use in uses:
				info = InstructionHandler(use)
				result = info.get_access_info_for_ssa_var(var)
				accesses.extend(result)
		return accesses

	def create_struct(self):
		struct = Structure()
		for info in self.access_info:
			if info.type != None:
				struct.insert(info.offset, info.type)
			else:
				struct.insert(info.offset, Type.int(int(info.size)))
		return struct

	def commit_struct(self, bv, name):
		self.struct_type = Type.structure_type(self.structure)
		self.named_type = Type.named_type_from_type(name, self.struct_type)
		bv.define_user_type(name, self.struct_type)
		#bv.define_user_type(name, self.named_type)
		return

