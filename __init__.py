from binaryninja import PluginCommand, Type, Structure, interaction
from binaryninja.log import log_error
from binaryninja.plugin import BackgroundTaskThread
from instruction_handler import InstructionHandler
from structor import Structor

class StructorTask(BackgroundTaskThread):
    def __init__(self, view):
        super(StructorTask, self).__init__('Generating structure...')
        self.view = view

    def run(self, instr):
		do_work(self.view, instr)
		self.finish()

def do_work(bv, instr):
	info = InstructionHandler(instr)
	choices = info.get_variables()
	if choices is []:
		interaction.show_message_box("Error!", "No variables found. If there's obviously a variable this is a bug.")
		return 	
	index = interaction.get_choice_input('Variable Selection', 'Please select a variable', choices)
	if index == None:
		return
	variable = choices[index]
	ssa_var = info.get_ssa_form_of_variable(variable)
	if ssa_var == None:
		log_error("Couldn't find SAA form of {}".format(variable))
		interaction.show_message_box("Error!", "Couldn't find SAA form of variable {}".format(variable))
		return
	mlil_func = instr.function
	result = Structor(ssa_var, mlil_func)
	if len(result.access_info) == 0:
		interaction.show_message_box("Nothing to do", "Can't figure out what to do with this...")
		return

	name = interaction.get_text_line_input("Struct Name", "Choose a name for the struct")
	if name == "":
		auto = bv.get_type_by_name("auto_struct")
		if auto is None:
			name = "auto_struct"
		else:
			num = 1
			while True:
				new_type = bv.get_type_by_name("auto_struct_{}".format(num))
				if new_type == None:
					name = "auto_struct_{}".format(num)
					break
				num += 1

	result.commit_struct(bv, name)

	struct_ptr = Type.pointer(bv.arch, result.named_type)
	for ssa_var in result.variables:
		instr.function.source_function.create_user_var(ssa_var.var, struct_ptr, ssa_var.var.name)
		#Maybe not necessary to set for every one because binja propagates it?

def create_struct(bv, instr):
	s = StructorTask(bv)
	s.run(instr)

PluginCommand.register_for_medium_level_il_instruction("Structor\\Create Auto Struct", "structor", create_struct)
