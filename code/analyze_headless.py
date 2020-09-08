# This selects the target binary, executes Ghidra without GUI
# and executes the target script on the target binary.
# Please keep in mind that this was tested in a Linux environment.
# Please notice also that all the variables are NOT
# absolute paths, they need to be changed 
# according to where you are running the code!

# Execution in linux: python2 analyze_headless.py

import os
# path to Ghidra's analyzeHeadless. This should be something like "whatever/ghidra/support/analyzeHeadless"
ghidra_analyzeHeadless_loc = "/opt/ghidra/support/analyzeHeadless"
# path to an ALREADY EXISTING Ghidra project, like "/home/user/project.rep"
ghidra_project_loc = "/home/valeriop/naming_satcs.rep"
# name of the ALREADY EXISTING Ghidra project selected before, for example "project"
ghidra_project_name = "naming_satcs"
# path to the pre-script required by the extract_info_script
pre_script_loc = "/home/valeriop/Scrivania/inf_ghidra_gh/pre_script_decomp.py"
# Path to the "extract_cfg.py" script, which is under "/inf_ghidra_gh/extract_cfg.py",
# so for example "/home/user/Scrivania/inf_ghidra_gh/extract_cfg.py"
extract_cfg_script_loc = "/home/valeriop/Scrivania/SATCS_proj/extract_cfgs.py"

##################################################################################################################
##################################################################################################################
##################################################################################################################
##################################################################################################################

# Path to the compiled binary you wish to analyze.
binary_dir = "/home/valeriop/Scrivania/SATCS_proj/dataset_unstripped/"
counter = 0
list_of_binaries = os.listdir(binary_dir)
for binary_name in list_of_binaries:
	counter+=1
	print("==========PROCESSED {} BINARIES.=============".format(counter))
	if os.path.exists("/home/valeriop/Scrivania/SATCS_proj/logs/"+binary_name+".log"):
		print("\nAlready processed.\n")
	else:
		binary_loc = binary_dir+binary_name
		# build command
		command = ghidra_analyzeHeadless_loc+" "+ghidra_project_loc+" "+ghidra_project_name+" "+" -import "+binary_loc+" -prescript "+pre_script_loc+ " -postscript "+extract_cfg_script_loc+" >/home/valeriop/Scrivania/SATCS_proj/logs/"+binary_name+".log"
		# execute command
		os.system(command)