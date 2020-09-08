# extract functions CFGs

from ghidra.app.decompiler import DecompileOptions, DecompInterface
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.program.model.pcode import PcodeOp
from ghidra.util import NumericUtilities
import os
import json
import networkx as nx
from networkx.readwrite import json_graph

################################################################################

#first, let's retrieve all functions and their names.

def list_all_functions_name():
	funcs_names_list = []
	func = getFirstFunction()
	while func is not None:
		funcs_names_list.append(func.getName())
		func = getFunctionAfter(func)
	return funcs_names_list

def list_all_functions():
    funcs_list = []
    func = getFirstFunction()
    while func is not None:
        x = func.isThunk()
        if not x:
            funcs_list.append(func)
        func = getFunctionAfter(func)
    return funcs_list

################################################################################

def open_program():
	iface = DecompInterface()
	iface.openProgram(currentProgram)
	return iface


################################################################################
################################################################################

# given a function, returns a "High-Function" and its basic blocks, a representation
# of the function made by Ghidra in which the function is divided in blocks and
# represented as pseudocode.

def get_hf(iface, func):
    iface.setOptions(DecompileOptions())
    iface.setSimplificationStyle("normalize")
    func_decompiled = iface.decompileFunction(func, 60, ConsoleTaskMonitor())
    highFunction = func_decompiled.getHighFunction()
    return highFunction

def get_basic_blocks_per_function(hf):
    return (hf, hf.getBasicBlocks())

################################################################################
################################################################################

# this retrieves a cfg per each function, if a block containing the entrypoint of
# that function is found in the blocks of the function itself.

def cfg_per_function(hf, blocklist):
    digraph = None
    entrypoint = get_function_entrypoint(hf)
    entrypoint_block = get_entrypoint_block(entrypoint, blocklist)
    if entrypoint_block is not None: # None happens for functions like _init or _start
        traversed = []
        digraph = nx.DiGraph()
        digraph.add_node(entrypoint_block.getStart().toString(), entrypoint = True, data = get_block_data(entrypoint_block, hf)) # add first entry vertex
        cfg_add_children(digraph, entrypoint_block, hf, traversed) # get the "children"
    return digraph

def get_function_entrypoint(hf):
    return hf.getFunction().getEntryPoint()

def get_entrypoint_block(entrypoint, blocklist):
    entry_block = None
    for block in blocklist:
        if(block.getStart().equals(entrypoint)):
            entry_block = block
    return entry_block

def cfg_add_children(digraph, block, hf, traversed): # "DFS" from the entrypoint block
    if block.getOutSize() > 0:
        for o in range(0, block.getOutSize()):
            out_block = block.getOut(o)
            if out_block is not block and out_block not in traversed: # avoid self-loops!
                digraph.add_node(out_block.getStart().toString(), entrypoint = False, data = get_block_data(out_block, hf))
                digraph.add_edge(block.getStart().toString(), out_block.getStart().toString())
                traversed.append(out_block)
                cfg_add_children(digraph, out_block, hf, traversed)
            elif out_block in traversed: # add the edge anyway
                 digraph.add_edge(block.getStart().toString(), out_block.getStart().toString())

    return

#########################################################################################
#########################################################################################
#########################################################################################
#########################################################################################

# Now we need something more. For each block in a CFG, we want to retrieve:
# - start and end addresses of the block;
# - its bytecode;
# - its set of assembly instructions as strings/dictionary (already done) with strings if
#   possible (already done) with address and value of the string (so something a little different);
# - its set of assembly instructions as Ghidra Instruction Object;
# - its set of called functions with name and address per each of them;

def get_block_data(block, hf):
    data = {}
    start_address = ("start_address", block.getStart().toString())
    end_address = ("end_address", block.getStop().toString())
    (res_asm, res_func, res_string, res_bytecode) = get_information_block(block, hf)
    asm_string = ("asm_dict_string",res_asm)
    called_functions = ("called_functions", res_func)
    strings_mem = ("strings_mem", res_string)
    bytecode = ("bytecode", res_bytecode)
    data[start_address[0]] = start_address[1]
    data[end_address[0]] = end_address[1]
    data[bytecode[0]] = bytecode[1]
    data[asm_string[0]] = asm_string[1]
    data[called_functions[0]] = called_functions[1]
    data[strings_mem[0]] = strings_mem[1]
    return data

# retrieves content of the block as asm instructions

def get_information_block(block, hf):
    res_asm = {}
    res_func = {}
    res_string = {}
    res_bytecode = {}
    start = block.getStart()
    stop = block.getStop()
    iter_ = currentProgram.getListing().getCodeUnits(start, True)
    done = False
    while (iter_.hasNext() and done == False):
        # here, we have the code unit, that is to say the precise instruction at a
        # given mem location. This should be where further analysis/preprocessing
        # is done.
        ins = iter_.next()
        ins_addr = ins.getAddress()
        ins_mnemo = ins.getMnemonicString()
        ins_str = ins.toString()
        try:
            ins_bytes = ins.getBytes()
            ins_bytecode = NumericUtilities.convertBytesToString(ins_bytes)
        except:
            ins_bytecode = None
            continue
        # here we get the mnemonic string, see if instruction is CALL/LEA/MOV/JUMP
        # or any other instruction having operands, retrieve the operands. Now we
        # check their type: if the operand is IMMEDIATE or MEMORY -> try to read into it!
        if(ins_mnemo.startswith('CALL') or ins_mnemo.startswith('J')):
            p_op = ins.getAddress(0) # gets the address of the operand
            if(p_op is not None): # must be a function
                if(getFunctionAt(p_op) is not None):
                    func_name = getFunctionAt(p_op).getName() # replace address with function name
                    ins_str = ins_str.split(' ', 1)[0]
                    ins_str += " "+func_name
                    res_func[p_op.toString()] = func_name
        elif(ins_mnemo.startswith('LEA') or ins_mnemo.startswith('MOV') or ins_mnemo.startswith('CMP')):
            s_op = ins.getAddress(1) # gets the address of the second operand
            if(s_op is not None): # may contain some data here
                data = getDataAt(s_op)
                if(data is not None and data.getDataType().getName() == 'string'):
                    try:
                        data_arr = data.getBytes()
                        # decode to utf-8 to actually read the bytes!
                        # that -1 is a very non-elegant way to get rid of last byte.
                        # There might be a better way to do it.
                        data_str = str(data_arr.tostring().decode('ascii'))[:-1]
                        res_string[s_op.toString()] = data_str
                        ins_str = ins_str.split(',', 1)[0]
                        ins_str += ", "+data_str
                    except:
                        continue
                elif(data is not None and data.isPointer()):
                    addr = data.getValue() # get the address
                    data_pointed = getDataAt(addr)
                    if(data_pointed is not None and data_pointed.getDataType().getName() == 'string'):
                        try:
                            data_arr = data_pointed.getBytes()
                            data_str = str(data_arr.tostring().decode('utf-8'))[:-1]
                            res_string[s_op.toString()] = data_str
                            ins_str = ins_str.split(',', 1)[0]
                            ins_str += ", "+data_str
                        except:
                            continue
        res_asm[ins_addr.toString()] = ins_str
        res_bytecode[ins_addr.toString()] = ins_bytecode
        if (ins_addr == stop):
            done = True
    return (res_asm, res_func, res_string, res_bytecode)

#########################################################################################
#########################################################################################
#########################################################################################
#########################################################################################
#########################################################################################

# prints each cfg of each function to a json output file.

def print_cfg_as_json(cfg, func_name):
    # the file will be saved under folder "data"
    # please notice these are NOT absolute paths, they need to be changed according 
    # to the directory you are running this code!
    previous = "/home/valeriop/Scrivania/SATCS_proj/data/"
    prepre = "/home/valeriop/Scrivania/SATCS_proj/data_2/"
    preprepre = "/home/valeriop/Scrivania/SATCS_proj/data_3/"
    save_in = "/home/valeriop/Scrivania/SATCS_proj/data_4/"
    if (not os.path.exists(previous+func_name+'.json') and not os.path.exists(prepre+func_name+'.json') and not os.path.exists(preprepre+func_name+'.json') and not os.path.exists(save_in+func_name+'.json')): # avoid duplicate functions
	    data = json_graph.node_link_data(cfg)
	    with open(save_in+func_name+'.json', 'w') as f:
	        json.dump(data, f)

################################################################################
################################################################################
################################################################################
################################################################################
################################################################################

def main():
	hfs = []
	listing = list_all_functions()
	iface = open_program()
	print("\nRetrieving CFGS per each function...\n")
	for func in listing:
		hfs.append(get_hf(iface, func))
	basic_blocks_list = []
	cfgs = {}
	for hf in hfs:
		if hf is not None:
			basic_blocks_list.append(get_basic_blocks_per_function(hf))
	for (hf, bblocks_f) in basic_blocks_list:
		func_name = hf.getFunction().getName()
		if func_name not in cfgs:
			cfgs[func_name] = []
			cfgs[func_name].append(cfg_per_function(hf, bblocks_f))
		else:
			cfgs[func_name].append(cfg_per_function(hf, bblocks_f))
	print("\nDone. Saving the CFGs...\n")
	for func_name in cfgs:
		for cfg in cfgs[func_name]:
			if cfg is not None:
				print_cfg_as_json(cfg, func_name)
	print("\nDone. Bye!\n")

main()