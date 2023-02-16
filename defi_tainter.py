import argparse
import sys
import pandas as pd
import os
from datetime import datetime
from web3 import Web3

class Contract:
    def __init__(self, platform, logic_addr, storage_addr, func_sign, block_number, caller, call_site, level):
      self.platform = platform
      self.logic_addr = self.format_addr(logic_addr)
      self.storage_addr = self.format_addr(storage_addr)
      self.func_sign = func_sign
      self.func = ""
      self.block_number = block_number
      self.caller = caller
      self.call_site = call_site
      self.callArgVals = {}
      self.url = ""
      self.external_calls = []
      self.level = level
      self.analyze()
    
    def format_addr(self, addr):
        if len(addr) != 42:
            return "0x" + "0"*(42-len(addr)) + addr.replace("0x", "")
        else:
            return addr
    
    def analyze(self):
        self.set_url()
        self.download_bytecode()
        if os.path.exists("./gigahorse-toolchain/contracts/" + self.logic_addr + ".hex"):
            self.analyze_contract()
            self.set_func()
            self.set_callArgVals()
            self.set_external_calls()

    def set_url(self):
        if self.platform == "ETH":
            self.url = "https://solitary-morning-tent.discover.quiknode.pro/52c71a829ae2798a9db90720b94c8762c6ca39bb/"
        elif self.platform == "BSC":
            self.url = "https://quaint-rough-waterfall.bsc.discover.quiknode.pro/176f56e8d451871eb43624a242435ca6a2f9afbe/"
        elif self.platform == "Avalanche":
            self.url = "https://avalanche-mainnet.infura.io/v3/6807f78a636b46c7a7573af66a2e3391"
        elif self.platform == "Polygon":
            self.url = "https://polygon-mainnet.g.alchemy.com/v2/EA2tN7s-N5p5wG8m2FzeShS9xEGtXCdG"
        elif self.platform == "Solana":
            self.url = "https://solana-mainnet.g.alchemy.com/v2/xRsxXqiD5Ef_5GuDJf0suuSkBytDjcYw"
        elif self.platform == "Fantom":
            self.url = "https://practical-long-energy.fantom.discover.quiknode.pro/fc97af1ebab40f57ea698b6cf3dd67a2d24cac1a/"
        elif self.platform == "Gnosis":
            self.url = "https://icy-quiet-star.xdai.discover.quiknode.pro/0916b0df3ee3a0a19a52d2a943fc64cdd3f6b925/"
        else:
            self.url = ""


    def download_bytecode(self):
        if self.url == "":
            return
        loc = "./gigahorse-toolchain/contracts/" + self.logic_addr + ".hex"
        if os.path.exists(loc):
            return 
        else:
            w3 = Web3(Web3.HTTPProvider(self.url))
            contract_address = Web3.toChecksumAddress(self.logic_addr)
            code = str(w3.eth.get_code(contract_address).hex())
            if code != "0x":
                with open(loc, "w") as f:
                    f.write(code[2:])

    def analyze_contract(self):
        command = "cd ./gigahorse-toolchain && ./gigahorse.py -C ./clients/price_manipulation _analysis.dl ./contracts/{contract_addr}.hex >/dev/null 2>&1"
        os.system(command.format(contract_addr = self.logic_addr))

    def set_func(self):
        loc = "./gigahorse-toolchain/.temp/" + self.logic_addr + "/out/PublicFunction.csv"
        if os.path.exists(loc) and (os.path.getsize(loc) > 0):
            df = pd.read_csv(loc, header=None, sep='	')
            df.columns = ["func", "funcSign"]
            try:
                self.func = list(df.loc[df["funcSign"] == self.func_sign, "func"])[0]
            except:
                try:
                    self.func = list(df.loc[df["funcSign"] == "0x00000000", "func"])[0]
                except:
                    None
    
    def set_callArgVals(self):
        if self.caller != "":
            loc = "./gigahorse-toolchain/.temp/" + self.caller + "/out/FLA_ExternalCall_Known_Arg.csv"
            if os.path.exists(loc) and (os.path.getsize(loc) > 0):
                df = pd.read_csv(loc, header=None, sep='	')
                df.columns = ["func", "callStmt", "argIndex", "argVal"]
                df = df.loc[df["callStmt"] == self.call_site]
                for i in range(len(df)):
                    temp_index = int(df.iloc[i]["argIndex"])
                    temp_callArgVal = df.iloc[i]["argVal"]
                    self.callArgVals[temp_index] = temp_callArgVal              

    def get_storage_content(self, slot_index, byteLow, byteHigh):
        w3 = Web3(Web3.HTTPProvider(self.url))
        contract_address = Web3.toChecksumAddress(self.storage_addr)
        storage_content = str(w3.eth.get_storage_at(contract_address, slot_index, self.block_number).hex())
        storage_content = storage_content.replace("0x", "")
        if byteLow == 0:
            contract_addr = "0x" + storage_content[-(byteHigh+1)*2:]
        else:
            contract_addr = "0x" + storage_content[-(byteHigh+1)*2:-byteLow*2]
        return contract_addr
    
    def set_external_calls(self):
        loc1 = "./gigahorse-toolchain/.temp/" + self.logic_addr + "/out/FLA_ExternalCallInfo.csv"
        if os.path.exists(loc1) and (os.path.getsize(loc1) > 0):
            df1 = pd.read_csv(loc1, header=None, sep='	')
            df1.columns = ["func", "callStmt", "callOp", "calleeVar", "numArg", "numRet"]
            df1 = df1.loc[df1["func"] == self.func]
        else:
            df1 = pd.DataFrame()

        loc2 = "./gigahorse-toolchain/.temp/" + self.logic_addr + "/out/FLA_ExternalCall_Callee_ConstType.csv"
        if os.path.exists(loc2) and (os.path.getsize(loc2) > 0):
            df2 = pd.read_csv(loc2, header=None, sep='	')
            df2.columns = ["func", "callStmt", "callee"]
        else:
            df2 = pd.DataFrame()

        loc3 = "./gigahorse-toolchain/.temp/" + self.logic_addr + "/out/FLA_ExternalCall_Callee_StorageType.csv"
        if os.path.exists(loc3) and (os.path.getsize(loc3) > 0):
            df3 = pd.read_csv(loc3, header=None, sep='	')
            df3.columns = ["func", "callStmt", "storageSlot", "byteLow", "byteHigh"]
        else:
            df3 = pd.DataFrame()
        
        loc6 = "./gigahorse-toolchain/.temp/" + self.logic_addr + "/out/FLA_ExternalCall_Callee_StorageType_ForProxy.csv"
        if os.path.exists(loc6) and (os.path.getsize(loc6) > 0):
            df6 = pd.read_csv(loc6, header=None, sep='	')
            df6.columns = ["func", "callStmt", "storageSlot"]
        else:
            df6 = pd.DataFrame()

        loc4 = "./gigahorse-toolchain/.temp/" + self.logic_addr + "/out/FLA_ExternalCall_FuncSign_ConstType.csv"
        if os.path.exists(loc4) and (os.path.getsize(loc4) > 0):
            df4 = pd.read_csv(loc4, header=None, sep='	')
            df4.columns = ["func", "callStmt", "funcSign"]
        else:
            df4 = pd.DataFrame()

        loc5 = "./gigahorse-toolchain/.temp/" + self.logic_addr + "/out/FLA_ExternalCall_FuncSign_ProxyType.csv"
        if os.path.exists(loc5) and (os.path.getsize(loc5) > 0):
            df5 = pd.read_csv(loc5, header=None, sep='	')
            df5.columns = ["func", "callStmt"]
        else:
            df5 = pd.DataFrame()
        
        loc7 = "./gigahorse-toolchain/.temp/" + self.logic_addr + "/out/FLA_ExternalCall_Callee_FuncArgType.csv"
        if os.path.exists(loc7) and (os.path.getsize(loc7) > 0):
            df7 = pd.read_csv(loc7, header=None, sep='	')
            df7.columns = ["func", "callStmt", "pubFun", "argIndex"]
        else:
            df7 = pd.DataFrame()

        for i in range(len(df1)):
            call_stmt = df1.iloc[i]["callStmt"]
            
            external_call = {"logic_addr":"", "storage_addr":"", "funcSign":"", "caller":"", "call_site": ""}

            if len(df2) != 0:
                df_temp = df2.loc[df2["callStmt"] == call_stmt]
                if len(df_temp) > 0:
                    external_call["logic_addr"] = list(df_temp["callee"])[0].replace("000000000000000000000000", "")
            
            if len(df3) != 0:
                df_temp = df3.loc[df3["callStmt"] == call_stmt]
                if len(df_temp) > 0:
                    external_call["logic_addr"] = self.get_storage_content(list(df_temp["storageSlot"])[0], list(df_temp["byteLow"])[0], list(df_temp["byteHigh"])[0])
            
            if len(df6) != 0:
                df_temp = df6.loc[df6["callStmt"] == call_stmt]
                if len(df_temp) > 0:
                    external_call["logic_addr"] = self.get_storage_content(list(df_temp["storageSlot"])[0], 0, 19)
            
            if len(df7) != 0:
                df_temp = df7.loc[df7["callStmt"] == call_stmt]
                if len(df_temp) > 0:
                    if list(df_temp["func"])[0] == list(df_temp["pubFun"])[0]:
                        temp_index = int(list(df_temp["argIndex"])[0])
                        if temp_index in self.callArgVals.keys():
                            external_call["logic_addr"] = self.callArgVals[temp_index]           
            
            if df1.iloc[i]["callOp"] == "DELEGATECALL":
                external_call["storage_addr"] = self.logic_addr
                external_call["caller"] = self.caller
                external_call["call_site"] = self.call_site
            else:
                external_call["storage_addr"] = external_call["logic_addr"]
                external_call["caller"] = self.logic_addr
                external_call["call_site"] = call_stmt
            
            if len(df4) != 0:
                df_temp = df4.loc[df4["callStmt"] == call_stmt]
                if len(df_temp) > 0:
                    external_call["funcSign"] = list(df_temp["funcSign"])[0][:10]
            
            if len(df5) != 0:
                df_temp = df5.loc[df5["callStmt"] == call_stmt]
                if len(df_temp) > 0:
                    external_call["funcSign"] = self.func_sign

            self.external_calls.append(external_call)

def construct_cross_contract_call_graph(source):
    pending = []
    pending.append(source)

    index = 0
    while len(pending) > 0:
        temp = pending.pop()
        index += 1
        # print("Processing " + str(index) + " : " + temp["logic_addr"] + "_" + temp["func_sign"])
        temp_key = temp["caller"] + "_" + temp["call_site"] + "_" + temp["logic_addr"] + "_" + temp["func_sign"]
        if temp_key in contracts.keys():
            continue
        contracts[temp_key] = Contract(temp["platform"], temp["logic_addr"], temp["storage_addr"], temp["func_sign"], temp["block_number"], temp["caller"], temp["call_site"], temp["level"])
        for external_call in contracts[temp_key].external_calls :
            if external_call["logic_addr"] != "" and external_call["storage_addr"] != "" and external_call["funcSign"] != "" :
                pending.append({"platform": temp["platform"], "logic_addr": external_call["logic_addr"], "storage_addr":external_call["storage_addr"], 
                "func_sign": external_call["funcSign"], "block_number": temp["block_number"], "caller": external_call["caller"], "call_site": external_call["call_site"], "level": temp["level"] + 1})

# helper
def find_executed_pp(caller, callsite, contract_addr, func_sign):
    addr = ""
    level = -1
    for key in contracts.keys():
        temp = key.split("_")
        if (temp[0] == caller) and (temp[1] == callsite) and (temp[3] == func_sign):
            if addr == "":
                addr = temp[2]
                level = contracts[key].level
            else:
                if contracts[key].level > level:
                    addr = temp[2]
                    level = contracts[key].level
    return addr


def new_pp(caller, callsite, contract_addr, func_sign, index, type):
    addr = find_executed_pp(caller, callsite, contract_addr, func_sign)
    return {'caller': caller, 'callsite': callsite, 'contract_addr': addr, 'func_sign': func_sign, 'index': index, 'type': type}  

def is_same(pp1, pp2):
    pp1_str = pp1["caller"] + "_" + pp1["callsite"] + "_" + pp1["func_sign"] + "_" + str(pp1["index"]) + "_" + pp1["type"]
    pp2_str = pp2["caller"] + "_" + pp2["callsite"] + "_" + pp2["func_sign"] + "_" + str(pp2["index"]) + "_" + pp2["type"]
    if pp1_str == pp2_str:
        return True
    else:
        return False

def find_parent(logic_addr, funcSign, caller, call_site):
    for key in contracts.keys():
        for external_call in contracts[key].external_calls:
            if (external_call["logic_addr"] == logic_addr) and (external_call["funcSign"] == funcSign) and (external_call["caller"] == caller) and (external_call["call_site"] == call_site):
                return contracts[key]
    return None

def find_contract(caller, callsite, contract_addr, func_sign):
    return contracts[caller + "_" + callsite + "_" + contract_addr + "_" + func_sign]

def get_external_call_info(call_site, external_calls):
    for external_call in external_calls:
        if external_call["call_site"] == call_site:
            return external_call["caller"], external_call["logic_addr"], external_call["funcSign"]
    return 

# 过程内分析
def intraprocedural_analysis():
    for key in contracts.keys():
        temp_address = key.split("_")[2]
        temp_funcSign = key.split("_")[3]
        loc = "./gigahorse-toolchain/.temp/" + temp_address + "/out/FLA_TaintedVarToSensitiveVar.csv"
        if os.path.exists(loc) and (os.path.getsize(loc) > 0):
            df = pd.read_csv(loc, header=None, sep='	')
            df.columns = ["funcSign", "taintedVar", "sensitiveVar"]
            df = df.loc[df["funcSign"] == temp_funcSign]
            if len(df) != 0:
                return True
    return False

# source
def get_func_rets_flow_from_sources(contract_addr, func_sign):
    loc = "./gigahorse-toolchain/.temp/" + contract_addr + "/out/FLA_TaintedFuncRet.csv"
    if os.path.exists(loc) and (os.path.getsize(loc) > 0):
        df = pd.read_csv(loc, header=None, sep='	')
        df.columns = ["funcSign", "retIndex", "ret"]
        df = df.loc[df["funcSign"] == func_sign]
        if len(df) != 0:
            return list(df["retIndex"])
        else:
            return []
    else:
        return []

def get_call_args_flow_from_sources(contract_addr, func_sign):
    call_args = []
    loc = "./gigahorse-toolchain/.temp/" + contract_addr + "/out/FLA_TaintedCallArg.csv"
    if os.path.exists(loc) and (os.path.getsize(loc) > 0):
        df = pd.read_csv(loc, header=None, sep='	')
        df.columns = ["funcSign", "callStmt", "callArgIndex"]
        df = df.loc[df["funcSign"] == func_sign]
        for i in range(len(df)):
            call_args.append({"callStmt": df.iloc[i]["callStmt"], "callArgIndex": df.iloc[i]["callArgIndex"]})
    return call_args

def get_pps_near_source():
    pps_near_source = []
    for key in contracts.keys():
        temp_caller = key.split("_")[0]
        temp_callsite = key.split("_")[1]
        temp_address = key.split("_")[2]
        temp_funcSign = key.split("_")[3]

        temp_indexes = get_func_rets_flow_from_sources(temp_address, temp_funcSign)
        if len(temp_indexes) > 0:
            for temp_index in temp_indexes:
                pps_near_source.append(new_pp(temp_caller, temp_callsite, temp_address, temp_funcSign, temp_index, "func_ret"))
        
        temp_call_args = get_call_args_flow_from_sources(temp_address, temp_funcSign)
        if len(temp_call_args) > 0:
            for temp_call_arg in temp_call_args:
                temp_external_call_caller, temp_external_call_logic_addr, temp_external_call_func_sign = get_external_call_info(temp_call_arg["callStmt"], contracts[key].external_calls)
                pps_near_source.append(new_pp(temp_external_call_caller, temp_call_arg["callStmt"], temp_external_call_logic_addr, temp_external_call_func_sign, temp_call_arg["callArgIndex"], "call_arg"))
    return pps_near_source

# sink
def get_callsites_flow_to_sink(contract_addr, func_sign):
    callsites = []
    loc = "./gigahorse-toolchain/.temp/" + contract_addr + "/out/FLA_CallRetToSensitiveVar.csv"
    if os.path.exists(loc) and (os.path.getsize(loc) > 0):
        df = pd.read_csv(loc, header=None, sep='	')
        df.columns = ["funcSign", "callStmt", "callRetVar", "callRetIndex", "sensitiveVar"]
        df = df.loc[df["funcSign"] == func_sign]
        for i in range(len(df)):
            callsites.append({"callStmt": df.iloc[i]["callStmt"], "callRetIndex": df.iloc[i]["callRetIndex"]})
    return callsites

def get_pps_near_sink():
    pps_near_sink = []
    for key in contracts.keys():
        temp_caller = key.split("_")[0]
        temp_callsite = key.split("_")[1]
        temp_address = key.split("_")[2]
        temp_funcSign = key.split("_")[3]

        temp_callsites = get_callsites_flow_to_sink(temp_address, temp_funcSign)
        if len(temp_callsites) > 0:
            for temp_cs in temp_callsites:
                temp_external_call_caller, temp_external_call_contract_addr, temp_external_call_func_sign = get_external_call_info(temp_cs["callStmt"], contracts[key].external_calls)
                pps_near_sink.append(new_pp(temp_external_call_caller, temp_cs["callStmt"], temp_external_call_contract_addr, temp_external_call_func_sign, temp_cs["callRetIndex"], "func_ret"))
    return pps_near_sink

# spread
def spread_callRet_funcRet(contract_addr, call_stmt, func_sign, ret_index):
    loc = "./gigahorse-toolchain/.temp/" + contract_addr + "/out/FLA_Spread_CallRetToFuncRet.csv"
    if os.path.exists(loc) and (os.path.getsize(loc) > 0):
        df = pd.read_csv(loc, header=None, sep='	')
        df.columns = ["callStmt", "callRet", "callRetIndex", "funcSign", "funcRetIndex", "funcRet"]
        df = df.loc[(df["callStmt"] == call_stmt) & (df["callRetIndex"] == ret_index) & (df["funcSign"] == func_sign)]
        if len(df) != 0:
            return list(df["funcRetIndex"])
        else:
            return []
    else:
        return []

def spread_callRet_CallArg(contract_addr, call_stmt, ret_index):
    callArgs = []
    loc = "./gigahorse-toolchain/.temp/" + contract_addr + "/out/FLA_Spread_CallRetToCallArg.csv"
    if os.path.exists(loc) and (os.path.getsize(loc) > 0):
        df = pd.read_csv(loc, header=None, sep='	')
        df.columns = ["callStmt1", "callRet", "callRetIndex", "callStmt2", "callArgIndex", "callArg"]
        df = df.loc[(df["callStmt1"] == call_stmt) & (df["callRetIndex"] == ret_index)]
        for i in range(len(df)):
            callArgs.append({"callStmt": df.iloc[i]["callStmt2"], "callArgIndex": df.iloc[i]["callArgIndex"]})
    return callArgs

def spread_funcArg_callArg(contract_addr, funcSign, funcArgIndex):
    callArgs = []
    loc = "./gigahorse-toolchain/.temp/" + contract_addr + "/out/FLA_Spread_FuncArgToCallArg.csv"
    if os.path.exists(loc) and (os.path.getsize(loc) > 0):
        df = pd.read_csv(loc, header=None, sep='	')
        df.columns = ["funcSign", "funcArgIndex", "funcArg", "callStmt", "callArgIndex", "callArg"]
        df = df.loc[(df["funcSign"] == funcSign) & (df["funcArgIndex"] == funcArgIndex)]
        for i in range(len(df)):
            callArgs.append({"callStmt": df.iloc[i]["callStmt"], "callArgIndex": df.iloc[i]["callArgIndex"]})
    return callArgs

def spread_funcArg_funcRet(contract_addr, funcSign, funcArgIndex):
    loc = "./gigahorse-toolchain/.temp/" + contract_addr + "/out/FLA_Spread_FuncArgToFuncRet.csv"
    if os.path.exists(loc) and (os.path.getsize(loc) > 0):
        df = pd.read_csv(loc, header=None, sep='	')
        df.columns = ["funcSign", "funcArgIndex", "funcArg", "funcRetIndex", "funcRet"]
        df = df.loc[(df["funcSign"] == funcSign) & (df["funcArgIndex"] == funcArgIndex)]
        if len(df) != 0:
            return list(df["funcRetIndex"])
        else:
            return []
    else:
        return []
    
def transfer(pp):
    next_pps = []
    parent_contract = find_parent(pp["contract_addr"], pp["func_sign"], pp["caller"], pp["callsite"])
    try:
        child_contract = find_contract(pp["caller"],pp["callsite"], pp["contract_addr"], pp["func_sign"])
    except:
        return next_pps

    if pp["type"] == "func_ret":
        if parent_contract != None:
            indexes = spread_callRet_funcRet(pp["caller"], pp["callsite"], parent_contract.func_sign, pp["index"])
            for index in indexes:
                next_pps.append(new_pp(parent_contract.caller, parent_contract.call_site, parent_contract.logic_addr, parent_contract.func_sign, index, "func_ret"))

        callArgs = spread_callRet_CallArg(pp["contract_addr"], pp["callsite"], pp["index"])
        for callArg in callArgs:
            temp_caller, temp_logic_addr, temp_func_sign = get_external_call_info(callArg["callStmt"], child_contract.external_calls)
            next_pps.append(new_pp(temp_caller, callArg["callStmt"], temp_logic_addr, temp_func_sign, str(callArg["callArgIndex"]), "call_arg"))
        
    if pp["type"] == "call_arg":
        callArgs = spread_funcArg_callArg(pp["contract_addr"], pp["func_sign"], pp["index"])
        for callArg in callArgs:
            temp_result = get_external_call_info(callArg["callStmt"], child_contract.external_calls)
            if temp_result != None:
                temp_caller, temp_logic_addr, temp_func_sign = temp_result
            else:
                continue
            next_pps.append(new_pp(pp["contract_addr"], callArg["callStmt"], temp_logic_addr, temp_func_sign, str(callArg["callArgIndex"]), "call_arg"))
        
        indexes = spread_funcArg_funcRet(pp["contract_addr"], pp["func_sign"], pp["index"])
        for index in indexes:
            next_pps.append(new_pp(pp["caller"], pp["callsite"], pp["contract_addr"], pp["func_sign"], index, "func_ret"))
    return next_pps

def is_reachable(pp1, pp2):
    if is_same(pp1, pp2):
        return True
    pending = [pp1]
    while len(pending) > 0:
        temp_pp = pending.pop()
        for pp in transfer(temp_pp):
            if is_same(pp, pp2):
                return True
            else:
                pending.append(pp)
    return False

def detect():
    if len(contracts) == 0:
        return False
    if intraprocedural_analysis():
        return True

    pps_near_source = get_pps_near_source()
    pps_near_sink = get_pps_near_sink()
    result = False
    for pp1 in pps_near_source:
        for pp2 in pps_near_sink:
            if is_same(pp1, pp2):
                result = True
            elif is_reachable(pp1, pp2):
                result = True
    return result

def print_call_graph(source):
    call_graph = []
    pending = [{"child": "" + "_" + "" + "_" + source["logic_addr"] + "_" + source["func_sign"], "parent":""}]

    while len(pending) > 0:
        temp = pending.pop()
        temp_key = temp["child"]
        temp_contract = contracts[temp_key]
        temp_str = "    "*temp_contract.level + "_" + temp_key

        for external_call in temp_contract.external_calls :
            if external_call["logic_addr"] != "" and external_call["storage_addr"] != "" and external_call["funcSign"] != "" :
                pending.append({"child": external_call["caller"] + "_" + external_call["call_site"] + "_" + external_call["logic_addr"] + "_" + external_call["funcSign"], "parent": temp_str})
        if temp["parent"] != "":
            temp_index = call_graph.index(temp["parent"])
            call_graph = call_graph[:temp_index + 1] + [temp_str] + call_graph[temp_index + 1:]
        else:
            call_graph = [temp_str] + call_graph

    for line in call_graph:
        temp = line.split("_")
        print(temp[0] + temp[3] + "_" + temp[4])


# Main Body
parser = argparse.ArgumentParser()
parser.add_argument("-bp",
                    "--blockchain_platform",
                    help="The blockchain platform where the test contract is deployed",
                    action="store", 
                    dest="platform", 
                    type=str)
parser.add_argument("-la",
                    "--logic_address",
                    help="Contract address for storing business logic",
                    action="store", 
                    dest="logic_addr", 
                    type=str)
parser.add_argument("-sa",
                    "--storage_address",
                    help="Contract address for storing business data",
                    action="store", 
                    dest="storage_addr", 
                    type=str)
parser.add_argument("-fs",
                    "--function_signature",
                    help="The function signature to be tested",
                    action="store", 
                    dest="func_sign", 
                    type=str)
parser.add_argument("-bn",
                    "--block_number",
                    help="Blockchain snapshot",
                    action="store", 
                    dest="block_number", 
                    type=int)
args = parser.parse_args()

contracts = {}
construct_cross_contract_call_graph({
    "platform": args.platform,
    "logic_addr": args.logic_addr,
    "storage_addr": args.storage_addr,
    "func_sign": args.func_sign,
    "block_number": args.block_number,
    "caller": "",
    "call_site": "",
    "level": 0
})
result = detect()
print(result)
sys.exit(1)
