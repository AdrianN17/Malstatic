import subprocess
import json
import r2pipe
import base64 
import os

def floss_api_response(path):
    command1 = f'floss -j -q "{path}"'
    
    print(command1)
    
    output = {"floss" : ""}

    try:
        output["floss"] = subprocess.check_output(command1, shell=True, text=True)
        
        output["floss"] = json.loads(output["floss"])
        
    except subprocess.CalledProcessError as e:
        print(f"Error with script : {e}")
        
    return output

def capa_api_response(path):
    command2 = f'capa -r /capa/rules -s /capa/sigs -j -q "{path}"'
    
    print(command2)
    
    output = {"capa" : ""}

    try:
        output["capa"] = subprocess.check_output(command2, shell=True, text=True)
        
        output["capa"] = json.loads(output["capa"])
        
    except subprocess.CalledProcessError as e:
        print(f"Error with script : {e}")
        
    return output

def manalyze_api_response(path):
    command3 = f'manalyze --dump=all --hashes --output json "{path}"'
    
    print(command3)
    
    output = {"manalyze" : ""}

    try:
        output["manalyze"] = subprocess.check_output(command3, shell=True, text=True)
        
        output["manalyze"] = json.loads(output["manalyze"])
        
    except subprocess.CalledProcessError as e:
        print(f"Error with script : {e}")
        
    return output

def radare2_api_response(path):
    
    r2 = r2pipe.open(path)
    asm = r2.cmd("pd")
    r2.quit()
    
    return {"filename" : os.path.basename(path), "radare2" : (base64.b64encode(asm.encode()).decode())}

def save_file_api_response(actual_dir, file):
    file_path = ""
    
    tmp_dir = os.path.join(actual_dir, "tmp")

    if not os.path.exists(tmp_dir):
        os.makedirs(tmp_dir)

    file_path = os.path.join(tmp_dir, file.filename)

    with open(file_path, "wb") as temp_file:
        temp_file.write(file.file.read())
        
    file_name = os.path.basename(file_path)
        
    if(len(file_path) != 0):
        return {"status": 201 , "message" : "PE file uploaded", "data" : (base64.b64encode(file_name.encode()).decode())}
    else:
        return {"status": 400 , "message" : "Bad Request"}
    
    