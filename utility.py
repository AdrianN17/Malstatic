import subprocess
import json

def floss_api_response(dir, path):
    command1 = f'floss -j -q "{path} "'
    
    print(command1)
    
    output = {"floss" : ""}

    try:
        output["floss"] = subprocess.check_output(command1, shell=True, text=True)
        
        output["floss"] = json.loads(output["floss"])
        
    except subprocess.CalledProcessError as e:
        print(f"Error with script : {e}")
        
    return output

def capa_api_response(dir, path):
    command2 = f'capa -r capa-rules-4.0.0 -s sigs -j -q "{path} "'
    
    print(command2)
    
    output = {"capa" : ""}

    try:
        output["capa"] = subprocess.check_output(command2, shell=True, text=True)
        
        output["capa"] = json.loads(output["capa"])
        
    except subprocess.CalledProcessError as e:
        print(f"Error with script : {e}")
        
    return output

def manalyze_api_response(dir, path):
    command3 = f' {dir}/manalyze_x64/manalyze --dump=all --hashes --output json "{path} "'
    
    print(command3)
    
    output = {"manalyze" : ""}

    try:
        output["manalyze"] = subprocess.check_output(command3, shell=True, text=True)
        
        output["manalyze"] = json.loads(output["manalyze"])
        
    except subprocess.CalledProcessError as e:
        print(f"Error with script : {e}")
        
    return output