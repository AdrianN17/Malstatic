import subprocess
import json

def flare_api_response(dir, path):
    command1 = f'floss -j -q "{path} "'
    command2 = f'capa -r capa-rules-4.0.0 -s sigs -j -q "{path} "'
    command3 = f' {dir}/manalyze_x64/manalyze --dump=all --hashes --output json "{path} "'
    
    print(command3)
    
    output = {"floss" : "", "capa" : "", "manalyze" : ""}

    try:
        output["floss"] = subprocess.check_output(command1, shell=True, text=True)
        output["capa"] = subprocess.check_output(command2, shell=True, text=True)
        output["manalyze"] = subprocess.check_output(command3, shell=True, text=True)
        
        output["floss"] = json.loads(output["floss"])
        output["capa"] = json.loads(output["capa"])
        output["manalyze"] = json.loads(output["manalyze"])
        
    except subprocess.CalledProcessError as e:
        print(f"Error al ejecutar los scripts: {e}")
        
    return output
