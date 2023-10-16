from utility import flare_api_response
from fastapi import FastAPI, UploadFile
from fastapi.middleware.cors import CORSMiddleware
import os

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/flare")
def flare_name(path: str):
    return flare_api_response(path)

@app.post("/flare")
def flare_file(file: UploadFile):
    
    file_path = ""
    
    actual_dir = os.path.dirname(os.path.abspath(__file__))

    tmp_dir = os.path.join(actual_dir, "tmp")

    if not os.path.exists(tmp_dir):
        os.makedirs(tmp_dir)

    file_path = os.path.join(tmp_dir, file.filename)

    with open(file_path, "wb") as temp_file:
        temp_file.write(file.file.read())
        
    flare_json = flare_api_response(actual_dir, file_path)

    os.remove(file_path)

    return flare_json