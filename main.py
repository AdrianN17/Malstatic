from utility import *
from fastapi import FastAPI, UploadFile, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.templating import Jinja2Templates
import uvicorn
import base64 
import os

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

actual_dir = os.path.dirname(os.path.abspath(__file__))

templates = Jinja2Templates(directory="public")

@app.get("/")
def read_root(request: Request):
    context = {"request": request}
    return templates.TemplateResponse("index.html", context)

@app.post("/file")
def add_file(file: UploadFile):
    file_path = ""
    
    tmp_dir = os.path.join(actual_dir, "tmp")

    if not os.path.exists(tmp_dir):
        os.makedirs(tmp_dir)

    file_path = os.path.join(tmp_dir, file.filename)

    with open(file_path, "wb") as temp_file:
        temp_file.write(file.file.read())
        
    if(len(file_path) != 0):
        return {"status": 201 , "message" : "PE file uploaded", "data" : (base64.b64encode(file_path.encode()).decode())}
    else:
        return {"status": 400 , "message" : "Bad Request"}

@app.get("/capa")
def floss_file(data : str):
    json_data = capa_api_response(actual_dir, base64.b64decode(data).decode())
    return json_data

@app.get("/floss")
def floss_file(data : str):
    json_data = floss_api_response(actual_dir, base64.b64decode(data).decode())
    return json_data

@app.get("/manalyze")
def flare_file(data : str):
    json_data = manalyze_api_response(actual_dir, base64.b64decode(data).decode())
    return json_data

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)