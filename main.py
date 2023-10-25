from utility import *
from fastapi import FastAPI, UploadFile, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
import uvicorn

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
app.mount("/public", StaticFiles(directory="public"), name="static")

@app.get("/")
def read_root(request: Request):
    context = {"request": request}
    return templates.TemplateResponse("index.html", context)

@app.post("/file")
def add_file(file: UploadFile):
    return save_file_api_response(actual_dir, file)

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

@app.get("/radare2")
def flare_file(data : str):
    json_data = radare2_api_response(actual_dir, base64.b64decode(data).decode())
    return json_data

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=7071)