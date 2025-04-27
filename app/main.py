from fastapi import FastAPI, Depends, HTTPException, status, UploadFile, File
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import jwt, JWTError
from datetime import datetime, timedelta
import pandas as pd
import os

SECRET_KEY = "supersecretkey123"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

app = FastAPI()

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

fake_user = {
    "username": "admin",
    "password": "Iwfm@CCM_2025"
}

def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta if expires_delta else timedelta(minutes=15))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

async def get_current_user(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=401, detail="Invalid token")
        return username
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

@app.post("/login")
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    if form_data.username != fake_user["username"] or form_data.password != fake_user["password"]:
        raise HTTPException(status_code=400, detail="Incorrect username or password")
    
    access_token = create_access_token(data={"sub": form_data.username})
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/cyclones")
async def list_cyclones():
    df = pd.read_csv("CycloneDataBase/Cyclone_List.csv")
    return df.to_dict(orient="records")

@app.post("/filter")
async def filter_cyclones(threshold: int):
    df = pd.read_csv("CycloneDataBase/Cyclone_List.csv")
    filtered = df[df["Total Number of Affected People"] > threshold]
    return filtered.to_dict(orient="records")

@app.post("/upload-cyclone")
async def upload_cyclone(file: UploadFile = File(...), current_user: str = Depends(get_current_user)):
    file_location = f"CycloneDataBase/NewUploads/{file.filename}"
    os.makedirs(os.path.dirname(file_location), exist_ok=True)
    with open(file_location, "wb+") as file_object:
        file_object.write(await file.read())
    return {"info": f"file '{file.filename}' saved successfully"}
