from fastapi import FastAPI, UploadFile, File, HTTPException, Depends, Header
from fastapi.responses import FileResponse
from pydantic import BaseModel
from sqlalchemy import create_engine, Column, String, Boolean, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
import os, uuid, shutil, base64

app = FastAPI()  #server

#<----DB---->
USERS = {}
FILES = {}

UPLOAD_DIR = os.path.join(os.getcwd(),'uploads')
os.makedirs(UPLOAD_DIR, exist_ok=True)

DB_URL = "mysql+pymysql://root:password@localhost:3306/fileshare"

engine = create_engine(DB_URL)

#local sessiomn for dbops
localSession = sessionmaker(bind = engine, autoflush= False, autocommit= False)

Base = declarative_base()  #ORM BAse

#<----Models---->
class User(Base):
    __tablename__ = "users"
    id = Column(String(64), primary_key=True, index=True)
    name = Column(String(128))
    email = Column(String(128), unique=True)
    pwd = Column(String(128))
    role = Column(String(32))
    is_verified = Column(Boolean, default=False)
    api_token = Column(String(128), unique = True)

class FileEntry(Base):
    __tablename__ = 'files'
    id = Column(String(64), primary_key=True, index = True)
    filename = Column(String(255))
    filepath = Column(String(255))
    uploaded_by = Column(String(64), ForeignKey("users.id"))

#Creating Tables
Base.metadata.create_all(bind = engine)

#<----Data Validation{Pydantic Schemas)---->
class SignupInput(BaseModel):
    name : str
    email : str
    pwd : str
    role : str

class LoginInput(BaseModel):
    email : str
    pwd : str


#<----Fetch DB Session---->
def get_db():
    db = localSession()
    try:
        yield db
    finally:
        db.close()

def generate_token():
    return str(uuid.uuid4())

def encrypt(text: str):
    return base64.urlsafe_b64encode(text.encode()).decode()

def decrypt(text: str):
    return base64.urlsafe_b64decode(text.encode()).decode()

def get_user_from_token(auth: str = Header(...), db: Session=Depends(get_db)):
    if not auth.startswith("Token "):
        raise HTTPException(status_code=401, detail="Header Inavlid")
    token = auth.split()[1]
    user = db.query(User).filter(User.api_token == token).first()
    if not user:
        raise HTTPException(status_code = 403, detail = "Token is invalid")
    return user

#<----Routes---->

#User signup
@app.post("/signup")
def signup(data: SignupInput, db: Session = Depends(get_db)):
    uid = str(uuid.uuid4()) #create new uid
    user = User(id = uid, name = data.name, email=data.email, pwd=data.pwd, role = data.role, )
    db.add(user)
    db.commit()
    encrypted = encrypt(uid)  #enc uid for verification link
    return {"encrypted_url" : f"/verify/{encrypted}"}

#Email Verification Link
@app.get("/verify/{token}")
def verify_email(token: str, db: Session = Depends(get_db)):
    try :
        uid = decrypt(token)
    except:
        raise HTTPException(status_code=400, detail="Token Invalid")
    user = db.query(User).filter(User.id == uid).first()
    if not user:
        raise HTTPException(status_code=404, detail = "USer not exists")
    user.is_verified = True
    db.commit()
    return {"message" : "email-verified"}

#User Login
@app.post("/login")
def user_login(data: LoginInput, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == data.email, User.pwd == data.pwd).first()
    if user:
        user.api_token = generate_token()
        db.commit()
        return {"api_token" : user.api_token}
    raise HTTPException(status_code = 401, detail = "Inavalid Creds")

#File Upload
@app.post("/upload")
def upload_file(file: UploadFile = File(...), user: User = Depends(get_user_from_token), db: Session = Depends(get_db)):
    if user.role != "ops":
        raise HTTPException(status_code=403, detail = "Only ops can upload")
    if not file.filename.endswith((".pptx", ".docx", ".xlsx")):
        raise HTTPException(status_code=400, detail = "invalid file type")
    file_id = str(uuid.uuid4())
    file_path = os.path.join(UPLOAD_DIR, file_id + "_" +file.filename)
    with open(file_path, 'wb') as f:
        shutil.copyfileobj(file.file,f)
    file_entry = FileEntry(id = file_id, filename = file_path, uploaded_by = user.id)
    db.add(file_entry)
    db.commit()
    return {"file_id" : file_id, "filename" : "file Uploaded"}

# Route: Generate secure download link for a file
@app.get("/download-link/{file_id}")
def get_download_link(file_id: str, user: User = Depends(get_user_from_token), db: Session = Depends(get_db)):
    if user.role != "client":
        raise HTTPException(status_code=403, detail="Only clients can download")
    file = db.query(FileEntry).filter(FileEntry.id == file_id).first()
    if not file:
        raise HTTPException(status_code=404, detail="File not found")
    encrypted = encrypt(f"{file_id}:{user.id}")  # Encode file ID and user ID
    return {"download_link": f"/download/{encrypted}"}

# Route: Download the actual file (secure)
@app.get("/download/{token}")
def download_file(token: str, user: User = Depends(get_user_from_token), db: Session = Depends(get_db)):
    try:
        file_id, user_id = decrypt(token).split(":")  # Decode link to get file ID and user ID
    except:
        raise HTTPException(status_code=400, detail="Invalid link")
    if user.id != user_id or user.role != "client":
        raise HTTPException(status_code=403, detail="Access denied")
    file = db.query(FileEntry).filter(FileEntry.id == file_id).first()
    if not file:
        raise HTTPException(status_code=404, detail="File not found")
    return FileResponse(file.filepath, filename=file.filename)  # Serve file to client
