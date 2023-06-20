import asyncio
from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import io
import json
import random
import smtplib
import uuid

import zlib
from typing import Annotated
import uvicorn


from fastapi import Depends, FastAPI, HTTPException, Header, Request, UploadFile, status
from fastapi.staticfiles import StaticFiles
from fastapi.security import OAuth2PasswordBearer
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, StreamingResponse
from fastapi.encoders import jsonable_encoder
from motor.motor_asyncio import AsyncIOMotorClient
from passlib.hash import argon2


from pydantic import BaseModel
from starlette.responses import FileResponse 
from dotenv import dotenv_values
from slowapi.errors import RateLimitExceeded
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from string import ascii_letters, digits


limiter = Limiter(key_func=get_remote_address)

ENV = dotenv_values("config.env")

db_client: AsyncIOMotorClient = AsyncIOMotorClient(ENV["MONGO_URI"], username=ENV["DB_USER"], password=ENV["DB_PASS"])
db = db_client['jpggay']

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")
routes_with_custom_exception = ['/upload']


app = FastAPI(openapi_url=None)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
NOT_FOUND = HTTPException(404, "Not Found")



async def auth_admin(auth: str):
    username = await db.get_collection("users").find_one({"username": "clxud"})

    if not username["auth"] == auth:
        return False
    
    return True
    

async def get_image(file, mimetype):
    decompressed = await asyncio.get_running_loop().run_in_executor(
        None,
        decompress_image,
        file
    )

    return StreamingResponse(io.BytesIO(decompressed), media_type=mimetype)

def compress_image(image: bytes) -> bytes:
    return zlib.compress(image, 9).hex()

def decompress_image(hex: str) -> bytes:
    return zlib.decompress(bytes.fromhex(hex))


def send_auth_email(username: str, email: str, auth: str) -> None:
    # use icloud mail server to send email
    msg = MIMEMultipart()
    msg['From'] = "daemon@jpg.gay"
    msg['To'] = email
    msg['Subject'] = 'Your jpg.gay authentification code'
    message = f'''
    <!DOCTYPE html>
        <html lang="en">
        <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Email Template</title>
        <style>
            body {{
                font-family: Arial, Helvetica, sans-serif; 
            }}
        </style>
        </head>
        <body>
        <table style="width: 100%; max-width: 600px; margin: 0 auto; padding: 20px;">
            <tr>
            <td style="text-align: center;">
                <h1 style="color: #333333;">jpg.gay</h1>
            </td>
            </tr>
            <tr>
            <td>
                <p style="color: #666666;">Hello, <code><b>{username}</b></code></p>
                <p style="color: #666666;">Thank you for signing up with <a href="http://jpg.gay">jpg.gay</a>, the gayest image uploader.</p>
                <p style="color: #666666;">Your authentication code is <code><b>{auth}</b></code></p>
                <p style="color: #666666;"><b>Keep this in a safe place.</b> You'll use this to access our services.</p>
                <p style="color: #666666;">To upload using our services, make a request to the following endpoint below</p>
                <br>
                <p style="color: #666666;">Endpoint: <code><b>https://jpg.gay/upload</b></code></p>
                <p style="color: #666666;">Headers: <code><b>{{'token': '{auth}'}}</b></code></p>
                <p style="color: #666666;">Method: <code><b>POST</b></code></p>
                <p style="color: #666666;">Request Body: <code><b>&lt;your file&gt;</b></code></p>
                <br>
                <p style="color: #666666;">A ShareX config has been attached for your convenience.</p>
                <br>
                <p style="color: #666666;">If you didn't sign up for an account and you are receiving this email, please contact us and we'll get it sorted out.</p>
                <p style="color: #666666;">- jpg.gay team</p>
            </td>
            </tr>
        </table>
        </body>
        </html>

    '''

    # make a stringio object to send the email
    f = io.StringIO()
    f.write(
    f'''
    {{
        "Version": "15.0.0",
        "Name": "test",
        "DestinationType": "ImageUploader",
        "RequestMethod": "POST",
        "RequestURL": "https://jpg.gay/upload",
        "Headers": {{
            "token": "{auth}"
        }},
        "Body": "MultipartFormData",
        "Arguments": {{
            "data": null
        }},
        "FileFormName": "file",
        "URL": "{{json:.resource}}",
        "DeletionURL": "{{json:.delete}}",
        "ErrorMessage": "{{response}}"
    }}
    '''
    )

    
    
    msg.attach(MIMEText(message, 'html'))

    f.seek(0)
    attachment = MIMEBase("application", "octet-stream")
    attachment.set_payload(f.read())
    attachment.add_header("Content-Disposition", f"attachment; filename=jpggay-{username}.sxcu")
    msg.attach(attachment)
    
    mailserver = smtplib.SMTP('smtp.mail.me.com', 587)
    mailserver.ehlo()
    mailserver.starttls()
    mailserver.ehlo()
    mailserver.login(ENV["SMTP_EMAIL"], ENV["SMTP_PASSWORD"])
    mailserver.sendmail("daemon@jpg.gay", email, msg.as_bytes())
    mailserver.quit()

class RegisterBody(BaseModel):
    email: str
    username: str
    password: str
    invite_code: str


class LoginBody(BaseModel):
    username: str
    password: str

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    if request.url.path in routes_with_custom_exception:
        # check whether the error relates to the `some_custom_header` parameter
        for err in exc.errors():
            if err['loc'][0] == 'header' and err['loc'][1] == 'token':
                return JSONResponse(content={'401': 'Token header missing'}, status_code=401)
            
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content=jsonable_encoder({'detail': exc.errors(), 'body': exc.body}),
    )



app.mount("/public", StaticFiles(directory="public"), name="public")
app.mount("/gateway", StaticFiles(directory="gateway"), name="gateway")
app.mount("/admin", StaticFiles(directory="admin"), name="admin")

@app.get("/")
async def read_index():
    return FileResponse('public/index.html')

@app.get("/gateway")
async def admin():
    return FileResponse('gateway/index.html')

@app.post("/admin")
async def admin(body: LoginBody):
    if not body.username or not body.password:
        raise HTTPException(400, "Bad Request")
    
    username = await db.get_collection("users").find_one({"username": body.username})

    if body.username != "clxud":
        raise HTTPException(401, "Unauthorized")
    
    hash = username["password"]

    if not argon2.verify(body.password, hash):
        raise HTTPException(401, "Unauthorized")

    return {"token": username["auth"]}

@app.get("/panel")
async def admin_panel(auth: str):
    if not auth:
        raise HTTPException(400, "Bad Request")
    
    if not await auth_admin(auth):
        raise HTTPException(401, "Unauthorized")

    return FileResponse('admin/index.html')

@app.post("/get_random_code")
async def get_random_code(auth: Annotated[str | None, Header()]):
    if not auth:
        raise HTTPException(400, "Bad Request")
    
    if not await auth_admin(auth):
        raise HTTPException(401, "Unauthorized")
    
    codes = await db.get_collection("invites").find({}).to_list(length=None)

    return {"code": random.choice(codes)["code"]}


@app.post("/gen_random_code")
async def gen_random_code(auth: Annotated[str | None, Header()]):
    if not auth:
        raise HTTPException(400, "Bad Request")
    
    if not await auth_admin(auth):
        raise HTTPException(401, "Unauthorized")
    
    code = uuid.uuid4()

    await db.get_collection("invites").insert_one({"code": f"{code}"})

    return {"code": f"{code}"}

@app.delete("/delete_account")
async def delete_account(auth: Annotated[str | None, Header()], email: str):
    if not auth:
        raise HTTPException(400, "Bad Request")
    
    if not await auth_admin(auth):
        raise HTTPException(401, "Unauthorized")
    
    user = await db.get_collection("users").find_one({"email": email})

    if not user:
        raise HTTPException(404, "User not found")
    
    await db.get_collection("users").delete_one({"email": email})

    await db.get_collection("files").delete_many({"uploader": user["username"]})

    return 204


@app.post("/upload")
async def upload(token: Annotated[str | None, Header()], file: UploadFile):
    username = await db.get_collection("users").find_one({"auth": token})

    if not username:
        raise HTTPException(401, "Invalid token provided")

    if username["username"] != "clxud":
        if file.size >= 8388608:
            raise HTTPException(413, "File size exceeds 8MB")
    
        with open("mime.json", "r", encoding="utf-8") as f:
            mime_types: dict = json.load(f)

        if file.content_type not in mime_types.values():
            raise HTTPException(415, "Unsupported media type")

    file_id = "".join(random.choice(ascii_letters + digits) for _ in range(16))

    compressed = await asyncio.get_running_loop().run_in_executor(
        None,
        compress_image,
        file.file.read()
    )

    await db.get_collection("files").insert_one({
         "id": file_id,
         "uploader": username['username'],
         "mimetype": file.content_type,
         "file": compressed
    })

    return {"resource": f"https://jpg.gay/{file_id}", "delete": f"https://jpg.gay/delete/{file_id}"}


@app.delete("/delete/{file_id}")
async def delete(token: Annotated[str | None, Header()], file_id: str):
    username = await db.get_collection("users").find_one({"auth": token})

    if not username:
        raise HTTPException(401, "Invalid token provided")
    
    file = await db.get_collection("files").find_one({"id": file_id})

    if not file:
        raise HTTPException(404, "File not found")
    
    if file["uploader"] != username["username"]:
        raise HTTPException(401, "Unauthorized")
    
    await db.get_collection("files").delete_one({"id": file_id})

    return 204



@app.post("/get_auth_token")
async def get_auth_token(body: LoginBody):
    username = await db.get_collection("users").find_one({"username": body.username})

    if username is None:
        raise HTTPException(401, "Unauthorized")
    
    hash = username["password"]

    if not argon2.verify(body.password, hash):
        raise HTTPException(401, "Unauthorized")

    return {"token": username["auth"]}


@app.post("/login")
@limiter.limit("5/minute")
async def login(request: Request, body: LoginBody):
    username = await db.get_collection("users").find_one({"username": body.username})

    if username is None:
        raise HTTPException(401, "Unauthorized")
    
    hash = username["password"]

    if not argon2.verify(body.password, hash):
        raise HTTPException(401, "Unauthorized")

    return 200


@app.post("/register")
@limiter.limit("15/minute")
async def register(request: Request, body: RegisterBody):

    invite = await db.get_collection("invites").find_one({"code": body.invite_code})

    if invite is None:
        raise HTTPException(403, "Invalid invite code. Please contact an admin for an invite code.")
    
    # check if username is taken
    username = await db.get_collection("users").find_one({"username": body.username})

    if username:
        raise HTTPException(409, "Username already in use.")
    
    # check if email is taken

    email = await db.get_collection("users").find_one({"email": body.email})

    if email:
        raise HTTPException(401, "Email already in use.")
    
    hashed = argon2.hash(body.password)

    auth = f"jpggay-{body.username}-{''.join(random.choice(ascii_letters + digits) for _ in range(16))}"

    await db.get_collection("users").insert_one({
        "username": body.username,
        "email": body.email,
        "password": hashed,
        "auth": auth,
    })

    await db.get_collection("invites").delete_one({"code": body.invite_code})

    # run function in executor to not block event loop
    await asyncio.get_running_loop().run_in_executor(
        None,
        send_auth_email,
        body.username,
        body.email,
        auth,
    )

    return 200

@app.post("/images")
async def get_images(body: LoginBody):
    username = await db.get_collection("users").find_one({"username": body.username})

    if username is None:
        raise HTTPException(401, "Unauthorized")
    
    hash = username["password"]

    if not argon2.verify(body.password, hash):
        raise HTTPException(401, "Unauthorized")

    
    urls = []
    images = await db.get_collection("files").find({"uploader": body.username}).to_list(length=None)

    if not images:
        raise HTTPException(404, "No images found")

    for image in images:
        urls.append(image["id"])
    

    return {"urls": urls}

@app.get("/download/{file_id}")
async def download_file(file_id: str):
    file = await db.get_collection("files").find_one({"id": file_id})

    if file is None:
        raise HTTPException(404, "File not found")
    
    decompressed = await asyncio.get_running_loop().run_in_executor(
        None,
        decompress_image,
        file["file"]
    )
    
    return StreamingResponse(
        io.BytesIO(decompressed),
        media_type=file["mimetype"],
        headers={
            "Content-Disposition": f"attachment; filename={file_id}.{file['mimetype'].split('/')[1]}"
        }
    )

@app.get("/{file_id}")
async def fetch_file(file_id: str):
    file = await db.get_collection("files").find_one({"id": file_id})

    if file is None:
        raise HTTPException(404, "File not found")
    
    
    return await get_image(file["file"], file["mimetype"])


if __name__ == "__main__":
  uvicorn.run("server:app", port=6969, reload=True)
