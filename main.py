import json
import shutil

from fastapi import FastAPI, HTTPException, Depends, status,Query, WebSocket, WebSocketDisconnect
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel
from passlib.context import CryptContext
import psycopg2
import jwt
import base64
import os
from fastapi import FastAPI, UploadFile, File, Form, HTTPException
import subprocess
from datetime import datetime, timedelta
from typing import Optional,List  # ✅ Correct

from starlette.middleware.cors import CORSMiddleware
from starlette.responses import PlainTextResponse, FileResponse

app = FastAPI()

# Secret key for encoding and decoding JWTs (keep it safe)
SECRET_KEY = "your_secret_key"  # Change this to a strong, secret key!
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30  # You can adjust the expiry time here

# Password hashing context
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Database connection (change these as per your setup)
conn = psycopg2.connect(
    dbname="aura+",
    user="postgres",
    password="12345",
    host="localhost",      # Or your DB host
    port="5432"            # Default PostgreSQL port
)
cursor = conn.cursor()
def get_connection():
    return psycopg2.connect(
        dbname="aura+",
        user="postgres",
        password="12345",
        host="localhost",  # Or your DB host
        port="5432"
    )

# Request body schema
class UserCreate(BaseModel):
    username: str
    name: str
    password: str
    question1_answer: str
    question2_answer: str
    question3_answer: str
    question4_answer: str
    question5_answer: str

class MessageCreate(BaseModel):
    chat_id: int
    sender_id: int
    content: Optional[str] = None
    media_url: Optional[str] = None
    message_type: str = "text"

class ChatQuery(BaseModel):
    chat_id: int


class Usernames(BaseModel):
    username1: str
    username2: str

class UsernameRequest(BaseModel):
    username: str


    #Create the group and add the members in it
class GroupCreateRequest(BaseModel):
    group_name: str
    creator_username: str
    members: list[str]  # list of usernames (excluding creator)

class ContactQuery(BaseModel):
    username: str


class TypingUpdate(BaseModel):
    chat_id: int
    user_id: int
    is_typing: bool


 # === Pydantic Schemas ===
class MessageCreate(BaseModel):
    chat_id: int
    sender_id: int
    content: str
    media_url: str = ""
    message_type: str = "text"

class MessageOut(MessageCreate):
    id: int

# === WebSocket Manager ===

# === Pydantic model for incoming messages ===
class WebSocketMessage(BaseModel):
    chat_id: int
    sender_id: int
    content: str
    media_url: Optional[str] = ""
    message_type: str = "text"

# === Updated ConnectionManager with safe broadcast ===
class ConnectionManager:
    def __init__(self):
        self.active_connections: list[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast(self, message: str):
        for connection in self.active_connections.copy():  # Use copy to avoid list mutation issues
            try:
                await connection.send_text(message)
            except Exception as e:
                print(f"Error sending message: {e}")
                self.disconnect(connection)

manager = ConnectionManager()

# === Improved WebSocket Chat Endpoint ===
@app.websocket("/ws/chat")
async def websocket_chat(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            try:
                raw_data = await websocket.receive_text()
                data_dict = json.loads(raw_data)
                message = WebSocketMessage(**data_dict)  # Validate incoming data
            except Exception as e:
                await websocket.send_text(f"Invalid message format: {str(e)}")
                continue

            # Save to DB with timestamp
            try:
                cursor.execute("""
                    INSERT INTO messages (chat_id, sender_id, content, media_url, message_type, created_at)
                    VALUES (%s, %s, %s, %s, %s, NOW()) RETURNING id, created_at
                """, (
                    message.chat_id,
                    message.sender_id,
                    message.content,
                    message.media_url,
                    message.message_type
                ))
                new_id, created_at = cursor.fetchone()
                conn.commit()

                # ✅ Fetch the sender's username
                cursor.execute("SELECT username FROM users WHERE id = %s", (message.sender_id,))
                sender = cursor.fetchone()
                sender_username = sender[0] if sender else "unknown"

                full_message = {
                    "id": new_id,
                    "chat_id": message.chat_id,
                    "sender_id": message.sender_id,
                    "username": sender_username,  # 👈 Include username
                    "content": message.content,
                    "media_url": message.media_url,
                    "message_type": message.message_type,
                    "time_stamp": created_at.isoformat()
                }

                print(f"💬 Message received: {full_message}")
                await manager.broadcast(json.dumps(full_message))

            except Exception as e:
                conn.rollback()
                await websocket.send_text(f"DB Error: {str(e)}")

    except WebSocketDisconnect:
        manager.disconnect(websocket)
        await manager.broadcast(json.dumps({"info": "A user disconnected"}))

#websockets for web
class GroupWebSocketMessage(BaseModel):
    chat_id: int
    sender_id: int
    content: Optional[str] = None
    media_url: Optional[str] = None
    message_type: str  # e.g., "text", "image", "audio"

@app.websocket("/ws/group_chat")
async def websocket_group_chat(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            try:
                raw_data = await websocket.receive_text()
                data_dict = json.loads(raw_data)
                message = GroupWebSocketMessage(**data_dict)
            except Exception as e:
                await websocket.send_text(f"Invalid message format: {str(e)}")
                continue

            try:
                # Save the message to the database
                cursor.execute("""
                    INSERT INTO group_messages (group_id, sender_id, content, media_url, message_type, created_at)
                    VALUES (%s, %s, %s, %s, %s, NOW())
                    RETURNING id, created_at
                """, (
                    message.chat_id,
                    message.sender_id,
                    message.content,
                    message.media_url,
                    message.message_type
                ))
                new_id, created_at = cursor.fetchone()
                conn.commit()

                # Get sender username
                cursor.execute("SELECT username FROM users WHERE id = %s", (message.sender_id,))
                sender = cursor.fetchone()
                sender_username = sender[0] if sender else "unknown"

                full_message = {
                    "id": new_id,
                    "chat_id": message.chat_id,
                    "sender_id": message.sender_id,
                    "username": sender_username,
                    "content": message.content,
                    "media_url": message.media_url,
                    "message_type": message.message_type,
                    "time_stamp": created_at.isoformat()
                }

                print(f"📢 Group message received: {full_message}")
                await manager.broadcast(json.dumps(full_message))

            except Exception as e:
                conn.rollback()
                await websocket.send_text(f"DB Error: {str(e)}")

    except WebSocketDisconnect:
        manager.disconnect(websocket)
        await manager.broadcast(json.dumps({"info": "A group user disconnected"}))


#register the user in to the database
@app.post("/register")
def register_user(user: UserCreate):
    try:
        # Hash the password
        hashed_password = pwd_context.hash(user.password)

        # Insert into the database
        cursor.execute("""
            INSERT INTO users (
                username, hashed_password,name,
                question1_answer, question2_answer,
                question3_answer, question4_answer, question5_answer
            )
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        """, (
            user.username,
            hashed_password,
            user.name,
            user.question1_answer,
            user.question2_answer,
            user.question3_answer,
            user.question4_answer,
            user.question5_answer
        ))

        conn.commit()
        return {"message": "User registered successfully."}

    except psycopg2.IntegrityError:
        conn.rollback()
        raise HTTPException(status_code=400, detail="Username already exists.")

    except Exception as e:
        conn.rollback()
        raise HTTPException(status_code=500, detail=str(e))

#check for the umer name
# OAuth2PasswordBearer instance (used for extracting token from Authorization header)
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")


# Request body schema
class UserCreate(BaseModel):
    username: str
    password: str

class UserQuery(BaseModel):
    username: str
# Function to hash passwords
def hash_password(password: str):
    return pwd_context.hash(password)


# Function to verify the password
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


# Function to create JWT Token
def create_access_token(data: dict, expires_delta: timedelta = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)):
    to_encode = data.copy()
    expire = datetime.utcnow() + expires_delta
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


# Function to verify JWT token
def verify_token(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except jwt.PyJWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token or expired token.")


# Login Request Schema
class LoginRequest(BaseModel):
    username: str
    password: str


#forget password
class SecurityQuestionRequest(BaseModel):
    username: str
    question1_answer: str
    question2_answer: str
    question3_answer: str
    question4_answer: str
    question5_answer: str


####update the password
# Request body schema for password update
class PasswordUpdateRequest(BaseModel):
    username: str
    new_password: str


####Update the old password by taking the old password

# Request body schema for password update
class PasswordUpdateRequest(BaseModel):
    username: str
    old_password: str
    new_password: str

class ForgetUpdateRequest(BaseModel):
    username: str
    new_password: str

# Request model
class UserPhotoUpdate(BaseModel):
    username: str
    name: str
    profile_image: str  # base64-encoded image

#Update the Online Status of the user

class OnlineStatusUpdate(BaseModel):
    username: str
    is_online: bool

# Endpoint to check username and password and return JWT token
@app.post("/login")
def login(data: LoginRequest):
    cursor.execute("SELECT * FROM users WHERE username = %s", (data.username,))
    user = cursor.fetchone()

    if not user:
        raise HTTPException(status_code=404, detail="User not found.")

    hashed_password = user[2]  # Assuming the 3rd column is the hashed password

    if not verify_password(data.password, hashed_password):
        raise HTTPException(status_code=401, detail="Incorrect password.")

    # Generate JWT token
    access_token = create_access_token(data={"sub": data.username})

    return {"access_token": access_token, "token_type": "bearer"}


# Endpoint to get user profile (Protected)
@app.get("/profile")
def get_profile(token: str = Depends(oauth2_scheme)):
    # Verify the token and extract user info
    user_data = verify_token(token)
    username = user_data.get("sub")

    cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
    user = cursor.fetchone()

    if not user:
        raise HTTPException(status_code=404, detail="User not found.")

    # Exclude sensitive fields like the password
    user_data = {
        "id": user[0],
        "username": user[1],
        "name": user[11],
        "profile_image": base64.b64encode(user[5]).decode('utf-8') if user[5] else None,
        "question1_answer": user[6],
        "question2_answer": user[7],
        "question3_answer": user[8],
        "question4_answer": user[9],
        "question5_answer": user[10],
        "is_online": user[3],
        "created_at": user[4]
    }

    return {"user": user_data}


#checks for the user is available or not
@app.get("/check-username")
def check_username(username: str):
    try:
        cursor.execute("SELECT id FROM users WHERE username = %s", (username,))
        user = cursor.fetchone()
        if user:
            return {"available": False, "message": "Username is already taken."}
        else:
            return {"available": True, "message": "Username is available."}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))




# Endpoint to check answers to security questions
@app.post("/check_security_answers")
def check_security_answers(data: SecurityQuestionRequest):
    cursor.execute("SELECT * FROM users WHERE username = %s", (data.username,))
    user = cursor.fetchone()

    if not user:
        raise HTTPException(status_code=404, detail="User not found.")

    # Compare the answers to the stored answers
    is_correct = (
        user[6] == data.question1_answer and  # question1_answer stored at index 4
        user[7] == data.question2_answer and  # question2_answer stored at index 5
        user[8] == data.question3_answer and  # question3_answer stored at index 6
        user[9] == data.question4_answer and  # question4_answer stored at index 7
        user[10] == data.question5_answer      # question5_answer stored at index 8
    )

    if is_correct:
        return {"success": True, "message": "All answers are correct."}
    else:
        return {"success": False, "message": "One or more answers are incorrect."}



# Function to hash passwords
def hash_password(password: str):
    return pwd_context.hash(password)

# Endpoint to update password
@app.post("/forgetupdate_password")
def update_password(data: ForgetUpdateRequest):
    # Fetch the user by username
    cursor.execute("SELECT * FROM users WHERE username = %s", (data.username,))
    user = cursor.fetchone()

    if not user:
        raise HTTPException(status_code=404, detail="User not found.")

    # Hash the new password
    new_hashed_password = hash_password(data.new_password)

    # Update the password in the database
    cursor.execute(
        "UPDATE users SET hashed_password = %s WHERE username = %s",
        (new_hashed_password, data.username)
    )
    conn.commit()

    return {"success": True, "message": "Password updated successfully."}




# # Function to hash passwords
# def hash_password(password: str):
#     return pwd_context.hash(password)


# Function to verify the password
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


# Endpoint to update password
@app.post("/update_password")
def update_password(data: PasswordUpdateRequest):
    # Fetch the user by username
    cursor.execute("SELECT * FROM users WHERE username = %s", (data.username,))
    user = cursor.fetchone()

    if not user:
        raise HTTPException(status_code=404, detail="User not found.")

    # Get the stored hashed password (assuming it's stored in column 2)
    stored_hashed_password = user[2]

    # Verify the old password
    if not verify_password(data.old_password, stored_hashed_password):
        raise HTTPException(status_code=401, detail="Old password is incorrect.")

    # Hash the new password
    new_hashed_password = hash_password(data.new_password)

    # Update the password in the database
    cursor.execute(
        "UPDATE users SET hashed_password = %s WHERE username = %s",
        (new_hashed_password, data.username)
    )
    conn.commit()

    return {"success": True, "message": "Password updated successfully."}


####Update the name and the profile image



@app.post("/update-user-photo")
def update_user_photo(data: UserPhotoUpdate):
    try:
        # Decode the base64 image string to bytes
        try:
            image_bytes = base64.b64decode(data.profile_image)
        except Exception:
            raise HTTPException(status_code=400, detail="Invalid base64 image string.")

        # Update name and image in database
        cursor.execute("""
            UPDATE users
            SET name = %s,
                profile_image = %s
            WHERE username = %s
        """, (
            data.name,
            psycopg2.Binary(image_bytes),
            data.username
        ))

        if cursor.rowcount == 0:
            raise HTTPException(status_code=404, detail="User not found.")

        conn.commit()
        return {"message": "User name and picture updated successfully."}

    except HTTPException:
        raise
    except Exception as e:
        conn.rollback()
        raise HTTPException(status_code=500, detail=str(e))


#Feteching the picture from the database



@app.post("/get-user-photo")
def get_user_photo(data: UserQuery):
    try:
        cursor.execute("SELECT name, profile_image FROM users WHERE username = %s", (data.username,))
        result = cursor.fetchone()

        if result is None or result[1] is None:
            raise HTTPException(status_code=404, detail="User or image not found.")

        name = result[0]
        image_bytes = result[1]
        image_base64 = base64.b64encode(image_bytes).decode("utf-8")

        return {
            "username": data.username,
            "name": name,
            "profile_image": image_base64
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/update-online-status")
def update_online_status(data: OnlineStatusUpdate):
    try:
        cursor.execute("""
            UPDATE users
            SET is_online = %s
            WHERE username = %s
        """, (
            data.is_online,
            data.username
        ))

        if cursor.rowcount == 0:
            raise HTTPException(status_code=404, detail="User not found.")

        conn.commit()
        return {"message": f"User online status updated to {data.is_online}."}

    except HTTPException:
        raise
    except Exception as e:
        conn.rollback()
        raise HTTPException(status_code=500, detail=str(e))


#get the online status of the user
@app.post("/get-online-status")
def get_online_status(data: UserQuery):
    try:
        cursor.execute("SELECT is_online FROM users WHERE username = %s", (data.username,))
        result = cursor.fetchone()

        if result is None:
            raise HTTPException(status_code=404, detail="User not found.")

        return {"username": data.username, "is_online": result[0]}

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/user-messages")
def get_user_messages(username: str = Query(...)):
    try:
        # Step 1: Get user ID from username
        cursor.execute("SELECT id FROM users WHERE username = %s", (username,))
        user_row = cursor.fetchone()
        if not user_row:
            raise HTTPException(status_code=404, detail="User not found.")
        user_id = user_row[0]

        # Step 2: Get all chat IDs where the user is a participant
        cursor.execute("""
            SELECT id FROM chats
            WHERE user1_id = %s OR user2_id = %s
        """, (user_id, user_id))
        chat_ids = [row[0] for row in cursor.fetchall()]

        if not chat_ids:
            return {"messages": []}

        # Step 3: Get messages in those chats not sent by the current user
        format_ids = tuple(chat_ids) if len(chat_ids) > 1 else f"({chat_ids[0]})"
        cursor.execute(f"""
            SELECT messages.id, messages.chat_id, messages.content, messages.media_url,
                   messages.message_type, messages.created_at,
                   users.username as sender_username
            FROM messages
            JOIN users ON messages.sender_id = users.id
            WHERE messages.chat_id IN {format_ids}
            AND messages.sender_id != %s
            ORDER BY messages.created_at DESC
        """, (user_id,))

        messages = cursor.fetchall()

        result = []
        for msg in messages:
            result.append({
                "message_id": msg[0],
                "chat_id": msg[1],
                "content": msg[2],
                "media_url": msg[3],
                "message_type": msg[4],
                "timestamp": msg[5],
                "sender": msg[6]
            })

        return {"messages": result}

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


#Get all the users



@app.post("/get-users")
def get_contacts(data: ContactQuery):
    try:
        cursor.execute("""
            SELECT username, name, profile_image
            FROM users
            WHERE username != %s
        """, (data.username,))

        results = cursor.fetchall()

        users = []
        for row in results:
            username, name, profile_image = row
            image_base64 = base64.b64encode(profile_image).decode("utf-8") if profile_image else None

            users.append({
                "username": username,
                "name": name,
                "profile_image": image_base64
            })

        return {"users": users}

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))



@app.post("/create_or_get_chat")
def create_or_get_chat(data: Usernames):
    # ✅ Get user1 ID
    cursor.execute("SELECT id FROM users WHERE username = %s", (data.username1,))
    user1 = cursor.fetchone()
    if not user1:
        raise HTTPException(status_code=404, detail="Username 1 not found.")
    user1_id = user1[0]

    # ✅ Get user2 ID
    cursor.execute("SELECT id FROM users WHERE username = %s", (data.username2,))
    user2 = cursor.fetchone()
    if not user2:
        raise HTTPException(status_code=404, detail="Username 2 not found.")
    user2_id = user2[0]

    # ❌ Prevent same user chat
    if user1_id == user2_id:
        raise HTTPException(status_code=400, detail="Cannot create chat with the same user.")

    # 🔎 Check if chat already exists (in either direction)
    cursor.execute("""
        SELECT id FROM chats
        WHERE (user1_id = %s AND user2_id = %s)
           OR (user1_id = %s AND user2_id = %s)
    """, (user1_id, user2_id, user2_id, user1_id))
    chat = cursor.fetchone()

    if chat:
        return {"chat_id": chat[0], "status": "exists"}

    # 🆕 Create new chat
    created_at = datetime.utcnow()
    cursor.execute("""
        INSERT INTO chats (user1_id, user2_id, created_at)
        VALUES (%s, %s, %s)
        RETURNING id
    """, (user1_id, user2_id, created_at))
    new_chat_id = cursor.fetchone()[0]
    conn.commit()

    return {"chat_id": new_chat_id, "status": "created"}

#return the all chats of the user
from fastapi import Request

@app.post("/get_user_chats")
def get_user_chats(data: UsernameRequest, request: Request):
    try:
        # Step 1: Get user ID from username
        cursor.execute("SELECT id FROM users WHERE username = %s", (data.username,))
        user = cursor.fetchone()
        if not user:
            raise HTTPException(status_code=404, detail="Username not found.")
        user_id = user[0]

        # Step 2: Fetch all chats for the user
        cursor.execute("""
            SELECT id, user1_id, user2_id FROM chats
            WHERE user1_id = %s OR user2_id = %s
        """, (user_id, user_id))
        chats = cursor.fetchall()

        result = []

        for chat_id, user1_id, user2_id in chats:
            other_user_id = user2_id if user1_id == user_id else user1_id

            # Step 3: Get other user's details
            cursor.execute("""
                SELECT username, name, profile_image FROM users WHERE id = %s
            """, (other_user_id,))
            other_user = cursor.fetchone()
            if not other_user:
                continue

            other_username, name, profile_picture = other_user

            # Convert BYTEA to base64 string
            if profile_picture:
                picture_base64 = base64.b64encode(profile_picture).decode('utf-8')
                picture_data_url = f"data:image/png;base64,{picture_base64}"
            else:
                picture_data_url = None

            # Step 4: Get the last message (content + media check)
            cursor.execute("""
                SELECT content, media_url, created_at FROM messages
                WHERE chat_id = %s
                ORDER BY created_at DESC
                LIMIT 1
            """, (chat_id,))
            last_msg = cursor.fetchone()
            if last_msg:
                content, media_url, last_time = last_msg
                if content:
                    last_message = content
                elif media_url:
                    last_message = "Media"
                else:
                    last_message = None
            else:
                last_message, last_time = None, None

            # Step 5: Add to result list
            result.append({
                "chat_id": chat_id,
                "with_username": other_username,
                "name": name,
                "with_user_id": other_user_id,
                "profile_picture_base64": picture_data_url,
                "last_message": last_message,
                "last_message_time": last_time
            })

        return result

    except Exception as e:
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Internal Error: {str(e)}")

#get the user group

@app.post("/get_user_groups")
def get_user_groups(data: UsernameRequest):
    try:
        # Step 1: Get user ID
        cursor.execute("SELECT id FROM users WHERE username = %s", (data.username,))
        user = cursor.fetchone()
        if not user:
            raise HTTPException(status_code=404, detail="Username not found.")
        user_id = user[0]

        # Step 2: Get all group IDs where the user is a member or admin
        cursor.execute("""
            SELECT DISTINCT g.id, g.group_name, g.created_at
            FROM groups g
            LEFT JOIN group_members gm ON g.id = gm.group_id
            WHERE g.created_by = %s OR gm.user_id = %s
        """, (user_id, user_id))
        groups = cursor.fetchall()

        result = []

        for group_id, group_name, created_at in groups:
            # Step 3: Get the last message from this group
            cursor.execute("""
                SELECT content, media_url, created_at
                FROM group_messages
                WHERE group_id = %s
                ORDER BY created_at DESC
                LIMIT 1
            """, (group_id,))
            msg = cursor.fetchone()

            if msg:
                content, media_url, last_time = msg
                last_message = content if content else ("Media" if media_url else None)
            else:
                last_message, last_time = None, None

            result.append({
                "group_id": group_id,
                "group_name": group_name,
                "last_message": last_message,
                "last_time": last_time.isoformat() if last_time else None
            })

        return result

    except Exception as e:
        print("❌ Error in get_user_groups:", e)
        raise HTTPException(status_code=500, detail="Internal server error")

#create the group

@app.post("/create_group")
def create_group(data: GroupCreateRequest):
    # Total members (creator + selected) must be 3–6
    total_members = 1 + len(data.members)
    if not (3 <= total_members <= 6):
        raise HTTPException(status_code=400, detail="Group must have between 3 and 6 total members.")

    # Get creator ID
    cursor.execute("SELECT id FROM users WHERE username = %s", (data.creator_username,))
    creator = cursor.fetchone()
    if not creator:
        raise HTTPException(status_code=404, detail="Creator username not found.")
    creator_id = creator[0]

    # Validate and get all member IDs
    member_ids = []
    for username in data.members:
        cursor.execute("SELECT id FROM users WHERE username = %s", (username,))
        user = cursor.fetchone()
        if not user:
            raise HTTPException(status_code=404, detail=f"Username not found: {username}")
        member_ids.append(user[0])

    # Insert group
    cursor.execute("""
        INSERT INTO groups (group_name, created_by, created_at)
        VALUES (%s, %s, %s)
        RETURNING id
    """, (data.group_name, creator_id, datetime.utcnow()))
    group_id = cursor.fetchone()[0]

    # Add creator as first member
    cursor.execute("""
        INSERT INTO group_members (group_id, user_id, joined_at)
        VALUES (%s, %s, %s)
    """, (group_id, creator_id, datetime.utcnow()))

    # Add other members
    for uid in member_ids:
        cursor.execute("""
            INSERT INTO group_members (group_id, user_id, joined_at)
            VALUES (%s, %s, %s)
        """, (group_id, uid, datetime.utcnow()))

    conn.commit()

    return {
        "group_id": group_id,
        "group_name": data.group_name,
        "total_members": total_members,
        "status": "created"
    }



@app.post("/update-typing-status")
def update_typing_status(data: TypingUpdate):
    try:
        # Check if entry already exists
        cursor.execute("""
            SELECT id FROM typing_status WHERE chat_id = %s AND user_id = %s
        """, (data.chat_id, data.user_id))
        result = cursor.fetchone()

        if result:
            # Update existing
            cursor.execute("""
                UPDATE typing_status
                SET is_typing = %s
                WHERE chat_id = %s AND user_id = %s
            """, (data.is_typing, data.chat_id, data.user_id))
        else:
            # Insert new
            cursor.execute("""
                INSERT INTO typing_status (chat_id, user_id, is_typing)
                VALUES (%s, %s, %s)
            """, (data.chat_id, data.user_id, data.is_typing))

        conn.commit()
        return {"message": "Typing status updated successfully."}

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

##get typing status
@app.get("/typing-status/{chat_id}/{username}")
def get_typing_status(chat_id: int, username: str):
    try:
        cursor.execute("""
            SELECT 1
            FROM typing_status t
            JOIN users u ON t.user_id = u.id
            WHERE t.chat_id = %s AND u.username = %s AND t.is_typing = TRUE
            LIMIT 1
        """, (chat_id, username))
        result = cursor.fetchone()

        return {"is_typing": bool(result)}

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))




# === REST API: POST Message ===

class MessageCreate(BaseModel):
    chat_id: int
    sender_id: int
    content: str
    media_url: str
    message_type: str


# === POST: Send a new message ===
@app.post("/messages", response_model=MessageOut)
def send_message(msg: MessageCreate):
    try:
        cursor.execute("""
            INSERT INTO messages (chat_id, sender_id, content, media_url, message_type, created_at)
            VALUES (%s, %s, %s, %s, %s, NOW())
            RETURNING id, created_at
        """, (msg.chat_id, msg.sender_id, msg.content, msg.media_url, msg.message_type))
        new_id, created_at = cursor.fetchone()
        conn.commit()

        # Fetch username
        cursor.execute("SELECT username FROM users WHERE id = %s", (msg.sender_id,))
        username_result = cursor.fetchone()
        username = username_result[0] if username_result else "unknown"

        return MessageOut(
            id=new_id,
            chat_id=msg.chat_id,
            sender_id=msg.sender_id,
            username=username,
            content=msg.content,
            media_url=msg.media_url or "",
            message_type=msg.message_type,
            time_stamp=created_at.isoformat()
        )

    except Exception as e:
        conn.rollback()
        raise HTTPException(status_code=500, detail=str(e))


# === GET: Get all messages for a chat ===
@app.get("/messages/{chat_id}", response_model=List[MessageOut])
def get_messages(chat_id: int):
    try:
        cursor.execute("""
            SELECT 
                m.id, m.chat_id, m.sender_id, u.username, m.content, 
                m.media_url, m.message_type, m.created_at
            FROM messages m
            JOIN users u ON m.sender_id = u.id
            WHERE m.chat_id = %s
            ORDER BY m.id ASC
        """, (chat_id,))
        rows = cursor.fetchall()

        messages = []
        for row in rows:
            id, chat_id, sender_id, username, content, media_url, message_type, created_at = row

            if not isinstance(created_at, str):
                created_at = created_at.isoformat()
            else:
                created_at = datetime.fromisoformat(created_at).isoformat()

            messages.append(MessageOut(
                id=id,
                chat_id=chat_id,
                sender_id=sender_id,
                username=username,
                content=content,
                media_url=media_url or "",
                message_type=message_type,
                time_stamp=created_at
            ))

        return messages

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# === GET: Get all messages for a group ===

@app.get("/group_messages/{group_id}", response_model=List[MessageOut])
def get_group_messages(group_id: int):
    try:
        cursor.execute("""
            SELECT 
                gm.id, gm.group_id, gm.sender_id, u.username, gm.content,
                gm.media_url, gm.message_type, gm.created_at
            FROM group_messages gm
            JOIN users u ON gm.sender_id = u.id
            WHERE gm.group_id = %s
            ORDER BY gm.id ASC
        """, (group_id,))
        rows = cursor.fetchall()

        messages = []
        for row in rows:
            id, chat_id, sender_id, username, content, media_url, message_type, created_at = row

            if not isinstance(created_at, str):
                created_at = created_at.isoformat()
            else:
                created_at = datetime.fromisoformat(created_at).isoformat()

            messages.append(MessageOut(
                id=id,
                chat_id=chat_id,
                sender_id=sender_id,
                username=username,
                content=content,
                media_url=media_url or "",
                message_type=message_type,
                time_stamp=created_at
            ))

        return messages

    except Exception as e:
        conn.rollback()  # ✅ Ensure the transaction state is reset
        print("❌ SQL Error:", e)
        raise HTTPException(status_code=500, detail=f"Error fetching group messages: {str(e)}")


UPLOAD_DIR = "uploaded_files"
os.makedirs(UPLOAD_DIR, exist_ok=True)

@app.post("/upload-media/", response_class=PlainTextResponse)
async def upload_media(
    username: str = Form(...),
    file: UploadFile = File(...)
):
    try:
        # Generate filename base
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        original_ext = os.path.splitext(file.filename)[1].lower()
        base_filename = f"{username}_{timestamp}"

        # Filenames
        original_filename = f"{base_filename}{original_ext}"
        webm_filename = f"{base_filename}.webm"
        m4a_filename = f"{base_filename}.m4a"

        # Paths
        original_path = os.path.join(UPLOAD_DIR, original_filename)
        webm_path = os.path.join(UPLOAD_DIR, webm_filename)
        m4a_path = os.path.join(UPLOAD_DIR, m4a_filename)

        # Save the uploaded file
        file_data = await file.read()
        with open(original_path, "wb") as buffer:
            buffer.write(file_data)

        # Copy with opposite extension if needed
        if "audio" in file.content_type:
            if original_ext == ".webm":
                shutil.copyfile(original_path, m4a_path)
                print(f"✅ Copied to: {m4a_filename}")
            elif original_ext == ".m4a":
                shutil.copyfile(original_path, webm_path)
                print(f"✅ Copied to: {webm_filename}")
            else:
                # If another audio format, save both versions
                shutil.copyfile(original_path, webm_path)
                shutil.copyfile(original_path, m4a_path)
                print(f"✅ Copied to: {webm_filename} and {m4a_filename}")

        print(f"✅ Saved original: {original_filename}")
        return m4a_filename

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Upload failed: {str(e)}")
#get the media
UPLOAD_DIR = "uploaded_files"

@app.get("/get-media/")
def get_media(link: str = Query(..., description="/uploaded_files/file.png")):
    # Sanitize: remove leading slashes and ensure it's inside UPLOAD_DIR
    filename = os.path.basename(link)
    file_path = os.path.join(UPLOAD_DIR, filename)

    if not os.path.exists(file_path):
        raise HTTPException(status_code=404, detail="File not found")

    return FileResponse(file_path, media_type="application/octet-stream", filename=filename)
class DeleteGroupMessages(BaseModel):
    id: int
    groupid: int
    senderid: int
    context: str
    mediaurl: str = None
    messagetype: str
    created_at: str


@app.delete("/delete-group-message/", response_model=DeleteGroupMessages)
def delete_group_message(
        message_id: int = Query(...),
        user_id: int = Query(...),
        group_id: int = Query(...)
):
    try:
        conn = get_connection()
        cursor = conn.cursor()

        # Check if the message exists and was sent by the user in that group
        cursor.execute("""
            SELECT id, group_id, sender_id, content, media_url, message_type, created_at
            FROM group_messages
            WHERE id = %s AND group_id = %s AND sender_id = %s
        """, (message_id, group_id, user_id))

        row = cursor.fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Message not found or not authorized to delete.")

        # Build the output response
        message_data = DeleteGroupMessages(
            id=row[0],
            groupid=row[1],
            senderid=row[2],
            context=row[3],
            mediaurl=row[4],
            messagetype=row[5],
            created_at=str(row[6])
        )

        # Delete the message
        cursor.execute("DELETE FROM group_messages WHERE id = %s", (message_id,))
        conn.commit()

        return message_data
    except psycopg2.Error as e:
        raise HTTPException(status_code=500, detail=f"Database error: {e.pgerror}")

    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()


class DeleteMessage(BaseModel):
    id: int
    chat_id: int
    sender_id: int
    content: str
    media_url: str
    message_type: str
    time_stamp: str


# DELETE endpoint
@app.delete("/delete-message/", response_model=DeleteMessage)
def delete_message(message_id: int = Query(...), user_id: int = Query(...)):
    try:
        conn = get_connection()
        cursor = conn.cursor()

        # JOIN to get username from users table
        cursor.execute("""
            SELECT id, chat_id, sender_id, content, media_url, message_type, created_at
            FROM messages WHERE id = %s AND sender_id = %s 
        """, (message_id, user_id))

        row = cursor.fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Message not found or not authorized to delete.")

        message_data = DeleteMessage(
            id=row[0],
            chat_id=row[1],
            sender_id=row[2],
            content=row[3],
            media_url=row[4],
            message_type=row[5],
            time_stamp=str(row[6])
        )

        # Delete the message
        cursor.execute("DELETE FROM messages WHERE id = %s", (message_id,))
        conn.commit()

        return message_data

    except psycopg2.Error as e:
        raise HTTPException(status_code=500, detail=f"Database error: {e.pgerror}")

    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()

class GroupOut(BaseModel):
    id: int
    group_name: str
    created_by: int
    created_at: str

@app.delete("/delete-group/", response_model=GroupOut)
def delete_group(group_id: int = Query(...), user_id: int = Query(...)):
    try:
        conn = get_connection()
        cursor = conn.cursor()

        # Check if the group exists and the user is the creator
        cursor.execute("""
            SELECT id, group_name, created_by, created_at
            FROM groups
            WHERE id = %s AND created_by = %s
        """, (group_id, user_id))

        group = cursor.fetchone()
        if not group:
            raise HTTPException(status_code=404, detail="Group not found or you are not authorized to delete it.")

        group_data = GroupOut(
            id=group[0],
            group_name=group[1],
            created_by=group[2],
            created_at=str(group[3])
        )

        # Delete the group
        cursor.execute("DELETE FROM groups WHERE id = %s", (group_id,))
        conn.commit()

        return group_data

    except psycopg2.Error as e:
        raise HTTPException(status_code=500, detail=f"Database error: {e.pgerror}")

    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()


# Define allowed origins (use "*" for all, or specify allowed URLs)
origins = [
    "http://localhost:8000",
    "http://192.168.100.196:8888",
    "*",  # Allow all origins (use with caution)
]

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,  # Allowed origins
    allow_credentials=True,
    allow_methods=["*"],  # Allow all HTTP methods
    allow_headers=["*"],  # Allow all headers
)