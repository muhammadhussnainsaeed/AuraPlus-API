from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel
from sqlalchemy import create_engine, Column, Integer, String, Boolean
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from passlib.context import CryptContext
from datetime import datetime, timedelta
import jwt

# SQLALCHEMY_DATABASE_URL = "postgresql://postgres:12345@localhost/chat_app"
from fastapi import FastAPI, HTTPException, Depends, status,Query
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel
from passlib.context import CryptContext
import psycopg2
import jwt
import base64
from datetime import datetime, timedelta
from typing import Optional,List  # ✅ Correct

from starlette.middleware.cors import CORSMiddleware

app = FastAPI()

# Secret key for encoding and decoding JWTs (keep it safe)
SECRET_KEY = "your_secret_key"  # Change this to a strong, secret key!
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30  # You can adjust the expiry time here

# Password hashing context
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Database connection (change these as per your setup)
conn = psycopg2.connect(
    dbname="AuraPlus",
    user="postgres",
    password="12345",
    host="localhost",      # Or your DB host
    port="5432"            # Default PostgreSQL port
)
cursor = conn.cursor()


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

# Pydantic schema for messages
class MessageCreate(BaseModel):
    chat_id: int
    sender_id: int
    content: str
    media_url: str = ""
    message_type: str = "text"

class MessageOut(BaseModel):
    id: int
    chat_id: int
    sender_id: int
    content: str
    media_url: str
    message_type: str



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
def update_password(data: PasswordUpdateRequest):
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




@app.post("/send-message")
def send_message(message: MessageCreate):
    try:
        cursor.execute("""
            INSERT INTO messages (chat_id, sender_id, content, media_url, message_type)
            VALUES (%s, %s, %s, %s, %s)
            RETURNING id, created_at
        """, (
            message.chat_id,
            message.sender_id,
            message.content,
            message.media_url,
            message.message_type
        ))
        result = cursor.fetchone()
        conn.commit()

        return {
            "success": True,
            "message_id": result[0],
            "created_at": result[1],
            "detail": "Message sent successfully."
        }

    except Exception as e:
        conn.rollback()
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/get-messages")
def get_messages(query: ChatQuery):
    try:
        cursor.execute("""
            SELECT id, sender_id, content, media_url, message_type, created_at
            FROM messages
            WHERE chat_id = %s
            ORDER BY created_at ASC
        """, (query.chat_id,))
        messages = cursor.fetchall()

        result = []
        for msg in messages:
            result.append({
                "message_id": msg[0],
                "sender_id": msg[1],
                "content": msg[2],
                "media_url": msg[3],
                "message_type": msg[4],
                "created_at": msg[5]
            })

        return {
            "success": True,
            "chat_id": query.chat_id,
            "messages": result
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




@app.post("/get_user_chats")
def get_user_chats(data: UsernameRequest):
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
            "profile_picture_base64": picture_data_url,
            "last_message": last_message,
            "last_message_time": last_time
        })

    return result



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


# Send a message (POST)
@app.post("/messages", response_model=MessageOut)
def send_message(msg: MessageCreate):
    try:
        cursor.execute("""
            INSERT INTO messages (chat_id, sender_id, content, media_url, message_type)
            VALUES (%s, %s, %s, %s, %s) RETURNING id
        """, (msg.chat_id, msg.sender_id, msg.content, msg.media_url, msg.message_type))
        new_id = cursor.fetchone()[0]
        conn.commit()
        return MessageOut(id=new_id, **msg.dict())
    except Exception as e:
        conn.rollback()
        raise HTTPException(status_code=500, detail=str(e))

# Get messages for a chat (GET)
@app.get("/messages/{chat_id}", response_model=List[MessageOut])
def get_messages(chat_id: int):
    try:
        cursor.execute("""
            SELECT id, chat_id, sender_id, content, media_url, message_type
            FROM messages WHERE chat_id = %s ORDER BY id ASC
        """, (chat_id,))
        rows = cursor.fetchall()
        return [MessageOut(
            id=row[0],
            chat_id=row[1],
            sender_id=row[2],
            content=row[3],
            media_url=row[4],
            message_type=row[5]
        ) for row in rows]
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))



# Define allowed origins (use "*" for all, or specify allowed URLs)
# origins = [
#     "http://localhost:8000",
#     "http://192.168.100.196:8888",
#     "*",  # Allow all origins (use with caution)
# ]
#
# # Add CORS middleware
# app.add_middleware(
#     CORSMiddleware,
#     allow_origins=origins,  # Allowed origins
#     allow_credentials=True,
#     allow_methods=["*"],  # Allow all HTTP methods
#     allow_headers=["*"],  # Allow all headers
# )