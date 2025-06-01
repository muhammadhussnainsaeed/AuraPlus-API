from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel
from passlib.context import CryptContext
import psycopg2
import jwt
import base64
from datetime import datetime, timedelta

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



#forget password
class SecurityQuestionRequest(BaseModel):
    username: str
    question1_answer: str
    question2_answer: str
    question3_answer: str
    question4_answer: str
    question5_answer: str

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


####update the password
# Request body schema for password update
class PasswordUpdateRequest(BaseModel):
    username: str
    new_password: str

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


####Update the old password by taking the old password

# Request body schema for password update
class PasswordUpdateRequest(BaseModel):
    username: str
    old_password: str
    new_password: str


# Function to hash passwords
def hash_password(password: str):
    return pwd_context.hash(password)


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
# Request model
class UserPhotoUpdate(BaseModel):
    username: str
    name: str
    profile_image: str  # base64-encoded image


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

class UserQuery(BaseModel):
    username: str

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


#Update the Online Status of the user

class OnlineStatusUpdate(BaseModel):
    username: str
    is_online: bool

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
