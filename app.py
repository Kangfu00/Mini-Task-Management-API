import os
import json
from flask import Flask, request, jsonify
import jwt
import datetime
import requests
from functools import wraps
from dotenv import load_dotenv
from werkzeug.security import generate_password_hash, check_password_hash

load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'default_key_for_dev')

# --- ฟังก์ชันช่วยอ่านและเขียนไฟล์ JSON ---
DB_FILE = 'db.json'

def load_db():
    with open(DB_FILE, 'r', encoding='utf-8') as f:
        return json.load(f)

def save_db(data):
    with open(DB_FILE, 'w', encoding='utf-8') as f:
        json.dump(data, f, ensure_ascii=False, indent=2)

# --- Decorator สำหรับตรวจสอบ JWT Token ---
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'Authorization' in request.headers:
            parts = request.headers['Authorization'].split()
            if len(parts) == 2 and parts[0] == 'Bearer':
                token = parts[1]
        
        if not token:
            return jsonify({"error": {"code": 401, "message": "Token is missing or invalid format"}}), 401
        
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user = data['user']
        except Exception as e:
            return jsonify({"error": {"code": 401, "message": "Token is invalid or expired"}}), 401
        
        return f(current_user, *args, **kwargs)
    return decorated

# --- 1. Endpoint: Login ---
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    if not data or not data.get('username') or not data.get('password'):
        return jsonify({"error": {"code": 400, "message": "Username and password are required"}}), 400
    
    username = data.get('username')
    password = data.get('password')
    db = load_db()

    # ตรวจสอบ User และ Hash Password
    if username in db['users'] and check_password_hash(db['users'][username], password):
        token = jwt.encode({
            'user': username,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1)
        }, app.config['SECRET_KEY'], algorithm="HS256")
        return jsonify({"token": token}), 200
    
    return jsonify({"error": {"code": 401, "message": "Unauthorized"}}), 401

# --- 2. Endpoint: ดูรายการ Task ---
@app.route('/tasks', methods=['GET'])
@token_required
def get_tasks(current_user):
    db = load_db()
    return jsonify({"tasks": db['tasks']}), 200

# --- 3. Endpoint: สร้าง Task ใหม่ ---
@app.route('/tasks', methods=['POST'])
@token_required
def create_task(current_user):
    req_data = request.get_json()
    if not req_data or not req_data.get('title'):
        return jsonify({"error": {"code": 400, "message": "Title is required"}}), 400
    
    db = load_db()
    new_task = {
        "id": len(db['tasks']) + 1,
        "title": req_data.get('title'),
        "status": req_data.get('status', 'pending')
    }
    db['tasks'].append(new_task)
    save_db(db) # เซฟกลับลงไฟล์ JSON
    
    return jsonify({"message": "Task created"}), 201

# --- 4. Endpoint: เรียก API เพื่อน ---
@app.route('/external-tasks', methods=['GET'])
@token_required
def get_external_tasks(current_user):
    # สมมติว่านี่คือ URL ของเพื่อนที่ Deploy แล้ว (ต้องไปขอจากเพื่อน)
    friend_login_url = "http://localhost:5001/login" 
    friend_tasks_url = "http://localhost:5001/tasks"
    
    # รหัสผ่านที่เพื่อนสร้างไว้ให้กลุ่มเราไปล็อกอิน
    friend_credentials = {
        "username": "my_group",
        "password": "password_from_friend"
    }
    
    try:
        # สเต็ปที่ 1: ยิง Request ไป Login ที่เซิร์ฟเวอร์เพื่อนเพื่อขอ Token
        login_response = requests.post(friend_login_url, json=friend_credentials, timeout=5)
        login_response.raise_for_status() # ดักจับ Error ถ้าเพื่อนตอบกลับมาเป็น 4xx, 5xx
        
        # แกะเอา Token ออกมาจาก Response ของเพื่อน
        friend_token = login_response.json().get('token')
        
        # สเต็ปที่ 2: เอา Token ของเพื่อนแนบใส่ Header แล้วยิงไปขอข้อมูล
        headers = {
            "Authorization": f"Bearer {friend_token}"
        }
        
        # เรียก API เพื่อน และป้องกันกรณี Timeout [cite: 64]
        task_response = requests.get(friend_tasks_url, headers=headers, timeout=5) 
        task_response.raise_for_status()
        
        # ได้ข้อมูล Task ของเพื่อนมาแล้ว!
        external_data = task_response.json()
        
    except requests.exceptions.RequestException as e:
        # ถ้าเซิร์ฟเวอร์เพื่อนล่ม หรือรหัสผิด จะเข้าเงื่อนไขนี้ [cite: 275]
        return jsonify({"error": {"code": 500, "message": f"Failed to connect to friend's API: {str(e)}"}}), 500

    # สเต็ปที่ 3: ดึงข้อมูลของเรา แล้วเอามาผสมกับของเพื่อน [cite: 61, 246]
    db = load_db()
    
    return jsonify({
        "my_tasks": db['tasks'],
        # ป้องกันกรณีโครงสร้าง JSON เพื่อนเป็นลิสต์เพียวๆ หรือซ้อนทับมา
        "external_tasks": external_data.get('tasks', external_data) 
    }), 200

if __name__ == '__main__':
    app.run(debug=True, port=5000)