from flask import Flask, request, jsonify
from pymongo import MongoClient
import bcrypt
from datetime import datetime, timedelta, timezone

import os

app = Flask(__name__)

# ดึง URL ฐานข้อมูลจาก Environment Variable (ซ่อนรหัสผ่าน)
uri = os.environ.get("MONGO_URI", "mongodb://localhost:27017/") # ใส่ localhost ไว้เผื่อรันในเครื่องตัวเองเฉยๆ

client = MongoClient(uri)
db = client['my_login_db']
users_col = db['users']
codes_col = db['codes']
announcements_col = db['announcements']

@app.route('/')
def home():
    return "<h1>ระบบ Login พร้อมทำงานแล้ว</h1>"

@app.route('/status', methods=['GET'])
def status():
    # จำนวนผู้สมัครทั้งหมด
    total_users = users_col.count_documents({})
    # จำนวนผู้ใช้ออนไลน์จริง (ที่มีสถานะ is_online = True)
    online_users = users_col.count_documents({"is_online": True})
    
    # หาคนล่าสุด
    latest_user_doc = users_col.find().sort("_id", -1).limit(1)
    latest_username = ""
    latest_time = ""
    for doc in latest_user_doc:
        name = doc.get("username", "")
        if len(name) > 4:
            latest_username = name[:2] + "x" * (len(name)-4) + name[-2:]
        elif len(name) > 2:
            latest_username = name[:1] + "x" * (len(name)-2) + name[-1:]
        else:
            latest_username = name
            
        # ดึงเวลาสมัครจาก ObjectId
        if "_id" in doc:
            latest_time = doc["_id"].generation_time.astimezone().strftime("%Y-%m-%d %H:%M:%S")

    return jsonify({
        "version": "1.0.0",
        "total_users": total_users,
        "online_users": online_users,
        "latest_user": latest_username,
        "latest_time": latest_time
    })
@app.route('/register', methods=['POST'])
def register():
    data = request.json
    raw_username = data.get('username')
    password = data.get('password')
    hwid = data.get('hwid')

    if not raw_username or not password or not hwid:
        return jsonify({"message": "ข้อมูลไม่ครบถ้วน (ต้องการ Username, Password และ HWID)"}), 400

    username = raw_username.strip().lower()

    # ตรวจสอบว่ามี user นี้หรือยัง
    if users_col.find_one({"username": username}):
        return jsonify({"message": "ชื่อผู้ใช้นี้มีอยู่ในระบบแล้ว"}), 400

    # ป้องกัน 1 เครื่อง สมัครได้แค่ 1 ไอดี
    if users_col.find_one({"hwid": hwid}):
        return jsonify({"message": "เครื่องนี้ได้ถูกใช้สมัครสมาชิกไปแล้ว (ไม่อนุญาตให้สมัครซ้ำ)"}), 400

    # Hash รหัสผ่านและแปลงเป็น string ก่อนเก็บ
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    
    expire_date = datetime.now(timezone.utc) + timedelta(days=3)
    
    users_col.insert_one({
        "username": username, 
        "password": hashed_password,
        "hwid": hwid,
        "expire_date": expire_date
    })
    return jsonify({"message": "สมัครสมาชิกสำเร็จ!"})

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    raw_username = data.get('username')
    password = data.get('password')
    hwid = data.get('hwid')
    
    if not raw_username or not password or not hwid:
        return jsonify({"message": "ข้อมูลไม่ครบถ้วน (ต้องการ Username, Password และ HWID)"}), 400

    username = raw_username.strip().lower()

    user = users_col.find_one({"username": username})
    
    if not user:
        return jsonify({"message": "ชื่อผู้ใช้หรือรหัสผ่านไม่ถูกต้อง"}), 401
    
    role = user.get("role", "member")
    
    if role == "admin":
        admin_hwids = user.get("admin_hwids", [])
        # รวมเครื่องแรกที่ใช้สมัครด้วย
        if user.get("hwid") and user.get("hwid") not in admin_hwids:
            admin_hwids.append(user.get("hwid"))
            
        if hwid not in admin_hwids:
            return jsonify({"message": f"ไม่อนุญาตให้เข้าสู่ระบบ (เครื่องนี้ยังไม่ได้รับอนุญาตสำหรับ Admin)\n\nHWID เครื่องนี้คือ: {hwid}\nนำไปเพิ่มสิทธิ์เพื่อเข้าใช้งาน"}), 401
    else:
        # ตรวจสอบ HWID ว่าตรงกับตอนสมัครไหม สำหรับ member ปกติ
        if user.get("hwid") != hwid:
            return jsonify({"message": "ไม่อนุญาตให้เข้าสู่ระบบ (เครื่องไม่ตรงกับที่สมัครไว้)"}), 401

    # ตรวจสอบรหัสผ่าน (แปลง string ใน DB กลับเป็น bytes เพื่อเช็ค)
    if bcrypt.checkpw(password.encode('utf-8'), user['password'].encode('utf-8')):
        # ตรวจสอบวันหมดอายุ
        expire_date = user.get("expire_date")
        if not expire_date:
            expire_date = datetime.now(timezone.utc) + timedelta(days=3)
            users_col.update_one({"_id": user["_id"]}, {"$set": {"expire_date": expire_date}})
            
        if expire_date.tzinfo is None:
            expire_date = expire_date.replace(tzinfo=timezone.utc)
            
        # ตรวจสอบวันหมดอายุ (ยกเว้น admin ไม่มีวันหมดอายุ)
        if role != "admin" and datetime.now(timezone.utc) > expire_date:
            return jsonify({"message": "หมดเวลาทดลองใช้งาน 3 วันแล้ว กรุณาติดต่อแอดมิน"}), 403

        # อัปเดตสถานะการออนไลน์
        users_col.update_one({"_id": user["_id"]}, {"$set": {"is_online": True}})
        
        return jsonify({
            "message": "เข้าสู่ระบบสำเร็จ!", 
            "expire_date": expire_date.isoformat(),
            "role": role
        })
    else:
        return jsonify({"message": "ชื่อผู้ใช้หรือรหัสผ่านไม่ถูกต้อง"}), 401

@app.route('/logout', methods=['POST'])
def logout():
    data = request.json
    username = data.get('username')
    
    if not username:
        return jsonify({"message": "ข้อมูลไม่ครบถ้วน"}), 400
        
    username = username.strip().lower()
    users_col.update_one({"username": username}, {"$set": {"is_online": False}})
    return jsonify({"message": "ออกจากระบบสำเร็จ!"})

@app.route('/redeem', methods=['POST'])
def redeem():
    data = request.json
    username = data.get('username')
    code = data.get('code')
    
    if not username or not code:
        return jsonify({"message": "ข้อมูลไม่ครบถ้วน (ต้องการ Username และ Code)"}), 400
        
    username = username.strip().lower()
    code = code.strip()
    
    # 1. เช็คว่ามีผู้ใช้นี้อยู่ไหม
    user = users_col.find_one({"username": username})
    if not user:
        return jsonify({"message": "ไม่พบผู้ใช้งานนี้ในระบบ"}), 404
        
    # 2. เช็คว่าโค้ดนี้มีอยู่ในระบบและยังไม่ถูกใช้หรือไม่
    code_doc = codes_col.find_one({"code": code})
    if not code_doc:
        return jsonify({"message": "ไม่พบโค้ดนี้ในระบบ"}), 404
        
    now_utc = datetime.now(timezone.utc)
    
    # ตรวจสอบการหมดอายุแบบใหม่
    if "expires_at" in code_doc:
        if now_utc > code_doc["expires_at"].replace(tzinfo=timezone.utc):
            return jsonify({"message": "โค้ดนี้หมดอายุหรือหมดเวลาการใช้งานแล้ว"}), 400
            
    # ตรวจสอบจำนวนสิทธิ์
    max_usages = code_doc.get("max_usages", 1)
    used_by_list = code_doc.get("used_by_list", [])
    
    # ถ้าเป็นโค้ดรุ่นเก่าที่ใช้ is_used
    if code_doc.get("is_used") and not used_by_list:
        return jsonify({"message": f"โค้ดนี้ถูกใช้งานไปแล้วเมื่อ {code_doc.get('used_at')}"}), 400
        
    if len(used_by_list) >= max_usages:
        return jsonify({"message": "สิทธิ์ของโค้ดนี้เต็มจำนวนแล้ว"}), 400
        
    if username in used_by_list:
        return jsonify({"message": "คุณได้ใช้งานโค้ดนี้ไปแล้ว"}), 400
        
    # 3. อัปเดตวันหมดอายุให้ User
    days_to_add = code_doc.get("days", 0)
    current_expire = user.get("expire_date")
    
    now_utc = datetime.now(timezone.utc)
    
    if not current_expire or current_expire.replace(tzinfo=timezone.utc) < now_utc:
        # ถ้าไม่มีวันหมดอายุ หรือหมดอายุไปแล้ว ให้นับเริ่มจากตอนนี้
        new_expire = now_utc + timedelta(days=days_to_add)
    else:
        # ถ้ายังมีเวลาเหลืออยู่ ให้บวกเพิ่มเข้าไปจากเดิม
        new_expire = current_expire.replace(tzinfo=timezone.utc) + timedelta(days=days_to_add)
        
    users_col.update_one({"_id": user["_id"]}, {"$set": {"expire_date": new_expire}})
    
    # 4. อัปเดตสถานะโค้ดว่าถูกใช้แล้ว
    used_time = now_utc.strftime("%Y-%m-%d %H:%M:%S")
    used_by_list.append(username)
    is_used_full = len(used_by_list) >= max_usages
    
    codes_col.update_one({"_id": code_doc["_id"]}, {"$set": {
        "is_used": is_used_full,
        "used_by_list": used_by_list,
        "used_at": used_time
    }})
    
    return jsonify({
        "message": "เติมเวลาใช้งานสำเร็จ!",
        "new_expire_date": new_expire.isoformat(),
        "days_added": days_to_add
    })

@app.route('/admin/generate_code', methods=['POST'])
def generate_code():
    # ในอนาคตคุณสามารถเพิ่มการเช็คสิทธิ์ admin_hwid หรือรหัสผ่านก่อนเพื่อความปลอดภัย
    data = request.json
    code = data.get('code')
    days = data.get('days')
    max_usages = data.get('max_usages', 1)
    expires_in_hours = data.get('expires_in_hours', 24)
    
    if not code or not isinstance(days, int):
        return jsonify({"message": "กรุณาส่ง code และ days (ตัวเลข)"}), 400
        
    code = code.strip()
    
    if codes_col.find_one({"code": code}):
        return jsonify({"message": "โค้ดนี้มีอยู่ในระบบแล้ว"}), 400
        
    now_utc = datetime.now(timezone.utc)
    expires_at = now_utc + timedelta(hours=expires_in_hours)
        
    codes_col.insert_one({
        "code": code,
        "days": days,
        "max_usages": max_usages,
        "expires_at": expires_at,
        "used_by_list": [],
        "is_used": False,
        "created_at": now_utc.strftime("%Y-%m-%d %H:%M:%S")
    })
    
    return jsonify({"message": f"สร้างโค้ด {code} สำหรับเติมเวลา {days} วัน เรียบร้อยแล้ว!"})

@app.route('/announcements', methods=['GET'])
def get_announcements():
    # ดึงประกาศล่าสุด 10 อันดับแรก
    docs = announcements_col.find().sort("created_at", -1).limit(10)
    results = []
    for doc in docs:
        results.append({
            "title": doc.get("title", ""),
            "content": doc.get("content", ""),
            "author": doc.get("author", "Admin"),
            "created_at": doc.get("created_at", "")
        })
    return jsonify({"announcements": results})

@app.route('/admin/announcement', methods=['POST'])
def create_announcement():
    data = request.json
    title = data.get('title')
    content = data.get('content')
    author = data.get('author', 'Admin')
    
    if not title or not content:
        return jsonify({"message": "กรุณาส่ง title และ content"}), 400
        
    announcements_col.insert_one({
        "title": title.strip(),
        "content": content.strip(),
        "author": author.strip(),
        "created_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    })
    
    return jsonify({"message": "สร้างประกาศเรียบร้อยแล้ว!"})

@app.route('/redeem_history/<username>', methods=['GET'])
def get_redeem_history(username):
    username = username.strip().lower()
    # ดึงข้อมูลการใช้โค้ดของ user นี้ โดยเรียงจากเวลาที่ใช้ล่าสุด
    docs = codes_col.find({"is_used": True, "used_by": username}).sort("used_at", -1)
    
    results = []
    for doc in docs:
        results.append({
            "code": doc.get("code", ""),
            "days": doc.get("days", 0),
            "used_at": doc.get("used_at", "")
        })
        
    return jsonify({"history": results})

if __name__ == '__main__':
    app.run(debug=True, use_reloader=False)