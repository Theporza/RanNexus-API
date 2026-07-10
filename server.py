from flask import Flask, request, jsonify
from pymongo import MongoClient
import bcrypt
from datetime import datetime, timedelta, timezone

app = Flask(__name__)

# เปลี่ยน <db_password> เป็นรหัสที่คุณตั้งไว้ใน MongoDB Atlas
uri = "mongodb+srv://lnwporza55yo_db_user:sEWbMeMVqlGhVuDX@nexusdb.i5bm9cl.mongodb.net/?appName=NexusDB"
client = MongoClient(uri)
db = client['my_login_db']
users_col = db['users']

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
        "version": "1.0.1",
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

if __name__ == '__main__':
    app.run(debug=True, use_reloader=False)