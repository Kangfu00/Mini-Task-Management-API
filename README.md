# Mini Task Management API

[cite_start]โปรเจคตัวอย่าง Python/Flask REST API สำหรับสาธิตการออกแบบ API, การยืนยันตัวตนด้วย JWT, การเชื่อมต่อกับ API ภายนอก และการจัดการข้อผิดพลาด (Error handling) 

## 1. ภาพรวมของระบบ (Overview)

[cite_start]โปรเจคนี้เป็นบริการ Backend ที่สร้างด้วย Python และ Flask [cite: 2] [cite_start]มีวัตถุประสงค์เพื่อให้บริการ HTTP API ในรูปแบบ REST สำหรับแอปพลิเคชันฝั่งไคลเอนต์เพื่อใช้จัดการงาน (Task) [cite: 3]
[cite_start]ไฟล์ README นี้จัดทำขึ้นเพื่ออธิบายถึง[cite: 4]:
- สิ่งที่โปรเจคนี้ทำ
- วิธีติดตั้งและรันโปรเจคในเครื่อง (Local)
- วิธีการทำงานของ API
- รูปแบบของ Request และ Response
- รูปแบบการแจ้งเตือน Error

## 2. เทคโนโลยีที่ใช้ (Technology Stack)

- [cite_start]Python 3.x [cite: 5]
- [cite_start]Flask [cite: 5]
- [cite_start]Werkzeug (ใช้งานผ่าน Flask) [cite: 5]
- PyJWT (สำหรับการยืนยันตัวตนผู้ใช้งาน)
- Requests (สำหรับเชื่อมต่อและดึงข้อมูลจาก API ภายนอก)
- [cite_start]Virtual environment (venv) [cite: 5]
- [cite_start]JSON over HTTP [cite: 5]
- [cite_start]ใช้ไฟล์ JSON ในเครื่อง (`db.json`) ทำหน้าที่เป็นฐานข้อมูลขนาดเล็ก [cite: 5]

## 3. โครงสร้างโปรเจค (Project Structure)

[cite_start]โครงสร้างไฟล์ที่สำคัญของโปรเจคนี้ประกอบด้วย[cite: 8]:

```text
project-root/
├─ db.json             # ไฟล์ฐานข้อมูลจำลอง (เก็บผู้ใช้และรายการงาน)
├─ main.py             # ไฟล์หลักสำหรับรันแอปพลิเคชัน Flask
├─ requirements.txt    # รายชื่อไลบรารีที่ต้องติดตั้ง
├─ .env                # ไฟล์เก็บตัวแปรสภาพแวดล้อม (ซ่อนรหัสลับต่างๆ)
└─ README.md           # ไฟล์เอกสารอธิบายโปรเจค
```
## 4. ตัวอย่างการใช้งาน (Example Use Case)
โปรเจคนี้มี API สำหรับจัดการระบบงานขนาดเล็ก  โดยมีความสามารถหลักดังนี้:

ยืนยันตัวตนผู้ใช้งาน (Login เพื่อรับ JWT Token)

เรียกดูรายการงานทั้งหมดในระบบของเรา

สร้างรายการงานใหม่

ดึงข้อมูลงานจาก API ของระบบเพื่อน (External API) มารวมกับข้อมูลของเรา

ตัวอย่างข้อมูลงานที่เก็บใน db.json:

JSON
{
  "id": 1,
  "title": "Design Mana-Brew website",
  "status": "pending"
}
## 5. วิธีติดตั้งและตั้งค่าในเครื่อง (Installation and Local Setup)
5.1 โคลนโปรเจค (Clone the project)
Bash
git clone <ลิงก์-repository-ของคุณ>
cd <ชื่อโฟลเดอร์โปรเจค>
5.2 สร้างและเปิดใช้งาน Virtual environment
Bash
python -m venv venv

# สำหรับ Windows:
venv\Scripts\activate

# สำหรับ macOS/Linux:
source venv/bin/activate
5.3 ติดตั้งไลบรารี (Install dependencies)
Bash
pip install -r requirements.txt
5.4 ตั้งค่าตัวแปรสภาพแวดล้อม (Configure environment variables)
สร้างไฟล์ที่ชื่อว่า .env ไว้ในโฟลเดอร์หลักของโปรเจค และใส่รหัสลับของคุณลงไป:

ข้อมูลโค้ด
SECRET_KEY=ใส่รหัสลับของคุณที่นี่
FRIEND_API_USERNAME=student
FRIEND_API_PASSWORD=1234
5.5 รันแอปพลิเคชัน
Bash
python main.py
URL สำหรับทดสอบในเครื่อง: http://127.0.0.1:5000

## 6. รูปแบบ Request Header ทั่วไป
ตัวอย่าง Header ที่ใช้บ่อย:

HTTP
Content-Type: application/json
Accept: application/json
Authorization: Bearer <access_token>
คำอธิบาย:


Content-Type ใช้บอกเซิร์ฟเวอร์ว่ารูปแบบข้อมูลที่ส่งไปคืออะไร 


Authorization ใช้สำหรับแนบ Token เมื่อเรียกใช้งาน API ที่ต้องผ่านการยืนยันตัวตน 

## 7. รูปแบบ Response และ Error มาตรฐาน
เพื่อความเป็นระเบียบ API จะตอบกลับข้อมูลที่ร้องขอในรูปแบบ JSON เสมอเมื่อทำงานสำเร็จ  ตัวอย่างเช่น:

JSON
{
  "tasks": [
    {
      "id": 1,
      "title": "Design Mana-Brew website",
      "status": "pending"
    }
  ]
}
ในกรณีที่เกิดข้อผิดพลาด API จะแจ้งเตือนพร้อมรหัสและข้อความในรูปแบบที่คาดเดาได้  ตัวอย่างเช่น:

JSON
{
  "error": {
    "code": 401,
    "message": "Token is invalid or expired"
  }
}
## 8. สรุปรายการ Endpoint (Endpoint Summary)
8.1 เข้าสู่ระบบ (Login)
Method: POST

Path: /login

Description: ตรวจสอบรหัสผ่านผู้ใช้งานและส่งมอบ JWT Token

Request body:

JSON
{
  "username": "student",
  "password": "1234"
}
Success response: 200 OK

JSON
{
  "token": "eyJhbGciOiJIUzI1NiIs..."
}
8.2 ดูรายการงานทั้งหมด (List Tasks)
Method: GET

Path: /tasks


Description: เรียกดูข้อมูลงานทั้งหมดในระบบ (จำเป็นต้องแนบ Authorization Header) 

Success response: 200 OK

8.3 สร้างงานใหม่ (Create Task)
Method: POST

Path: /tasks


Description: สร้างงานใหม่ (จำเป็นต้องแนบ Authorization Header) 

Request body:

JSON
{
  "title": "Train YOLOv8 model for Yu-Gi-Oh! cards",
  "status": "in_progress"
}
Success response: 201 Created

JSON
{
  "message": "Task created"
}
8.4 เรียกข้อมูลงานของเพื่อน (Get External Tasks)
Method: GET

Path: /external-tasks

Description: ดึงข้อมูลงานในระบบของเรา นำไปรวมกับข้อมูลที่ดึงมาจาก API ของระบบเพื่อน (จำเป็นต้องแนบ Authorization Header)

Success response: 200 OK

JSON
{
  "my_tasks": [ ... ],
  "external_tasks": [ ... ]
}
## 9. ข้อควรระวังด้านความปลอดภัย (Security Notes)
คำแนะนำเบื้องต้น:

ห้ามใส่รหัสผ่านหรือคีย์ความลับลงไปในซอร์สโค้ดโดยเด็ดขาด 

ให้เก็บรหัสลับไว้ในไฟล์ตัวแปรสภาพแวดล้อม (.env) 

ปกป้อง Endpoint ที่สำคัญด้วยการตรวจสอบความถูกต้องของ Token เสมอ 

## 10. ข้อมูลติดต่อ (Contact)

ผู้จัดทำ: <พิมพ์ชื่อ-นามสกุลของคุณ> - <พิมพ์รหัสนักศึกษา>