const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
app.use(express.json());
app.use(express.static('public'));

// รหัสลับสำหรับเซ็นต์สร้าง Token (ในการใช้งานจริงควรตั้งใน Environment Variable)
const JWT_SECRET = process.env.JWT_SECRET || 'my_super_secret_key_12345';

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL ? { rejectUnauthorized: false } : false
});

// สร้างตารางข้อมูลผู้ใช้ และ ตารางโพยหวย
async function initDB() {
  try {
    await pool.query(`DROP TABLE IF EXISTS bets CASCADE;`);
    await pool.query(`DROP TABLE IF EXISTS users CASCADE;`);
    await pool.query(`
  CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL,
    phone VARCHAR(20) UNIQUE NOT NULL,
    full_name VARCHAR(100) NOT NULL,
    bank_name VARCHAR(50) NOT NULL,
    account_number VARCHAR(30) NOT NULL,
    ref_code VARCHAR(50),
    role VARCHAR(20) DEFAULT 'member',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
  );
`);
    await pool.query(`
      CREATE TABLE IF NOT EXISTS bets (
        id SERIAL PRIMARY KEY,
        player_name VARCHAR(100) NOT NULL,
        number VARCHAR(10) NOT NULL,
        bet_type VARCHAR(20) NOT NULL,
        amount NUMERIC NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);
    // เพิ่มท้ายฟังก์ชัน initDB() ใน index.js
const adminCheck = await pool.query("SELECT * FROM users WHERE role = 'admin' OR role = 'superadmin'");
if (adminCheck.rows.length === 0) {
  const defaultPassword = await bcrypt.hash('admin1234', 10); // 🔑 รหัสผ่านแอดมินตัวแรก
  await pool.query(
    `INSERT INTO users (username, password, phone, full_name, bank_name, account_number, role)
     VALUES ($1, $2, $3, $4, $5, $6, 'superadmin')`,
    ['admin_master', defaultPassword, '0000000000', 'Super Admin Master', 'System', '000000']
  );
  console.log("สร้างบัญชี Super Admin เรียบร้อย (User: admin_master / Pass: admin1234)");
}
    console.log("Database initialized successfully.");
  } catch (err) {
    console.error("Error initializing DB:", err);
  }
}
initDB();

// ==========================================
// ระบบยามเฝ้าประตู (Middleware)
// ==========================================

// ฟังก์ชันตรวจสอบ Token
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1]; 
  
  if (!token) return res.status(401).json({ success: false, message: 'ไม่พบ Token กรุณาล็อกอิน' });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ success: false, message: 'Token ไม่ถูกต้องหรือหมดอายุ' });
    req.user = user; // เก็บข้อมูลผู้ใช้ไว้ใน req.user
    next();
  });
};

// ฟังก์ชันเช็คสิทธิ์แอดมิน
const isAdmin = (req, res, next) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ success: false, message: 'ไม่มีสิทธิ์เข้าถึง เฉพาะแอดมินเท่านั้น' });
  }
  next();
};

// เก็บ OTP จำลองไว้ใน Memory (เพื่อการทดสอบ)
const otpStore = {};

// 1. API ขอ OTP (จำลอง)
app.post('/api/request-otp', (req, res) => {
  const { phone } = req.body;
  if (!phone) return res.status(400).json({ success: false, message: 'กรุณากรอกเบอร์โทรศัพท์' });

  // สุ่มเลข OTP 6 หลัก
  const generatedOtp = Math.floor(100000 + Math.random() * 900000).toString();
  otpStore[phone] = generatedOtp; // บันทึกไว้เทียบตอนสมัคร

  console.log(`[OTP Mock] Phone: ${phone} | OTP: ${generatedOtp}`);

  res.json({
    success: true,
    message: 'ส่งรหัส OTP เรียบร้อยแล้ว (สำหรับทดสอบ OTP คือ: ' + generatedOtp + ')'
  });
});

// 2. API สมัครสมาชิกแบบข้อมูลครบถ้วน
app.post('/api/register', async (req, res) => {
  const { username, password, confirmPassword, phone, otp, fullName, bankName, accountNumber, refCode } = req.body;

  // ตรวจสอบความครบถ้วนของข้อมูล
  if (!username || !password || !phone || !otp || !fullName || !bankName || !accountNumber) {
    return res.status(400).json({ success: false, message: 'กรุณากรอกข้อมูลให้ครบถ้วน' });
  }

  if (password !== confirmPassword) {
    return res.status(400).json({ success: false, message: 'รหัสผ่านและยืนยันรหัสผ่านไม่ตรงกัน' });
  }

  // ตรวจสอบ OTP
  if (otpStore[phone] !== otp) {
    return res.status(400).json({ success: false, message: 'รหัส OTP ไม่ถูกต้อง' });
  }

  try {
    const hashedPassword = await bcrypt.hash(password, 10);

    const result = await pool.query(
      `INSERT INTO users (username, password, phone, full_name, bank_name, account_number, ref_code, role) 
       VALUES ($1, $2, $3, $4, $5, $6, $7, 'member') 
       RETURNING id, username, phone, full_name`,
      [username, hashedPassword, phone, fullName, bankName, accountNumber, refCode || null]
    );

    // สมัครเสร็จแล้ว ลบ OTP ออกจาก memory
    delete otpStore[phone];

    res.json({ success: true, message: 'สมัครสมาชิกสำเร็จ!', user: result.rows[0] });
  } catch (err) {
    if (err.code === '23505') { // Username หรือ Phone ซ้ำ
      return res.status(400).json({ success: false, message: 'ชื่อผู้ใช้หรือเบอร์โทรศัพท์นี้มีในระบบแล้ว' });
    }
    console.error(err);
    res.status(500).json({ success: false, message: 'เกิดข้อผิดพลาดในการลงทะเบียน' });
  }
});

// 2. API เข้าสู่ระบบ
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ success: false, message: 'กรุณากรอกชื่อผู้ใช้และรหัสผ่าน' });
  }

  try {
    const result = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
    if (result.rows.length === 0) {
      return res.status(400).json({ success: false, message: 'ชื่อผู้ใช้หรือรหัสผ่านไม่ถูกต้อง' });
    }

    const user = result.rows[0];
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(400).json({ success: false, message: 'ชื่อผู้ใช้หรือรหัสผ่านไม่ถูกต้อง' });
    }

    const token = jwt.sign(
      { id: user.id, username: user.username, role: user.role },
      JWT_SECRET,
      { expiresIn: '24h' }
    );

    res.json({
      success: true,
      message: 'เข้าสู่ระบบสำเร็จ!',
      token: token,
      role: user.role,
      username: user.username
    });

  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: 'เกิดข้อผิดพลาดในการเข้าสู่ระบบ' });
  }
});

// 3. API สำหรับบันทึกโพยหวย (เพิ่มส่วนนี้ที่ขาดไป)
app.post('/api/bet', authenticateToken, async (req, res) => {
  const { number, betType, amount } = req.body;
  const playerName = req.user.username; // ดึงชื่อผู้ใช้จาก Token อัตโนมัติ

  if (!number || !betType || !amount) {
    return res.status(400).json({ success: false, message: 'กรุณากรอกข้อมูลให้ครบถ้วน' });
  }

  try {
    const result = await pool.query(
      'INSERT INTO bets (player_name, number, bet_type, amount) VALUES ($1, $2, $3, $4) RETURNING *',
      [playerName, number, betType, parseFloat(amount)]
    );
    res.json({ success: true, bet: result.rows[0] });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: 'เกิดข้อผิดพลาดในการบันทึกข้อมูล' });
  }
});

// ==========================================
// API สำหรับแอดมิน (Admin)
// ==========================================

// API สำหรับดึงข้อมูลโพยหวยทั้งหมด
app.get('/api/admin/bets', authenticateToken, isAdmin, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM bets ORDER BY created_at DESC');
    res.json({ success: true, bets: result.rows });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: 'ไม่สามารถดึงข้อมูลโพยได้' });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
