const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
app.use(express.json());
app.use(express.static('public'));

// รหัสลับสำหรับเซ็นต์สร้าง Token
const JWT_SECRET = process.env.JWT_SECRET || 'my_super_secret_key_12345';

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL ? { rejectUnauthorized: false } : false
});

// ==========================================
// 1. ฟังก์ชันเริ่มต้นฐานข้อมูล (initDB)
// ==========================================
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

    // สร้าง Super Admin ตัวแรกถ้ายังไม่มีในระบบ
    const adminCheck = await pool.query("SELECT * FROM users WHERE role = 'admin' OR role = 'superadmin'");
    if (adminCheck.rows.length === 0) {
      const defaultPassword = await bcrypt.hash('admin1234', 10);
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
// 2. Middleware ยืนยันตัวตน (JWT Authentication)
// ==========================================

// ตรวจสอบ JWT Token ทั่วไป
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1]; 

  if (!token) return res.status(401).json({ success: false, message: 'ไม่พบ Token กรุณาล็อกอิน' });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ success: false, message: 'Token ไม่ถูกต้องหรือหมดอายุ' });
    req.user = user;
    next();
  });
};

// เช็คสิทธิ์ Admin ขึ้นไป (Admin หรือ Superadmin)
const isAdmin = (req, res, next) => {
  if (req.user.role !== 'admin' && req.user.role !== 'superadmin') {
    return res.status(403).json({ success: false, message: 'ไม่มีสิทธิ์เข้าถึง เฉพาะแอดมินเท่านั้น' });
  }
  next();
};

// เช็คสิทธิ์ Super Admin เท่านั้น
const verifySuperAdmin = (req, res, next) => {
  if (!req.user || req.user.role !== 'superadmin') {
    return res.status(403).json({ success: false, message: 'ปฏิเสธการเข้าถึง: สำหรับ Super Admin เท่านั้น' });
  }
  next();
};

// ==========================================
// 3. API สำหรับระบบสมาชิก & ล็อกอิน
// ==========================================

const otpStore = {};

// API ขอ OTP
app.post('/api/request-otp', (req, res) => {
  const { phone } = req.body;
  if (!phone) return res.status(400).json({ success: false, message: 'กรุณากรอกเบอร์โทรศัพท์' });

  const generatedOtp = Math.floor(100000 + Math.random() * 900000).toString();
  otpStore[phone] = generatedOtp;

  console.log(`[OTP Mock] Phone: ${phone} | OTP: ${generatedOtp}`);

  res.json({
    success: true,
    message: 'ส่งรหัส OTP เรียบร้อยแล้ว (สำหรับทดสอบ OTP คือ: ' + generatedOtp + ')'
  });
});

// API สมัครสมาชิก
app.post('/api/register', async (req, res) => {
  const { username, password, confirmPassword, phone, otp, fullName, bankName, accountNumber, refCode } = req.body;

  if (!username || !password || !phone || !otp || !fullName || !bankName || !accountNumber) {
    return res.status(400).json({ success: false, message: 'กรุณากรอกข้อมูลให้ครบถ้วน' });
  }

  if (password !== confirmPassword) {
    return res.status(400).json({ success: false, message: 'รหัสผ่านและยืนยันรหัสผ่านไม่ตรงกัน' });
  }

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

    delete otpStore[phone];

    res.json({ success: true, message: 'สมัครสมาชิกสำเร็จ!', user: result.rows[0] });
  } catch (err) {
    if (err.code === '23505') {
      return res.status(400).json({ success: false, message: 'ชื่อผู้ใช้หรือเบอร์โทรศัพท์นี้มีในระบบแล้ว' });
    }
    console.error(err);
    res.status(500).json({ success: false, message: 'เกิดข้อผิดพลาดในการลงทะเบียน' });
  }
});

// API ล็อกอิน (ออก JWT Token ให้ Frontend)
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;

  try {
    const result = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
    if (result.rows.length === 0) {
      return res.status(400).json({ success: false, message: 'ไม่พบชื่อใช้งานนี้' });
    }

    const user = result.rows[0];
    const isMatch = await bcrypt.compare(password, user.password);

    if (!isMatch) {
      return res.status(400).json({ success: false, message: 'รหัสผ่านไม่ถูกต้อง' });
    }

    // สร้าง JWT Token รวมข้อมูล id, username และ role
    const token = jwt.sign(
      { id: user.id, username: user.username, role: user.role },
      JWT_SECRET,
      { expiresIn: '1d' }
    );

    res.json({
      success: true,
      message: 'ล็อกอินสำเร็จ!',
      token: token,
      user: {
        id: user.id,
        username: user.username,
        role: user.role
      }
    });

  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: 'เกิดข้อผิดพลาดในการล็อกอิน' });
  }
});

// API ดึงข้อมูลผู้ใช้ปัจจุบัน (ผ่าน Token)
app.get('/api/me', authenticateToken, (req, res) => {
  res.json({ success: true, user: req.user });
});

// API บันทึกโพยหวย
app.post('/api/bet', authenticateToken, async (req, res) => {
  const { number, betType, amount } = req.body;
  const playerName = req.user.username;

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
// 4. API สำหรับแอดมิน & Super Admin
// ==========================================

// ดึงโพยทั้งหมด (สำหรับ Admin & Super Admin)
app.get('/api/admin/bets', authenticateToken, isAdmin, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM bets ORDER BY created_at DESC');
    res.json({ success: true, bets: result.rows });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: 'ไม่สามารถดึงข้อมูลโพยได้' });
  }
});

// ดึงรายชื่อสมาชิกทั้งหมด (สำหรับ Super Admin เท่านั้น)
app.get('/api/admin/users', authenticateToken, verifySuperAdmin, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT id, username, phone, full_name, bank_name, account_number, role, created_at 
       FROM users 
       ORDER BY id ASC`
    );
    res.json({ success: true, users: result.rows });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: 'เกิดข้อผิดพลาดในการดึงข้อมูลสมาชิก' });
  }
});

// เปลี่ยน Role ของผู้ใช้งาน (สำหรับ Super Admin เท่านั้น)
app.put('/api/admin/users/:id/role', authenticateToken, verifySuperAdmin, async (req, res) => {
  const userId = req.params.id;
  const { role } = req.body;

  const allowedRoles = ['member', 'admin', 'superadmin'];
  if (!allowedRoles.includes(role)) {
    return res.status(400).json({ success: false, message: 'ยศ/บทบาทไม่ถูกต้อง' });
  }

  if (parseInt(userId) === req.user.id && role !== 'superadmin') {
    return res.status(400).json({ success: false, message: 'คุณไม่สามารถลดระดับสิทธิ์ Super Admin ของตัวเองได้' });
  }

  try {
    const result = await pool.query(
      `UPDATE users SET role = $1 WHERE id = $2 RETURNING id, username, role`,
      [role, userId]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ success: false, message: 'ไม่พบผู้ใช้นี้ในระบบ' });
    }

    res.json({ success: true, message: `อัปเดตสิทธิ์ของ ${result.rows[0].username} เป็น ${role} เรียบร้อยแล้ว`, user: result.rows[0] });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: 'เกิดข้อผิดพลาดในการอัปเดตสิทธิ์' });
  }
});

// ==========================================
// 5. เริ่มต้น Server
// ==========================================
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
