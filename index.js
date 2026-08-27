const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken'); // ดึงการใช้งาน JWT เข้ามา

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
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        username VARCHAR(50) UNIQUE NOT NULL,
        password VARCHAR(255) NOT NULL,
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
    console.log("Database initialized successfully.");
  } catch (err) {
    console.error("Error initializing DB:", err);
  }
}
initDB();

// --- API สมัครสมาชิก (จากสเต็ปแรก) ---
app.post('/api/register', async (req, res) => {
  const { username, password, role } = req.body;

  if (!username || !password) {
    return res.status(400).json({ success: false, message: 'กรุณากรอกชื่อผู้ใช้และรหัสผ่าน' });
  }

  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const userRole = role === 'admin' ? 'admin' : 'member';

    const result = await pool.query(
      'INSERT INTO users (username, password, role) VALUES ($1, $2, $3) RETURNING id, username, role',
      [username, hashedPassword, userRole]
    );

    res.json({ success: true, message: 'สมัครสมาชิกสำเร็จ!', user: result.rows[0] });
  } catch (err) {
    if (err.code === '23505') {
      return res.status(400).json({ success: false, message: 'ชื่อผู้ใช้นี้มีในระบบแล้ว' });
    }
    console.error(err);
    res.status(500).json({ success: false, message: 'เกิดข้อผิดพลาดในการสมัครสมาชิก' });
  }
});

// --- API เข้าสู่ระบบ (NEW: สเต็ปที่ 2) ---
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ success: false, message: 'กรุณากรอกชื่อผู้ใช้และรหัสผ่าน' });
  }

  try {
    // 1. ค้นหาผู้ใช้จากชื่อ username
    const result = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
    if (result.rows.length === 0) {
      return res.status(400).json({ success: false, message: 'ชื่อผู้ใช้หรือรหัสผ่านไม่ถูกต้อง' });
    }

    const user = result.rows[0];

    // 2. ตรวจสอบรหัสผ่านว่าตรงกับที่เข้ารหัสไว้หรือไม่
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(400).json({ success: false, message: 'ชื่อผู้ใช้หรือรหัสผ่านไม่ถูกต้อง' });
    }

    // 3. สร้าง Token (บัตรผ่าน) ฝากข้อมูล id, username, role เอาไว้ มีอายุ 1 วัน
    const token = jwt.sign(
      { id: user.id, username: user.username, role: user.role },
      JWT_SECRET,
      { expiresIn: '24h' }
    );

    // ส่ง token และข้อมูลบทบาทกลับไปให้ Frontend
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

// ==========================================
// ส่วนที่ 3: ระบบป้องกัน (Middleware) & Dashboard
// ==========================================

// ฟังก์ชัน "ยามเฝ้าประตู" ตรวจสอบ Token
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  // ดึง token ออกมาจากรูปแบบ "Bearer <token>"
  const token = authHeader && authHeader.split(' ')[1]; 
  
  if (!token) return res.status(401).json({ success: false, message: 'ไม่พบ Token กรุณาล็อกอิน' });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ success: false, message: 'Token ไม่ถูกต้องหรือหมดอายุ' });
    req.user = user; // เอาข้อมูลผู้ใช้ (id, username, role) แปะไว้ใช้ต่อ
    next(); // ปล่อยให้ผ่านไปทำงานต่อได้
  });
};

// ฟังก์ชันเช็คสิทธิ์ว่าเป็น "แอดมิน" หรือไม่
const isAdmin = (req, res, next) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ success: false, message: 'ไม่มีสิทธิ์เข้าถึง เฉพาะแอดมินเท่านั้น' });
  }
  next();
};

// API สำหรับดึงข้อมูลโพยหวยทั้งหมด (ต้องล็อกอิน + เป็นแอดมิน ถึงจะดึงได้)
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
