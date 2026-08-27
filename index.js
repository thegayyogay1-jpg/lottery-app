const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');

const app = express();
app.use(express.json());
app.use(express.static('public'));

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL ? { rejectUnauthorized: false } : false
});

// สร้างตารางข้อมูลผู้ใช้ และ ตารางโพยหวย
async function initDB() {
  try {
    // 1. ตารางผู้ใช้งาน (users)
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        username VARCHAR(50) UNIQUE NOT NULL,
        password VARCHAR(255) NOT NULL,
        role VARCHAR(20) DEFAULT 'member',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);

    // 2. ตารางโพยหวย (bets)
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

// API สำหรับสมัครสมาชิก
app.post('/api/register', async (req, res) => {
  const { username, password, role } = req.body;

  if (!username || !password) {
    return res.status(400).json({ success: false, message: 'กรุณากรอกชื่อผู้ใช้และรหัสผ่าน' });
  }

  try {
    // เข้ารหัสรหัสผ่านก่อนบันทึกเพื่อความปลอดภัย
    const hashedPassword = await bcrypt.hash(password, 10);
    // กำหนดบทบาท (ถ้าไม่ระบุให้เป็น member ถ้าระบุว่าเป็น admin จะได้สิทธิ์แอดมิน)
    const userRole = role === 'admin' ? 'admin' : 'member';

    const result = await pool.query(
      'INSERT INTO users (username, password, role) VALUES ($1, $2, $3) RETURNING id, username, role',
      [username, hashedPassword, userRole]
    );

    res.json({ success: true, message: 'สมัครสมาชิกสำเร็จ!', user: result.rows[0] });
  } catch (err) {
    if (err.code === '23505') { // Error code จาก PostgreSQL เมื่อ username ซ้ำ
      return res.status(400).json({ success: false, message: 'ชื่อผู้ใช้นี้มีในระบบแล้ว' });
    }
    console.error(err);
    res.status(500).json({ success: false, message: 'เกิดข้อผิดพลาดในการสมัครสมาชิก' });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
