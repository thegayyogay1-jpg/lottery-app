const express = require('express');
const { Pool } = require('pg');
const path = require('path');

const app = express();
app.use(express.json());
app.use(express.static('public'));

// เชื่อมต่อ PostgreSQL ผ่าน DATABASE_URL จาก Render
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL ? { rejectUnauthorized: false } : false
});

// สร้างตารางเก็บโพยหวยอัตโนมัติเมื่อเริ่มระบบ
async function initDB() {
  try {
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
    console.log("Database table initialized successfully.");
  } catch (err) {
    console.error("Error initializing DB:", err);
  }
}
initDB();

// API สำหรับบันทึกโพยหวย
app.post('/api/bet', async (req, res) => {
  const { playerName, number, betType, amount } = req.body;

  if (!playerName || !number || !betType || !amount) {
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

// API สำหรับดึงรายการโพยทั้งหมดมาดู
app.get('/api/bets', async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM bets ORDER BY created_at DESC');
    res.json({ success: true, bets: result.rows });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: 'ไม่สามารถดึงข้อมูลได้' });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
