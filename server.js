require("dotenv").config();
const express = require("express");
const mysql = require("mysql2");
const bodyParser = require("body-parser");
const cors = require("cors");
const cloudinary = require('cloudinary').v2;
const multer = require('multer');
const upload = multer({ dest: 'uploads/' });
const fileUploader = require("express-fileupload");
const { GoogleGenerativeAI } = require("@google/generative-ai");
const nodemailer = require('nodemailer');
const app = express();

// ----------- MIDDLEWARE & CONFIG -----------
app.use(fileUploader());
app.use(cors({
  origin: 'https://plarena-2.onrender.com', // Change to your deployed frontend URL
  credentials: true
}));
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(express.static("public"));

cloudinary.config({
  cloud_name: process.env.CLOUD_NAME,
  api_key: process.env.CLOUD_API_KEY,
  api_secret: process.env.CLOUD_API_SECRET
});

const genAI = new GoogleGenerativeAI(process.env.GEMINI_API_KEY);
const model = genAI.getGenerativeModel({ model: "gemini-2.0-flash" });

const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});

// ================ DATABASE CONNECTION ================
const db = mysql.createConnection({
  host: process.env.DB_HOST || "defaultdb-jitesh365days-b913.j.aivencloud.com",
  port: process.env.DB_PORT || 26893,
  user: process.env.DB_USER || "avnadmin",
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME || "defaultdb",
  ssl: { rejectUnauthorized: false }
});
db.connect(err => {
  if (err) throw err;
  console.log("MySQL Connected!");
});

// =============== IN-MEMORY STORES ===============
const verificationCodes = {};
const loginOTPs = {};

// ============== EMAIL VERIFICATION ROUTES ==============
app.post("/sendVerificationCode", (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).send({ message: "Email is required!" });
  const code = Math.floor(100000 + Math.random() * 900000).toString();
  verificationCodes[email] = { code, expiry: Date.now() + 5 * 60 * 1000 };
  const mailOptions = {
    from: process.env.EMAIL_USER,
    to: email,
    subject: 'Plarena - Email Verification',
    html: `
      <div style="font-family: Arial,sans-serif;padding:20px;background:#f4f4f4;">
        <div style="max-width:600px;margin:0 auto;background:white;padding:30px;border-radius:10px;">
          <h2 style="color:#007bff;text-align:center;">Email Verification</h2>
          <p>Hello,</p>
          <p>Thank you for signing up! Your verification code is:</p>
          <div style="text-align:center;margin:30px 0;">
            <span style="font-size:32px;font-weight:bold;color:#007bff;letter-spacing:5px;">${code}</span>
          </div>
          <p>This code will expire in 5 minutes.</p>
          <p>If you didn't request this, please ignore this email.</p>
          <hr style="margin:20px 0;">
          <p style="color:#888;font-size:12px;">Plarena Platform</p>
        </div>
      </div>`
  };
  transporter.sendMail(mailOptions, (error, info) => {
    if (error) return res.status(500).send({ message: "Failed to send verification email!" });
    res.send({ message: "Verification code sent to your email!" });
  });
});

app.post("/verifyCode", (req, res) => {
  const { email, code } = req.body;
  if (!email || !code) return res.status(400).send({ message: "Email and code are required!" });
  const stored = verificationCodes[email];
  if (!stored) return res.status(400).send({ message: "No verification code found for this email!" });
  if (Date.now() > stored.expiry) {
    delete verificationCodes[email];
    return res.status(400).send({ message: "Verification code expired!" });
  }
  if (stored.code !== code) return res.status(400).send({ message: "Invalid verification code!" });
  delete verificationCodes[email];
  res.send({ message: "Email verified successfully!", verified: true });
});

// Signup with Verification
app.post("/signupWithVerification", (req, res) => {
  const { email, password, utype, verified } = req.body;
  if (!email || !password || !utype) return res.status(400).send({ message: "All fields are required!" });
  if (!verified) return res.status(400).send({ message: "Please verify your email first!" });
  const sql = "INSERT INTO users (emailid, password, utype) VALUES (?, ?, ?)";
  db.query(sql, [email, password, utype], (err) => {
    if (err) return res.status(400).send({ message: "Email already exists or database error!" });
    res.send({ message: "Signup Success! You can now login." });
  });
});

// ============== OTP LOGIN ==============
app.post("/sendLoginOTP", (req, res) => {
  const { emailid } = req.body;
  console.log("OTP request for:", emailid);

  if (!emailid){
  console.log("No emailid provided!"); 
  return res.status(400).send({ message: "Email is required!" });}

  db.query("SELECT * FROM users WHERE emailid = ?", [emailid], (err, results) => {
    if (err) {
      console.error("Check User Error:", err);
      return res.status(500).send({ message: "Database error!" });}
    if (results.length === 0) {
      console.log("User not found:", emailid);
      return res.status(404).send({ message: "User not found! Please signup first." });}
    if (results[0].status === 0) {
      console.log("Account blocked:", emailid);
      return res.status(403).send({ message: "Your account is blocked!" });}
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    loginOTPs[emailid] = { otp, expiry: Date.now() + 5 * 60 * 1000, utype: results[0].utype };
    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: emailid,
      subject: 'Plarena - Login OTP',
      html: `
        <div style="font-family:Arial,sans-serif;padding:20px;background:#f4f4f4;">
          <div style="max-width:600px;margin:0 auto;background:white;padding:30px;border-radius:10px;">
            <h2 style="color:#007bff;text-align:center;">🔐 Login OTP</h2>
            <p>Hello,</p>
            <p>Your One-Time Password for login is:</p>
            <div style="text-align:center;margin:30px 0;">
              <span style="font-size:36px;font-weight:bold;color:#007bff;letter-spacing:8px;background:#f0f0f0;padding:15px 30px;border-radius:8px;">${otp}</span>
            </div>
            <p style="color:#d9534f;font-weight:bold;">⏰ This OTP will expire in 5 minutes.</p>
            <p>If you didn't request this, please ignore this email.</p>
            <hr style="margin:20px 0;">
            <p style="color:#888;font-size:12px;text-align:center;">Plarena Platform</p>
          </div>
        </div>`
    };
    console.log("Sending OTP to:", emailid);
    transporter.sendMail(mailOptions, (error, info) => {
      if (error) {
        console.error("Email Send Error:", error); 
        return res.status(500).send({ message: "Failed to send OTP email!" });}
        console.log("Login OTP sent:", info.response);
      res.send({ message: "OTP sent to your email!" });
    });
  });
});

app.post("/loginWithOTP", (req, res) => {
  const { emailid, otp } = req.body;
  if (!emailid || !otp) return res.status(400).send("Email and OTP are required!");
  const stored = loginOTPs[emailid];
  if (!stored) return res.status(400).send("No OTP found for this email! Please request a new one.");
  if (Date.now() > stored.expiry) {
    delete loginOTPs[emailid];
    return res.status(400).send("OTP expired! Please request a new one.");
  }
  if (stored.otp !== otp) return res.status(401).send("Invalid OTP!");
  delete loginOTPs[emailid];
  res.json({ message: "Login successful!", utype: stored.utype, emailid: emailid });
});

// ============== USER AUTH & PASSWORD ENDPOINTS ==============
app.post("/signup", (req, res) => {
  const { email, password, utype } = req.body;
  if (!email || !password || !utype) {
    return res.status(400).send({ message: "All fields are required!" });
  }
  const sql = "INSERT INTO users (emailid, password, utype) VALUES (?, ?, ?)";
  db.query(sql, [email, password, utype], (err) => {
    if (err) return res.status(400).send({ message: "Email already exists or database error!" });
    res.send({ message: "Signup Success!" });
  });
});

app.post("/login", (req, res) => {
  const { emailid, password } = req.body;
  if (!emailid || !password) return res.status(400).send("All fields are required!");
  const query = "SELECT * FROM users WHERE emailid = ? AND password = ?";
  db.query(query, [emailid, password], (err, results) => {
    if (err) return res.status(500).send("Database error!");
    if (results.length > 0) {
      const user = results[0];
      if (user.status === 0) return res.status(403).send("Your account is blocked!");
      res.json({ message: "✅ Login successful!", utype: user.utype, emailid: user.emailid });
    } else {
      res.status(401).send("❌ Invalid email or password!");
    }
  });
});

app.put('/user/password', (req, res) => {
  const { emailid, oldpwd, newpwd } = req.body;
  if (!emailid || !oldpwd || !newpwd) return res.status(400).send("All fields are required!");
  db.query("SELECT * FROM users WHERE emailid=? AND password=?", [emailid, oldpwd], (err, results) => {
    if (err) return res.status(500).send("Database error!");
    if (!results.length) return res.status(401).send("Old password incorrect!");
    db.query("UPDATE users SET password=? WHERE emailid=?", [newpwd, emailid], (err2) => {
      if (err2) return res.status(500).send("Database error!");
      res.send("Password updated successfully!");
    });
  });
});

// ============== IMAGE UPLOAD (CLOUDINARY) ==============
app.post('/uploadImage', upload.single('image'), (req, res) => {
  if (!req.file) return res.status(400).send("No file uploaded");
  cloudinary.uploader.upload(req.file.path, (err, result) => {
    if (err) return res.status(500).send("Cloudinary upload failed");
    res.send({ url: result.secure_url });
  });
});

// ============== AI AADHAAR VERIFICATION (GEMINI/Cloudinary) ==============
async function extractAadhaarData(imgurl) {
  const prompt = "Read the text on picture and tell all the information in adhaar card and give output STRICTLY in JSON format {adhaar_number:'', name:'', gender:'', dob: ''}. Only output JSON, no code, no markdown!";
  const imageResp = await fetch(imgurl).then((response) => response.arrayBuffer());
  const result = await model.generateContent([
    { inlineData: { data: Buffer.from(imageResp).toString("base64"), mimeType: "image/jpeg" } }, 
    prompt
  ]);
  const cleaned = result.response.text().replace(/``````/g, '').trim();
  return JSON.parse(cleaned);
}
app.post("/picreader", async function (req, res) {
  if (!req.files || !req.files.imggg) return res.status(400).send("No file uploaded.");
  const fileName = req.files.imggg.name;
  const savePath = __dirname + "/public/uploads/" + fileName;
  await req.files.imggg.mv(savePath);
  try {
    const picUrlResult = await cloudinary.uploader.upload(savePath);
    const jsonData = await extractAadhaarData(picUrlResult.secure_url || picUrlResult.url);
    res.send(jsonData);
  } catch (err) {
    res.status(500).send({ error: err.message });
  }
});

// ============== PLAYER PROFILE ==============
app.get("/getPlayerProfile", (req, res) => {
  db.query("SELECT * FROM players WHERE emailid = ?", [req.query.emailid], (err, results) => {
    if (err) return res.status(500).send("DB error");
    res.json(results[0] || {});
  });
});
app.post("/updatePlayerProfile", (req, res) => {
  const data = req.body;
  db.query("REPLACE INTO players SET ?", data, (err) => {
    if (err) return res.status(500).send({ message: "DB error" });
    res.send({ message: "Profile saved!" });
  });
});

// ============== ORGANIZER PROFILE ==============
app.get("/getOrganizerDetails", (req, res) => {
  db.query("SELECT * FROM organizers WHERE emailid = ?", [req.query.emailid], (err, results) => {
    if (err) return res.status(500).send("DB error");
    res.json(results[0] || {});
  });
});
app.post("/updateOrganizerDetails", (req, res) => {
  const data = req.body;
  db.query("REPLACE INTO organizers SET ?", data, (err) => {
    if (err) return res.status(500).send({ message: "DB error" });
    res.send({ message: "Organizer details updated!" });
  });
});

// ============== TOURNAMENT MANAGEMENT ==============
app.post("/postTournament", (req, res) => {
  const data = req.body;
  db.query(
    "INSERT INTO tournaments(emailid, event, doe, toe, address, city, sports, minage, maxage, lastdate, fee, prize, contact) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    [data.emailid, data.event, data.doe, data.toe, data.address, data.city, data.sports, data.minage, data.maxage, data.lastdate, data.fee, data.prize, data.contact],
    (err) => {
      if (err) return res.status(500).send({ message: "Database error!" });
      res.send({ message: "Event posted successfully!" });
    }
  );
});
app.get("/getTournaments", (req, res) => {
  const emailid = req.query.emailid;
  db.query("SELECT * FROM tournaments WHERE emailid=?", [emailid], (err, results) => {
    if (err) return res.status(500).send("DB error");
    res.json(results);
  });
});
app.post("/deleteTournament", (req, res) => {
  const { rid } = req.body;
  db.query("DELETE FROM tournaments WHERE rid=?", [rid], (err) => {
    if (err) return res.status(500).send("DB error");
    res.send({ message: "Tournament deleted!" });
  });
});

// ============== TOURNAMENT FINDER ==============
app.get('/searchTournaments', (req, res) => {
  const { city, sports, age } = req.query;
  let sql = "SELECT * FROM tournaments WHERE 1=1";
  const params = [];
  if (city) {
    sql += " AND city = ?";
    params.push(city);
  }
  if (sports) {
    sql += " AND sports = ?";
    params.push(sports);
  }
  if (age) {
    sql += " AND minage <= ? AND maxage >= ?";
    params.push(age, age);
  }
  db.query(sql, params, (err, results) => {
    if (err) return res.status(500).json([]);
    res.json(results);
  });
});
app.get('/distinctCities', (req, res) => {
  db.query("SELECT DISTINCT city FROM tournaments", (err, results) => {
    if (err) return res.json([]);
    res.json(results.map(x => x.city));
  });
});
app.get('/distinctSports', (req, res) => {
  db.query("SELECT DISTINCT sports FROM tournaments", (err, results) => {
    if (err) return res.json([]);
    res.json(results.map(x => x.sports));
  });
});

// ============== ADMIN CONSOLE ==============
app.get("/admin/users", (req, res) => {
  db.query("SELECT emailid, utype, dos, status FROM users", (err, results) => {
    if (err) return res.status(500).json([]);
    res.json(results);
  });
});
app.get("/admin/players", (req, res) => {
  db.query("SELECT * FROM players", (err, results) => {
    if (err) return res.status(500).json([]);
    res.json(results);
  });
});
app.get("/admin/organizers", (req, res) => {
  db.query("SELECT * FROM organizers", (err, results) => {
    if (err) return res.status(500).json([]);
    res.json(results);
  });
});
app.get("/admin/tournaments", (req, res) => {
  db.query("SELECT * FROM tournaments", (err, results) => {
    if (err) return res.status(500).json([]);
    res.json(results);
  });
});
app.put("/admin/user/:emailid/block", (req, res) => {
  db.query("UPDATE users SET status=0 WHERE emailid=?", [req.params.emailid], (err) => {
    if (err) return res.status(500).send("DB Error");
    res.send({ message: "User blocked" });
  });
});
app.put("/admin/user/:emailid/resume", (req, res) => {
  db.query("UPDATE users SET status=1 WHERE emailid=?", [req.params.emailid], (err) => {
    if (err) return res.status(500).send("DB Error");
    res.send({ message: "User resumed" });
  });
});
app.delete("/admin/player/:emailid", (req, res) => {
  db.query("DELETE FROM players WHERE emailid=?", [req.params.emailid], (err) => {
    if (err) return res.status(500).send("DB Error");
    db.query("DELETE FROM users WHERE emailid=? AND utype='Player'", [req.params.emailid]);
    res.send({ message: "Player deleted" });
  });
});
app.delete("/admin/organizer/:emailid", (req, res) => {
  db.query("DELETE FROM organizers WHERE emailid=?", [req.params.emailid], (err) => {
    if (err) return res.status(500).send("DB Error");
    db.query("DELETE FROM users WHERE emailid=? AND utype='Organizer'", [req.params.emailid]);
    res.send({ message: "Organizer deleted" });
  });
});

// ============== TEST ROUTE ==============
app.get("/", (req, res) => {
  res.send("🚀 Server is working fine!");
});

// ============== SERVER START ==============
const PORT = process.env.PORT || 8005;
app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});
