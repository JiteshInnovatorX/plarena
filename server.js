require("dotenv").config();
const express = require("express");
const mysql = require("mysql2");
const bodyParser = require("body-parser");
const cors = require("cors");
const cloudinary = require('cloudinary').v2;
const fileUploader = require("express-fileupload");
const { GoogleGenerativeAI } = require("@google/generative-ai");
const nodemailer = require('nodemailer');
const fs = require("fs");
const path = require("path");
const fetch = (...args) => import('node-fetch').then(({ default: fetch }) => fetch(...args));

const app = express();

//// ----------- MIDDLEWARE & CONFIG ----------- ////
app.use(fileUploader());
app.use(cors({
  origin: true, // Allow all origins for the UI since they are on the same Render host or frontend host
  credentials: true
}));
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(express.static("public"));

// Create uploads directory if not exists
const uploadDir = path.join(__dirname, "public", "uploads");
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir, { recursive: true });
}

cloudinary.config({
  cloud_name: process.env.CLOUD_NAME,
  api_key: process.env.CLOUD_API_KEY,
  api_secret: process.env.CLOUD_API_SECRET
});

const genAI = new GoogleGenerativeAI(process.env.GEMINI_API_KEY);
const model = genAI.getGenerativeModel({ model: "gemini-2.0-flash" });



//// ================ DATABASE CONNECTION ================
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

//// =============== IN-MEMORY STORES ===============
const verificationCodes = {};
const loginOTPs = {};

//// ============== EMAIL VERIFICATION ROUTES ==============
app.post("/sendVerificationCode", (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).send({ message: "Email is required!" });
  const code = Math.floor(100000 + Math.random() * 900000).toString();
  verificationCodes[email] = { code, expiry: Date.now() + 5 * 60 * 1000 };
  const data = {
    service_id: 'service_cp5exqe',
    template_id: 'template_h5f57rm',
    user_id: '2hDhZJ6g23gN2iMBV',
    accessToken: 'CeMg6C4Xk-FjJ5UoMMNAd',
    template_params: {
      email: email,
      passcode: code,
      time: new Date(Date.now() + 5 * 60 * 1000).toLocaleTimeString()
    }
  };

  fetch('https://api.emailjs.com/api/v1.0/email/send', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data)
  })
    .then(resp => {
      if (!resp.ok) throw new Error("EmailJS API Error");
      res.send({ message: "Verification code sent to your email!" });
    })
    .catch(error => {
      console.error("EmailJS Error:", error);
      res.status(500).send({ message: "Failed to send verification email!" });
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

//// ============== OTP LOGIN ==============
app.post("/sendLoginOTP", (req, res) => {
  const { emailid } = req.body;
  console.log("OTP request for:", emailid);
  if (!emailid) {
    console.log("No emailid provided!");
    return res.status(400).send({ message: "Email is required!" });
  }
  db.query("SELECT * FROM users WHERE emailid = ?", [emailid], (err, results) => {
    if (err) {
      console.error("Check User Error:", err);
      return res.status(500).send({ message: "Database error!" });
    }
    if (results.length === 0) {
      console.log("User not found:", emailid);
      return res.status(404).send({ message: "User not found! Please signup first." });
    }
    if (results[0].status === 0) {
      console.log("Account blocked:", emailid);
      return res.status(403).send({ message: "Your account is blocked!" });
    }
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    loginOTPs[emailid] = { otp, expiry: Date.now() + 5 * 60 * 1000, utype: results[0].utype };
    const data = {
      service_id: 'service_cp5exqe',
      template_id: 'template_h5f57rm',
      user_id: '2hDhZJ6g23gN2iMBV',
      accessToken: 'CeMg6C4Xk-FjJ5UoMMNAd',
      template_params: {
        email: emailid,
        passcode: otp,
        time: new Date(Date.now() + 5 * 60 * 1000).toLocaleTimeString()
      }
    };

    console.log("Sending OTP to:", emailid, "via EmailJS");
    fetch('https://api.emailjs.com/api/v1.0/email/send', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data)
    })
      .then(resp => {
        if (!resp.ok) throw new Error("EmailJS API Error");
        console.log("Login OTP sent");
        res.send({ message: "OTP sent to your email!" });
      })
      .catch(error => {
        console.error("Email Send Error:", error);
        res.status(500).send({ message: "Failed to send OTP email!" });
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

//// ============== USER AUTH & PASSWORD ENDPOINTS ==============
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
      res.json({ message: "Login successful!", utype: user.utype, emailid: user.emailid });
    } else {
      res.status(401).send("Invalid email or password!");
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

//// ============== IMAGE UPLOAD (CLOUDINARY) ==============
app.post("/uploadImage", async function (req, res) {
  try {
    if (!req.files || !req.files.image) {
      console.log("No file uploaded");
      return res.status(400).json({ error: "No file uploaded" });
    }

    const file = req.files.image;

    // Validate file size (max 10MB)
    if (file.size > 10 * 1024 * 1024) {
      return res.status(400).json({ error: "File size exceeds 10MB limit" });
    }

    // Validate file type
    const allowedMimes = ['image/jpeg', 'image/png', 'image/gif', 'image/webp'];
    if (!allowedMimes.includes(file.mimetype)) {
      return res.status(400).json({ error: "Invalid file type. Only JPEG, PNG, GIF, WebP allowed" });
    }

    let fName = Date.now() + "-" + file.name.replace(/\s+/g, "_");
    let fullPath = path.join(uploadDir, fName);
    console.log("Saving file to:", fullPath);
    await file.mv(fullPath);

    console.log("Attempting Cloudinary upload...");
    const result = await cloudinary.uploader.upload(fullPath, {
      resource_type: "auto",
      timeout: 30000
    });
    console.log("Cloudinary upload result:", result.secure_url);

    // Delete local file after upload
    fs.unlink(fullPath, err => { if (err) console.error("File cleanup error:", err); });

    res.json({ url: result.secure_url, message: "Upload successful" });
  } catch (err) {
    console.error("Upload failed:", err);
    res.status(500).json({ error: "Cloudinary upload failed: " + err.message });
  }
});


//// ============== AI AADHAAR VERIFICATION (GEMINI/Cloudinary) ==============
async function extractAadhaarData(imgurl) {
  const prompt = "Read the text on the Aadhaar card image and extract ALL information. Return STRICTLY valid JSON format ONLY: {\"adhaar_number\": \"\", \"name\": \"\", \"gender\": \"\", \"dob\": \"\"} with no other text, markdown, or code blocks!";

  try {
    console.log("Fetching image from:", imgurl);
    const imageResp = await fetch(imgurl).then((response) => {
      if (!response.ok) throw new Error("Failed to fetch image from Cloudinary");
      return response.arrayBuffer();
    });

    console.log("Image fetched, sending to Gemini AI...");
    const result = await model.generateContent([
      { inlineData: { data: Buffer.from(imageResp).toString("base64"), mimeType: "image/jpeg" } },
      prompt
    ]);

    let aiText = result.response.text().trim();
    console.log("Raw Gemini AI response:", aiText);

    // Remove markdown code blocks if present
    aiText = aiText.replace(/```json\n?/g, '').replace(/```\n?/g, '').trim();

    // Extract JSON from the response
    let match = aiText.match(/\{[\s\S]*\}/);
    if (!match) {
      throw new Error("No JSON found in AI response: " + aiText);
    }

    const jsonData = JSON.parse(match[0]);
    console.log("Successfully parsed JSON:", jsonData);

    return jsonData;
  } catch (err) {
    console.error("Aadhaar extraction error:", err.message);
    throw new Error("Failed to extract Aadhaar data: " + err.message);
  }
}

app.post("/picreader", async (req, res) => {
  let savePath = null;
  try {
    // More precise logs for debugging
    if (!req.files) {
      console.log("No files found in request!");
      return res.status(400).json({ error: "No file uploaded" });
    }
    if (!req.files.imggg) {
      console.log("imggg field not found in files!", Object.keys(req.files));
      return res.status(400).json({ error: "No Aadhaar image uploaded. Expected field: 'imggg'" });
    }

    const file = req.files.imggg;

    // Validate file size (max 10MB)
    if (file.size > 10 * 1024 * 1024) {
      return res.status(400).json({ error: "File size exceeds 10MB limit" });
    }

    // Validate file type
    const allowedMimes = ['image/jpeg', 'image/png', 'image/gif', 'image/webp'];
    if (!allowedMimes.includes(file.mimetype)) {
      return res.status(400).json({ error: "Invalid file type. Only JPEG, PNG, GIF, WebP allowed" });
    }

    const fileName = Date.now() + "-" + file.name.replace(/\s+/g, "_");
    savePath = path.join(uploadDir, fileName);
    await file.mv(savePath);
    console.log("File saved to", savePath);

    // Upload to Cloudinary
    let picUrlResult;
    try {
      console.log("Uploading to Cloudinary...");
      picUrlResult = await cloudinary.uploader.upload(savePath, {
        resource_type: "auto",
        timeout: 30000
      });
      console.log("Cloudinary upload successful:", picUrlResult.secure_url);
    } catch (cloudErr) {
      console.error("Cloudinary upload failed:", cloudErr.message || cloudErr);
      // Clean up before returning error
      fs.unlink(savePath, (err) => { if (err) console.error("Cleanup error:", err); });
      return res.status(500).json({ error: "Cloudinary upload failed: " + cloudErr.message });
    }

    const cloudinaryUrl = picUrlResult.secure_url || picUrlResult.url;
    console.log("Using Cloudinary URL for AI extraction:", cloudinaryUrl);

    // Aadhaar Data Extraction
    let jsonData;
    try {
      jsonData = await extractAadhaarData(cloudinaryUrl);
      console.log("Gemini/AI extraction successful:", jsonData);
    } catch (aiErr) {
      console.error("Gemini extraction failed:", aiErr.message);
      // Still return success with just the image URL if AI fails
      jsonData = { url: cloudinaryUrl, error: "AI extraction failed but image uploaded successfully" };
    }

    // Include the Cloudinary URL in the response
    jsonData.url = cloudinaryUrl;
    res.json(jsonData);

  } catch (err) {
    console.error("Unhandled error in /picreader:", err);
    res.status(500).json({ error: "Processing failed: " + err.message });
  } finally {
    // Clean up local file
    if (savePath) {
      fs.unlink(savePath, (err) => {
        if (err) console.error("Failed to delete local upload:", err);
        else console.log("Local file cleaned up:", savePath);
      });
    }
  }
});

//// ============== PLAYER PROFILE ==============
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

//// ============== ORGANIZER PROFILE ==============
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

//// ============== TOURNAMENT MANAGEMENT ==============
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

//// ============== TOURNAMENT FINDER ==============
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

//// ============== ADMIN CONSOLE ==============
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

//// ============== TEST ROUTE ==============
app.get("/", (req, res) => {
  res.send("🚀 Server is working fine!");
});

//// ============== SERVER START ==============
const PORT = process.env.PORT || 8005;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
