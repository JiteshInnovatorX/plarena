require("dotenv").config();
const express = require("express");
const mysql = require("mysql2");
const bodyParser = require("body-parser");
const cors = require("cors");
const cloudinary = require("cloudinary").v2;
const fileUploader = require("express-fileupload");
const { GoogleGenerativeAI } = require("@google/generative-ai");
const nodemailer = require("nodemailer");
const fs = require("fs");
const path = require("path");

const app = express();

//// ----------- MIDDLEWARE ----------- ////
app.use(fileUploader());
app.use(cors({ origin: true, credentials: true }));
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(express.static("public"));

//// ----------- CLOUDINARY CONFIG ----------- ////
cloudinary.config({
  cloud_name: process.env.CLOUD_NAME,
  api_key: process.env.CLOUD_API_KEY,
  api_secret: process.env.CLOUD_API_SECRET,
});

//// ----------- GEMINI CONFIG ----------- ////
const genAI = new GoogleGenerativeAI(process.env.GEMINI_API_KEY);
const model = genAI.getGenerativeModel({ model: "gemini-2.0-flash" });

//// ----------- UPDATED EMAIL CONFIG (RENDER SAFE) ----------- ////
const transporter = nodemailer.createTransport({
  host: "smtp.gmail.com",
  port: 465,
  secure: true,
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
      ? process.env.EMAIL_PASS.replace(/\s/g, "")
      : "",
  },
  connectionTimeout: 10000,
});

// Verify SMTP connection on startup
transporter.verify((error, success) => {
  if (error) {
    console.error("SMTP Connection Error:", error);
  } else {
    console.log("SMTP Server Ready");
  }
});

//// ----------- DATABASE CONNECTION ----------- ////
const db = mysql.createConnection({
  host: process.env.DB_HOST,
  port: process.env.DB_PORT,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  ssl: { rejectUnauthorized: false },
});

db.connect((err) => {
  if (err) {
    console.error("Database connection failed:", err);
  } else {
    console.log("MySQL Connected!");
  }
});

//// ----------- OTP STORE ----------- ////
const loginOTPs = {};

//// ============== SEND LOGIN OTP ============== ////
app.post("/sendLoginOTP", (req, res) => {
  const { emailid } = req.body;

  if (!emailid) {
    return res.status(400).json({ message: "Email is required!" });
  }

  db.query(
    "SELECT * FROM users WHERE emailid = ?",
    [emailid],
    (err, results) => {
      if (err) {
        console.error("DB Error:", err);
        return res.status(500).json({ message: "Database error!" });
      }

      if (results.length === 0) {
        return res
          .status(404)
          .json({ message: "User not found! Please signup first." });
      }

      if (results[0].status === 0) {
        return res.status(403).json({ message: "Your account is blocked!" });
      }

      const otp = Math.floor(100000 + Math.random() * 900000).toString();

      loginOTPs[emailid] = {
        otp,
        expiry: Date.now() + 5 * 60 * 1000,
        utype: results[0].utype,
      };

      const mailOptions = {
        from: process.env.EMAIL_USER,
        to: emailid,
        subject: "Plarena - Login OTP",
        html: `<h2>Your OTP is: ${otp}</h2><p>Valid for 5 minutes.</p>`,
      };

      transporter.sendMail(mailOptions, (error, info) => {
        if (error) {
          console.error("Email Send Error FULL:", error);
          return res.status(500).json({
            message: "Failed to send OTP email!",
            error: error.message,
          });
        }

        console.log("OTP sent:", info.response);
        res.json({ message: "OTP sent to your email!" });
      });
    }
  );
});

//// ============== VERIFY OTP ============== ////
app.post("/loginWithOTP", (req, res) => {
  const { emailid, otp } = req.body;

  if (!emailid || !otp) {
    return res.status(400).json({ message: "Email and OTP required!" });
  }

  const stored = loginOTPs[emailid];

  if (!stored) {
    return res
      .status(400)
      .json({ message: "No OTP found. Please request again." });
  }

  if (Date.now() > stored.expiry) {
    delete loginOTPs[emailid];
    return res.status(400).json({ message: "OTP expired!" });
  }

  if (stored.otp !== otp) {
    return res.status(401).json({ message: "Invalid OTP!" });
  }

  delete loginOTPs[emailid];

  res.json({
    message: "Login successful!",
    utype: stored.utype,
    emailid,
  });
});

//// ----------- TEST ROUTE ----------- ////
app.get("/", (req, res) => {
  res.send("Server is working fine!");
});

//// ----------- SERVER START ----------- ////
const PORT = process.env.PORT || 8005;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});