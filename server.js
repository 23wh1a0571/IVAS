// ================= IMPORTS =================
const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const { body, validationResult } = require("express-validator");

const app = express();

// ================= MIDDLEWARE =================
app.use(cors());
app.use(express.json());

// ================= MONGODB CONNECTION =================
mongoose.connect("mongodb://127.0.0.1:27017/ivas_auth")
  .then(() => console.log("✅ MongoDB Connected"))
  .catch(err => console.log("❌ MongoDB Error:", err));

// ================= USER SCHEMA =================
const UserSchema = new mongoose.Schema({
  username: {
    type: String,
    required: true,
    unique: true,
    trim: true
  },
  password: {
    type: String,
    required: true
  }
});

const User = mongoose.model("User", UserSchema);

// ================= REGISTER =================
app.post(
  "/register",
  [
    body("username")
      .trim()
      .notEmpty()
      .withMessage("Username is required")
      .isLength({ min: 3 })
      .withMessage("Username must be at least 3 characters"),

    body("password")
      .notEmpty()
      .withMessage("Password is required")
      .isLength({ min: 3 })
      .withMessage("Password must be at least 3 characters")
  ],

  async (req, res) => {
    try {

      // Check validation errors
      const errors = validationResult(req);

      if (!errors.isEmpty()) {
        return res.status(400).json({
          success: false,
          errors: errors.array()
        });
      }

      let { username, password } = req.body;

      username = username.trim();

      console.log("📥 Incoming:", req.body);

      // Check existing user
      const existing = await User.findOne({
        username: { $eq: username }
      });

      console.log("🔍 Existing user:", existing);

      if (existing) {
        return res.json({
          success: false,
          message: "User already exists"
        });
      }

      // Hash password
      const hashedPassword = await bcrypt.hash(password, 10);

      // Create user
      await User.create({
        username,
        password: hashedPassword
      });

      console.log("✅ User registered:", username);

      res.json({
        success: true,
        message: "Registered successfully"
      });

    } catch (err) {

      console.log("❌ Error:", err);

      res.status(500).json({
        success: false,
        message: "Server error"
      });

    }
  }
);

// ================= LOGIN =================
app.post(
  "/login",
  [
    body("username")
      .trim()
      .notEmpty()
      .withMessage("Username is required"),

    body("password")
      .notEmpty()
      .withMessage("Password is required")
  ],

  async (req, res) => {
    try {

      // Check validation errors
      const errors = validationResult(req);

      if (!errors.isEmpty()) {
        return res.status(400).json({
          success: false,
          errors: errors.array()
        });
      }

      let { username, password } = req.body;

      username = username.trim();

      console.log("🔐 Login attempt:", username);

      const user = await User.findOne({ username });

      if (!user) {
        return res.json({
          success: false,
          message: "User not found"
        });
      }

      const isMatch = await bcrypt.compare(password, user.password);

      if (!isMatch) {
        return res.json({
          success: false,
          message: "Invalid password"
        });
      }

      console.log("✅ Login success:", username);

      res.json({
        success: true,
        message: "Login successful",
        username: user.username
      });

    } catch (err) {

      console.log("❌ Login error:", err);

      res.status(500).json({
        success: false,
        message: "Server error"
      });

    }
  }
);

// ================= TEST ROUTE =================
app.get("/", (req, res) => {
  res.send("🚀 IVAS Auth Server Running");
});

// ================= START SERVER =================
const PORT = 5000;

app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});
