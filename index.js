// ---------------------------------------------------------------
//  Rhythm & Rise – Auth Server (Email OTP via Nodemailer)
// ---------------------------------------------------------------

const path = require('path');
require('dotenv').config({ path: path.join(__dirname, '.env') });

const express    = require('express');
const cors       = require('cors');
const bcrypt     = require('bcryptjs');
const jwt        = require('jsonwebtoken');
const fs         = require('fs');
const nodemailer = require('nodemailer');
const helmet     = require('helmet');
const cookieParser = require('cookie-parser');
const rateLimit  = require('express-rate-limit');
const validator  = require('validator');
const xss        = require('xss');
const multer     = require('multer');

// ── Startup diagnostics ─────────────────────────────────────────
if (process.env.NODE_ENV !== 'production') {
  console.log('--- Auth Server Debug ---');
  console.log("EMAIL_USER:", process.env.EMAIL_USER);
  console.log("EMAIL_PASS EXISTS:", !!process.env.EMAIL_PASS);
  console.log('DEV_SKIP_EMAIL:', process.env.DEV_SKIP_EMAIL || 'false');
  console.log('-------------------------');
}

const app = express();

app.set('trust proxy', 1);

// ── Security Headers (Helmet) ────────────────────────────────────
app.use(helmet({
  crossOriginResourcePolicy: { policy: "cross-origin" } // Allow images/videos to load
}));

// ── CORS ─────────────────────────────────────────────────────────
app.use(cors({
  origin: process.env.FRONTEND_URL || 'https://rythmnrise.com',
  credentials: true
}));

// ── Body Parser & Cookie Parser ──────────────────────────────────
app.use(express.json({ limit: '10kb' })); // Prevent large payloads
app.use(cookieParser());

// ── Rate Limiting ────────────────────────────────────────────────
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 20, // limit each IP to 20 requests per windowMs
  message: { success: false, message: 'Too many requests, please try again later.' }
});

const uploadLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 50,
  message: { success: false, message: 'Too many uploads, please try again later.' }
});

// ── Constants ────────────────────────────────────────────────────
const USERS_FILE = path.join(__dirname, 'users.json');
const JWT_SECRET = process.env.JWT_SECRET || 'rhythm_rise_super_secret_key';
const UPLOADS_DIR = path.join(__dirname, 'uploads');

if (!fs.existsSync(UPLOADS_DIR)) fs.mkdirSync(UPLOADS_DIR);
app.use('/uploads', express.static(UPLOADS_DIR)); // Serve uploaded files

// ── File Upload Security (Multer) ────────────────────────────────
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, UPLOADS_DIR),
  filename: (req, file, cb) => {
    // Sanitize filename to prevent malicious extensions or paths
    const ext = path.extname(file.originalname).toLowerCase();
    const safeName = Date.now() + '-' + Math.round(Math.random() * 1E9) + ext;
    cb(null, safeName);
  }
});

const upload = multer({ 
  storage,
  limits: { fileSize: 50 * 1024 * 1024 }, // 50MB size limit
  fileFilter: (req, file, cb) => {
    // Validate MIME types strictly
    if (file.mimetype.startsWith('image/') || file.mimetype.startsWith('video/')) {
      cb(null, true);
    } else {
      cb(new Error('Only images and videos are allowed.'));
    }
  }
});

// ── Nodemailer transporter ───────────────────────────────────────
const transporter = nodemailer.createTransport({
  host: "smtp.gmail.com",
  port: 587,
  secure: false,           // use STARTTLS, not SSL
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  },
  tls: {
    rejectUnauthorized: false
  },
  // ✅ This is what forces IPv4 — must be at the TOP level, not inside tls
  family: 4
});
transporter.verify(function(error, success) {
  if (error) {
    console.log("Mail error:", error);
  } else {
    console.log("Mail server ready");
  }
});

// ── User helpers ─────────────────────────────────────────────────
const getUsers = () => {
  if (!fs.existsSync(USERS_FILE)) return [];
  try { return JSON.parse(fs.readFileSync(USERS_FILE)); }
  catch { return []; }
};

const saveUser = (user) => {
  const users = getUsers();
  users.push(user);
  fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));
};

// ── OTP store (in-memory) ────────────────────────────────────────
const otpStore = new Map();

// ── OTP generator ────────────────────────────────────────────────
const generateOTP = () => Math.floor(100000 + Math.random() * 900000).toString();

// ── Email OTP sender ─────────────────────────────────────────────
const sendEmailOTP = async (toEmail, otp) => {
  if (process.env.DEV_SKIP_EMAIL === 'true') {
    console.warn('⚠️  [EMAIL SKIPPED] DEV_SKIP_EMAIL=true');
    console.log(`🔑 [DEV OTP] ${toEmail} => ${otp}`);
    return;
  }
  console.log(`[Email] Sending OTP to ${toEmail}...`);
  try {
    const info = await transporter.sendMail({
      from: `"Rhythm & Rise" <${process.env.EMAIL_USER}>`,
      to: toEmail,
      subject: 'Your Rhythm & Rise Verification Code',
      html: `
        <div style="font-family: 'Segoe UI', Arial, sans-serif; max-width:480px; margin:auto; padding:32px; background:#fff; border-radius:16px; border:1px solid #eee;">
          <h2 style="color:#7c3aed; margin-bottom:8px;">Rhythm & Rise</h2>
          <p style="color:#555; margin-bottom:24px;">Your one-time verification code is:</p>
          <div style="background:#f5f3ff; border-radius:12px; padding:24px; text-align:center; margin-bottom:24px;">
            <h1 style="font-size:48px; letter-spacing:12px; color:#7c3aed; margin:0;">${otp}</h1>
          </div>
          <p style="color:#888; font-size:14px;">This code expires in <strong>5 minutes</strong>. Do not share it with anyone.</p>
        </div>
      `,
    });
    console.log(`[Email] OTP sent successfully. MessageId: ${info.messageId}`);
  } catch (err) {
    console.error('[Email] Failed to send OTP:', err.message);
    throw new Error(`Email delivery failed: ${err.message}`);
  }
};

// ================================================================
//  ROUTES
// ================================================================

// ── File Upload Endpoint ─────────────────────────────────────────
app.post('/api/upload', uploadLimiter, upload.single('media'), (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ success: false, message: 'No file uploaded or invalid format' });
    // Sanitize title
    const originalName = req.file.originalname.split('.')[0];
    const safeTitle = xss(originalName);
    
    // Construct absolute URL (using localhost for demo/local dev, ideally use req.get('host') + protocol)
    const protocol = req.protocol === 'https' ? 'https' : (req.get('X-Forwarded-Proto') || 'http');
    const host = req.get('host');
    const url = `${protocol}://${host}/uploads/${req.file.filename}`;

    res.status(200).json({ success: true, url, title: safeTitle });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// Apply rate limiter to auth routes
app.use('/api/auth', authLimiter);

// ── Signup Step 1: validate fields, send OTP to email ────────────
app.post('/api/auth/signup/step1', async (req, res) => {
  try {
    let { email, password, name } = req.body;

    if (!email || !password || !name) {
      return res.status(400).json({ success: false, message: 'Name, email and password are required' });
    }

    // Input Validation & Sanitization
    if (!validator.isEmail(email)) return res.status(400).json({ success: false, message: 'Invalid email format' });
    email = validator.normalizeEmail(email);
    name = xss(name.trim()); // Sanitize Name to prevent XSS

    const users = getUsers();
    if (users.find((u) => u.email === email)) {
      return res.status(400).json({ success: false, message: 'An account with this email already exists' });
    }

    const authorizedAdmin = process.env.ADMIN_EMAIL || 'rhythmandrise100@gmail.com';
    if (email.toLowerCase() === authorizedAdmin.toLowerCase()) {
      return res.status(403).json({ success: false, message: 'Admin accounts cannot be created via signup' });
    }

    const otp            = generateOTP();
    const verificationId = Date.now().toString();

    otpStore.set(verificationId, {
      otp,
      expires:  Date.now() + 5 * 60 * 1000,
      userData: { email, password: await bcrypt.hash(password, 10), name, role: 'user' },
    });

    await sendEmailOTP(email, otp);

    res.status(200).json({ success: true, verificationId, message: 'OTP sent to your email' });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Failed to send OTP' });
  }
});

// ── Signup Step 2: verify OTP, create account ────────────────────
app.post('/api/auth/signup/step2', async (req, res) => {
  try {
    const { otp, verificationId } = req.body;
    const stored = otpStore.get(verificationId);

    if (!stored)                      return res.status(400).json({ success: false, message: 'Invalid or expired session' });
    if (Date.now() > stored.expires)  return res.status(400).json({ success: false, message: 'OTP has expired' });
    if (otp !== stored.otp)           return res.status(400).json({ success: false, message: 'Incorrect OTP code' });

    saveUser(stored.userData);
    otpStore.delete(verificationId); // Invalidate OTP after use

    res.status(200).json({ success: true, message: 'Account created successfully' });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Verification failed' });
  }
});

// ── Login Step 1: validate credentials, send OTP ─────────────────
app.post('/api/auth/login/step1', async (req, res) => {
  try {
    let { email, password, role } = req.body;

    if (!email || !password) return res.status(400).json({ success: false, message: 'Email and password required' });
    
    email = validator.normalizeEmail(email);

    let user;
    if (role === 'admin') {
      const authorizedAdmin = process.env.ADMIN_EMAIL || 'rhythmandrise100@gmail.com';
      if (email.toLowerCase() !== authorizedAdmin.toLowerCase()) {
        return res.status(403).json({ success: false, message: 'Unauthorized admin account' });
      }
      if (password === '18*June*1976') {
        user = { email: authorizedAdmin, role: 'admin', name: 'Admin', otpEmail: authorizedAdmin };
      }
    } else {
      user = getUsers().find((u) => u.email.toLowerCase() === email.toLowerCase());
      if (user && !(await bcrypt.compare(password, user.password))) {
        user = null;
      }
    }

    if (!user) {
      return res.status(401).json({ success: false, message: 'Invalid email or password' });
    }

    const otp            = generateOTP();
    const verificationId = Date.now().toString();
    const otpTarget      = user.otpEmail || user.email;

    otpStore.set(verificationId, {
      otp,
      expires: Date.now() + 5 * 60 * 1000,
      user:    { email: user.email, role: user.role || role, name: user.name },
    });

    await sendEmailOTP(otpTarget, otp);

    res.status(200).json({ success: true, verificationId, message: `OTP sent to ${otpTarget}` });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Failed to send OTP' });
  }
});

// ── Login Step 2: verify OTP, issue JWT in HttpOnly Cookie ───────
app.post('/api/auth/login/step2', async (req, res) => {
  try {
    const { otp, verificationId } = req.body;
    const stored = otpStore.get(verificationId);

    if (!stored)                      return res.status(400).json({ success: false, message: 'Invalid session' });
    if (Date.now() > stored.expires)  return res.status(400).json({ success: false, message: 'OTP has expired' });
    if (otp !== stored.otp)           return res.status(400).json({ success: false, message: 'Incorrect OTP' });

    const token = jwt.sign(stored.user, JWT_SECRET, { expiresIn: '7d' });
    otpStore.delete(verificationId); // Invalidate OTP after use

    // Secure HttpOnly Cookie
    res.cookie('token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
    });

    res.status(200).json({ success: true, user: stored.user });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Login verification failed' });
  }
});

// ── Resend OTP ────────────────────────────────────────────────────
app.post('/api/auth/otp/resend', async (req, res) => {
  try {
    const { verificationId } = req.body;
    const stored = otpStore.get(verificationId);

    if (!stored) return res.status(400).json({ success: false, message: 'Invalid session' });

    const newOtp = generateOTP();
    stored.otp     = newOtp;
    stored.expires = Date.now() + 5 * 60 * 1000;

    const toEmail = stored.userData ? stored.userData.email : stored.user ? stored.user.email : null;
    if (!toEmail) return res.status(400).json({ success: false, message: 'Could not determine email address' });

    await sendEmailOTP(toEmail, newOtp);

    res.status(200).json({ success: true, verificationId, message: 'New OTP sent to your email' });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Failed to resend OTP' });
  }
});

// ── Verify Session via HttpOnly Cookie ───────────────────────────
app.get('/api/auth/verify', async (req, res) => {
  try {
    const token = req.cookies.token;
    if (!token) {
      return res.status(401).json({ success: false, message: 'No session cookie provided' });
    }
    const decoded = jwt.verify(token, JWT_SECRET);
    res.status(200).json({ success: true, user: decoded });
  } catch (err) {
    res.status(401).json({ success: false, message: 'Invalid or expired session' });
  }
});

// ── Logout ───────────────────────────────────────────────────────
app.post('/api/auth/logout', (req, res) => {
  res.clearCookie('token', {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict'
  });
  res.status(200).json({ success: true, message: 'Logged out successfully' });
});

// ── Global 404 handler ───────────────────────────────────────────
app.use((req, res) => {
  res.status(404).json({ success: false, message: `Route ${req.originalUrl} not found` });
});

// ── Global error handler ─────────────────────────────────────────
app.use((err, req, res, next) => {
  console.error('Global Error:', process.env.NODE_ENV === 'development' ? err : err.message);
  
  // Handle Multer payload too large error safely
  if (err.code === 'LIMIT_FILE_SIZE') {
    return res.status(413).json({ success: false, message: 'File is too large. Max size is 50MB.' });
  }

  res.status(err.status || 500).json({
    success: false,
    message: 'Internal Server Error',
    error: process.env.NODE_ENV === 'development' ? err.stack : undefined,
  });
});

// ── Start ────────────────────────────────────────────────────────
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`✅ Auth Server running on port ${PORT}`));
