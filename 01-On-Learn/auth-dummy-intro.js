// ============= DEPENDENCIES =============
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const cors = require('cors');
const validator = require('validator');
require('dotenv').config();

const app = express();

// ============= SECURITY MIDDLEWARE =============
app.use(helmet());
app.use(cors({
  origin: process.env.FRONTEND_URL || 'http://localhost:3000',
  credentials: true
}));
app.use(express.json({ limit: '10mb' }));

// Rate limiting
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // 5 attempts per window
  message: { error: 'Too many authentication attempts, please try again later' },
  standardHeaders: true,
  legacyHeaders: false,
});

// ============= DATABASE CONNECTION =============
mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/auth_app', {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

// ============= USER SCHEMA =============
const userSchema = new mongoose.Schema({
  email: {
    type: String,
    required: true,
    unique: true,
    lowercase: true,
    validate: [validator.isEmail, 'Invalid email format']
  },
  password: {
    type: String,
    required: true,
    minlength: 8
  },
  refreshTokens: [{
    token: {
      type: String,
      required: true
    },
    createdAt: {
      type: Date,
      default: Date.now,
      expires: 604800 // 7 days in seconds
    }
  }],
  loginAttempts: {
    type: Number,
    default: 0
  },
  lockUntil: Date,
  emailVerified: {
    type: Boolean,
    default: false
  },
  role: {
    type: String,
    enum: ['user', 'admin'],
    default: 'user'
  }
}, {
  timestamps: true
});

// Virtual for checking if account is locked
userSchema.virtual('isLocked').get(function() {
  return !!(this.lockUntil && this.lockUntil > Date.now());
});

// Hash password before saving
userSchema.pre('save', async function(next) {
  if (!this.isModified('password')) return next();
  
  try {
    const saltRounds = 12;
    this.password = await bcrypt.hash(this.password, saltRounds);
    next();
  } catch (error) {
    next(error);
  }
});

// Method to compare passwords
userSchema.methods.comparePassword = async function(candidatePassword) {
  if (this.isLocked) {
    throw new Error('Account is temporarily locked');
  }
  
  const isMatch = await bcrypt.compare(candidatePassword, this.password);
  
  if (isMatch) {
    // Reset login attempts on successful login
    if (this.loginAttempts > 0) {
      this.loginAttempts = 0;
      this.lockUntil = undefined;
      await this.save();
    }
    return true;
  } else {
    // Increment login attempts
    this.loginAttempts += 1;
    
    // Lock account after 5 failed attempts for 2 hours
    if (this.loginAttempts >= 5) {
      this.lockUntil = Date.now() + 2 * 60 * 60 * 1000; // 2 hours
    }
    
    await this.save();
    return false;
  }
};

// Method to add refresh token
userSchema.methods.addRefreshToken = async function(refreshToken) {
  // Remove old tokens (keep only last 5)
  if (this.refreshTokens.length >= 5) {
    this.refreshTokens = this.refreshTokens.slice(-4);
  }
  
  this.refreshTokens.push({ token: refreshToken });
  await this.save();
};

// Method to remove refresh token
userSchema.methods.removeRefreshToken = async function(refreshToken) {
  this.refreshTokens = this.refreshTokens.filter(
    tokenObj => tokenObj.token !== refreshToken
  );
  await this.save();
};

const User = mongoose.model('User', userSchema);

// ============= JWT UTILITIES =============
const generateAccessToken = (userId, email, role) => {
  return jwt.sign(
    { userId, email, role },
    process.env.ACCESS_TOKEN_SECRET,
    { expiresIn: '15m' }
  );
};

const generateRefreshToken = (userId) => {
  return jwt.sign(
    { userId },
    process.env.REFRESH_TOKEN_SECRET,
    { expiresIn: '7d' }
  );
};

// ============= MIDDLEWARE =============
const authenticateToken = async (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  
  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }
  
  try {
    const decoded = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET);
    
    // Check if user still exists
    const user = await User.findById(decoded.userId);
    if (!user) {
      return res.status(401).json({ error: 'User not found' });
    }
    
    req.user = decoded;
    next();
  } catch (error) {
    if (error.name === 'TokenExpiredError') {
      return res.status(401).json({ error: 'Access token expired' });
    }
    return res.status(403).json({ error: 'Invalid access token' });
  }
};

// Input validation middleware
const validateRegistration = (req, res, next) => {
  const { email, password } = req.body;
  
  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password are required' });
  }
  
  if (!validator.isEmail(email)) {
    return res.status(400).json({ error: 'Invalid email format' });
  }
  
  if (password.length < 8) {
    return res.status(400).json({ error: 'Password must be at least 8 characters long' });
  }
  
  // Check password strength
  const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/;
  if (!passwordRegex.test(password)) {
    return res.status(400).json({ 
      error: 'Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character' 
    });
  }
  
  next();
};

// ============= ROUTES =============

// Register
app.post('/api/auth/register', authLimiter, validateRegistration, async (req, res) => {
  try {
    const { email, password } = req.body;
    
    // Check if user already exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(409).json({ error: 'User already exists' });
    }
    
    // Create new user
    const user = new User({ email, password });
    await user.save();
    
    // Generate tokens
    const accessToken = generateAccessToken(user._id, user.email, user.role);
    const refreshToken = generateRefreshToken(user._id);
    
    // Store refresh token
    await user.addRefreshToken(refreshToken);
    
    res.status(201).json({
      message: 'User registered successfully',
      accessToken,
      refreshToken,
      user: {
        id: user._id,
        email: user.email,
        role: user.role,
        emailVerified: user.emailVerified
      }
    });
    
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Login
app.post('/api/auth/login', authLimiter, async (req, res) => {
  try {
    const { email, password } = req.body;
    
    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required' });
    }
    
    // Find user
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    // Check if account is locked
    if (user.isLocked) {
      return res.status(423).json({ error: 'Account is temporarily locked due to too many failed login attempts' });
    }
    
    // Verify password
    const isValidPassword = await user.comparePassword(password);
    if (!isValidPassword) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    // Generate tokens
    const accessToken = generateAccessToken(user._id, user.email, user.role);
    const refreshToken = generateRefreshToken(user._id);
    
    // Store refresh token
    await user.addRefreshToken(refreshToken);
    
    res.json({
      message: 'Login successful',
      accessToken,
      refreshToken,
      user: {
        id: user._id,
        email: user.email,
        role: user.role,
        emailVerified: user.emailVerified
      }
    });
    
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Refresh Token
app.post('/api/auth/refresh', async (req, res) => {
  try {
    const { refreshToken } = req.body;
    
    if (!refreshToken) {
      return res.status(401).json({ error: 'Refresh token required' });
    }
    
    // Verify refresh token
    const decoded = jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET);
    
    // Find user and check if refresh token exists
    const user = await User.findById(decoded.userId);
    if (!user) {
      return res.status(401).json({ error: 'User not found' });
    }
    
    const tokenExists = user.refreshTokens.some(tokenObj => tokenObj.token === refreshToken);
    if (!tokenExists) {
      return res.status(401).json({ error: 'Invalid refresh token' });
    }
    
    // Generate new access token
    const newAccessToken = generateAccessToken(user._id, user.email, user.role);
    
    res.json({
      accessToken: newAccessToken
    });
    
  } catch (error) {
    if (error.name === 'TokenExpiredError') {
      return res.status(401).json({ error: 'Refresh token expired' });
    }
    console.error('Refresh token error:', error);
    res.status(403).json({ error: 'Invalid refresh token' });
  }
});

// Logout
app.post('/api/auth/logout', authenticateToken, async (req, res) => {
  try {
    const { refreshToken } = req.body;
    
    if (refreshToken) {
      const user = await User.findById(req.user.userId);
      if (user) {
        await user.removeRefreshToken(refreshToken);
      }
    }
    
    res.json({ message: 'Logged out successfully' });
    
  } catch (error) {
    console.error('Logout error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Logout from all devices
app.post('/api/auth/logout-all', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId);
    if (user) {
      user.refreshTokens = [];
      await user.save();
    }
    
    res.json({ message: 'Logged out from all devices successfully' });
    
  } catch (error) {
    console.error('Logout all error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Protected route example
app.get('/api/user/profile', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId).select('-password -refreshTokens');
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    res.json({ user });
    
  } catch (error) {
    console.error('Profile error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Change password
app.put('/api/user/change-password', authenticateToken, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;
    
    if (!currentPassword || !newPassword) {
      return res.status(400).json({ error: 'Current password and new password are required' });
    }
    
    const user = await User.findById(req.user.userId);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    // Verify current password
    const isValidPassword = await bcrypt.compare(currentPassword, user.password);
    if (!isValidPassword) {
      return res.status(401).json({ error: 'Current password is incorrect' });
    }
    
    // Validate new password
    if (newPassword.length < 8) {
      return res.status(400).json({ error: 'New password must be at least 8 characters long' });
    }
    
    const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/;
    if (!passwordRegex.test(newPassword)) {
      return res.status(400).json({ 
        error: 'New password must contain at least one uppercase letter, one lowercase letter, one number, and one special character' 
      });
    }
    
    // Update password
    user.password = newPassword;
    user.refreshTokens = []; // Invalidate all refresh tokens
    await user.save();
    
    res.json({ message: 'Password changed successfully' });
    
  } catch (error) {
    console.error('Change password error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Error handling middleware
app.use((error, req, res, next) => {
  console.error('Global error handler:', error);
  res.status(500).json({ error: 'Internal server error' });
});

// ============= SERVER START =============
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

module.exports = app;



// ----------------------------------------------------------------------------------------------------

# ============= .env file =============
# Copy this to .env file in your project root

# MongoDB Connection
MONGODB_URI=mongodb://localhost:27017/auth_app

# JWT Secrets (Generate strong random strings)
ACCESS_TOKEN_SECRET=your_super_secret_access_token_key_here_make_it_very_long_and_random
REFRESH_TOKEN_SECRET=your_super_secret_refresh_token_key_here_make_it_different_and_very_long

# Server Configuration
PORT=3000
NODE_ENV=development

# Frontend URL for CORS
FRONTEND_URL=http://localhost:3000

# ============= package.json =============
{
  "name": "secure-auth-api",
  "version": "1.0.0",
  "description": "Secure authentication API with JWT tokens",
  "main": "server.js",
  "scripts": {
    "start": "node server.js",
    "dev": "nodemon server.js",
    "test": "jest"
  },
  "dependencies": {
    "express": "^4.18.2",
    "mongoose": "^8.0.0",
    "bcrypt": "^5.1.1",
    "jsonwebtoken": "^9.0.2",
    "express-rate-limit": "^7.1.5",
    "helmet": "^7.1.0",
    "cors": "^2.8.5",
    "validator": "^13.11.0",
    "dotenv": "^16.3.1"
  },
  "devDependencies": {
    "nodemon": "^3.0.1",
    "jest": "^29.7.0",
    "supertest": "^6.3.3"
  },
  "keywords": [
    "authentication",
    "jwt",
    "express",
    "mongodb",
    "security"
  ],
  "author": "Your Name",
  "license": "MIT"
}

# ============= Installation Commands =============
# Run these commands to set up your project:

npm init -y
npm install express mongoose bcrypt jsonwebtoken express-rate-limit helmet cors validator dotenv
npm install --save-dev nodemon jest supertest

# Generate secure JWT secrets (run in terminal):
node -e "console.log('ACCESS_TOKEN_SECRET=' + require('crypto').randomBytes(64).toString('hex'))"
node -e "console.log('REFRESH_TOKEN_SECRET=' + require('crypto').randomBytes(64).toString('hex'))"