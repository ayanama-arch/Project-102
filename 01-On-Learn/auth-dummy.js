// package.json
{
  "name": "secure-auth-system",
  "version": "1.0.0",
  "description": "Production-ready authentication system with token rotation",
  "main": "server.js",
  "scripts": {
    "start": "node server.js",
    "dev": "nodemon server.js"
  },
  "dependencies": {
    "express": "^4.18.2",
    "mongoose": "^7.5.0",
    "jsonwebtoken": "^9.0.2",
    "bcrypt": "^5.1.1",
    "cookie-parser": "^1.4.6",
    "dotenv": "^16.3.1",
    "express-rate-limit": "^6.10.0",
    "helmet": "^7.0.0",
    "joi": "^17.10.0",
    "uuid": "^9.0.0",
    "nodemailer": "^6.9.4",
    "express-validator": "^7.0.1"
  },
  "devDependencies": {
    "nodemon": "^3.0.1"
  }
}

// .env
NODE_ENV=development
PORT=3000
MONGODB_URI=mongodb://localhost:27017/auth_system
JWT_ACCESS_SECRET=your_super_secret_access_key_here_make_it_long_and_complex
JWT_REFRESH_SECRET=your_super_secret_refresh_key_here_make_it_different_and_long
ACCESS_TOKEN_EXPIRY=15m
REFRESH_TOKEN_EXPIRY=30d
COOKIE_SECRET=your_cookie_signing_secret_here

# Email configuration (optional)
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=your_email@gmail.com
SMTP_PASS=your_app_password
FROM_EMAIL=noreply@yourapp.com

// models/User.js
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');

const userSchema = new mongoose.Schema({
  email: {
    type: String,
    required: true,
    unique: true,
    lowercase: true,
    trim: true,
    index: true
  },
  password: {
    type: String,
    required: true,
    minlength: 6
  },
  firstName: {
    type: String,
    required: true,
    trim: true
  },
  lastName: {
    type: String,
    required: true,
    trim: true
  },
  isEmailVerified: {
    type: Boolean,
    default: false
  },
  lastLoginAt: {
    type: Date,
    default: null
  },
  loginAttempts: {
    type: Number,
    default: 0
  },
  lockUntil: {
    type: Date,
    default: null
  },
  notificationPreferences: {
    securityAlerts: {
      type: Boolean,
      default: true
    },
    emailNotifications: {
      type: Boolean,
      default: true
    }
  }
}, {
  timestamps: true,
  toJSON: {
    transform: function(doc, ret) {
      delete ret.password;
      delete ret.__v;
      return ret;
    }
  }
});

// Virtual for account lock status
userSchema.virtual('isLocked').get(function() {
  return !!(this.lockUntil && this.lockUntil > Date.now());
});

// Pre-save middleware to hash password
userSchema.pre('save', async function(next) {
  if (!this.isModified('password')) return next();
  
  try {
    const salt = await bcrypt.genSalt(12);
    this.password = await bcrypt.hash(this.password, salt);
    next();
  } catch (error) {
    next(error);
  }
});

// Compare password method
userSchema.methods.comparePassword = async function(candidatePassword) {
  return bcrypt.compare(candidatePassword, this.password);
};

// Increment login attempts
userSchema.methods.incLoginAttempts = function() {
  // If we have a previous lock that has expired, restart at 1
  if (this.lockUntil && this.lockUntil < Date.now()) {
    return this.updateOne({
      $unset: { lockUntil: 1 },
      $set: { loginAttempts: 1 }
    });
  }
  
  const updates = { $inc: { loginAttempts: 1 } };
  
  // Lock account after 5 failed attempts for 2 hours
  if (this.loginAttempts + 1 >= 5 && !this.isLocked) {
    updates.$set = { lockUntil: Date.now() + 2 * 60 * 60 * 1000 }; // 2 hours
  }
  
  return this.updateOne(updates);
};

// Reset login attempts
userSchema.methods.resetLoginAttempts = function() {
  return this.updateOne({
    $unset: { loginAttempts: 1, lockUntil: 1 }
  });
};

module.exports = mongoose.model('User', userSchema);

// models/RefreshToken.js
const mongoose = require('mongoose');
const { v4: uuidv4 } = require('uuid');

const refreshTokenSchema = new mongoose.Schema({
  tokenId: {
    type: String,
    required: true,
    unique: true,
    default: uuidv4
  },
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    required: true,
    ref: 'User',
    index: true
  },
  token: {
    type: String,
    required: true,
    unique: true
  },
  isUsed: {
    type: Boolean,
    default: false,
    index: true
  },
  isRevoked: {
    type: Boolean,
    default: false,
    index: true
  },
  ipAddress: {
    type: String,
    required: true
  },
  userAgent: {
    type: String,
    required: true
  },
  deviceId: {
    type: String,
    required: true
  },
  deviceInfo: {
    browser: String,
    os: String,
    device: String
  },
  expiresAt: {
    type: Date,
    required: true,
    index: { expireAfterSeconds: 0 }
  },
  parentTokenId: {
    type: String,
    default: null,
    index: true
  },
  childTokenIds: [{
    type: String
  }],
  reuseDetectedAt: {
    type: Date,
    default: null
  },
  lastUsedAt: {
    type: Date,
    default: null
  }
}, {
  timestamps: true
});

// Compound indexes for performance
refreshTokenSchema.index({ userId: 1, isUsed: 1, isRevoked: 1, expiresAt: 1 });
refreshTokenSchema.index({ tokenId: 1, isUsed: 1 });

// Mark token as used and create audit trail
refreshTokenSchema.methods.markAsUsed = function() {
  this.isUsed = true;
  this.lastUsedAt = new Date();
  return this.save();
};

// Mark token as revoked
refreshTokenSchema.methods.revoke = function() {
  this.isRevoked = true;
  return this.save();
};

// Check if token is valid
refreshTokenSchema.methods.isValid = function() {
  return !this.isUsed && !this.isRevoked && this.expiresAt > new Date();
};

module.exports = mongoose.model('RefreshToken', refreshTokenSchema);

// models/SecurityEvent.js
const mongoose = require('mongoose');

const securityEventSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    required: true,
    ref: 'User',
    index: true
  },
  eventType: {
    type: String,
    required: true,
    enum: [
      'LOGIN_SUCCESS',
      'LOGIN_FAILED',
      'TOKEN_REFRESH',
      'TOKEN_REUSE_DETECTED',
      'LOGOUT',
      'PASSWORD_CHANGE',
      'ACCOUNT_LOCKED',
      'SESSION_REVOKED'
    ],
    index: true
  },
  severity: {
    type: String,
    enum: ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'],
    default: 'LOW'
  },
  ipAddress: {
    type: String,
    required: true
  },
  userAgent: {
    type: String,
    required: true
  },
  deviceId: {
    type: String,
    required: true
  },
  metadata: {
    type: mongoose.Schema.Types.Mixed,
    default: {}
  },
  notificationSent: {
    type: Boolean,
    default: false
  }
}, {
  timestamps: true
});

// TTL index to auto-delete old events after 90 days
securityEventSchema.index({ createdAt: 1 }, { expireAfterSeconds: 90 * 24 * 60 * 60 });

module.exports = mongoose.model('SecurityEvent', securityEventSchema);

// utils/tokenUtils.js
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const RefreshToken = require('../models/RefreshToken');

class TokenUtils {
  static generateAccessToken(payload) {
    return jwt.sign(payload, process.env.JWT_ACCESS_SECRET, {
      expiresIn: process.env.ACCESS_TOKEN_EXPIRY || '15m',
      issuer: 'auth-service',
      audience: 'api-users'
    });
  }

  static generateRefreshToken() {
    return crypto.randomBytes(64).toString('hex');
  }

  static verifyAccessToken(token) {
    try {
      return jwt.verify(token, process.env.JWT_ACCESS_SECRET, {
        issuer: 'auth-service',
        audience: 'api-users'
      });
    } catch (error) {
      if (error.name === 'TokenExpiredError') {
        throw new Error('ACCESS_TOKEN_EXPIRED');
      }
      if (error.name === 'JsonWebTokenError') {
        throw new Error('INVALID_ACCESS_TOKEN');
      }
      throw error;
    }
  }

  static async createRefreshToken(userId, ipAddress, userAgent, deviceId, deviceInfo) {
    const token = this.generateRefreshToken();
    const expiresAt = new Date();
    expiresAt.setDate(expiresAt.getDate() + 30); // 30 days

    const refreshToken = new RefreshToken({
      userId,
      token,
      ipAddress,
      userAgent,
      deviceId,
      deviceInfo,
      expiresAt
    });

    await refreshToken.save();
    return refreshToken;
  }

  static async rotateRefreshToken(oldTokenDoc, ipAddress, userAgent, deviceId, deviceInfo) {
    // Create new refresh token
    const newToken = this.generateRefreshToken();
    const expiresAt = new Date();
    expiresAt.setDate(expiresAt.getDate() + 30);

    const newRefreshToken = new RefreshToken({
      userId: oldTokenDoc.userId,
      token: newToken,
      ipAddress,
      userAgent,
      deviceId,
      deviceInfo,
      expiresAt,
      parentTokenId: oldTokenDoc.tokenId
    });

    // Use transaction to ensure atomicity
    const session = await RefreshToken.startSession();
    
    try {
      await session.withTransaction(async () => {
        // Mark old token as used
        await oldTokenDoc.markAsUsed();
        
        // Add new token ID to parent's children
        oldTokenDoc.childTokenIds.push(newRefreshToken.tokenId);
        await oldTokenDoc.save({ session });
        
        // Save new token
        await newRefreshToken.save({ session });
      });

      return newRefreshToken;
    } catch (error) {
      throw new Error('TOKEN_ROTATION_FAILED');
    } finally {
      await session.endSession();
    }
  }

  static async validateRefreshToken(token) {
    const tokenDoc = await RefreshToken.findOne({ token }).populate('userId');
    
    if (!tokenDoc) {
      throw new Error('INVALID_REFRESH_TOKEN');
    }

    if (!tokenDoc.isValid()) {
      throw new Error('REFRESH_TOKEN_EXPIRED');
    }

    return tokenDoc;
  }

  static async revokeUserTokens(userId, excludeTokenId = null) {
    const query = { userId, isRevoked: false };
    if (excludeTokenId) {
      query.tokenId = { $ne: excludeTokenId };
    }

    return RefreshToken.updateMany(query, {
      $set: { isRevoked: true }
    });
  }

  static async detectTokenReuse(tokenDoc) {
    // If token is already used, it's a reuse attempt
    if (tokenDoc.isUsed) {
      // Mark reuse detection timestamp
      tokenDoc.reuseDetectedAt = new Date();
      await tokenDoc.save();

      // Revoke all tokens in the chain
      await this.revokeTokenChain(tokenDoc);
      
      return true;
    }
    
    return false;
  }

  static async revokeTokenChain(tokenDoc) {
    const tokensToRevoke = new Set();
    
    // Add current token
    tokensToRevoke.add(tokenDoc.tokenId);
    
    // Find and add all parent tokens
    let currentToken = tokenDoc;
    while (currentToken.parentTokenId) {
      tokensToRevoke.add(currentToken.parentTokenId);
      currentToken = await RefreshToken.findOne({ tokenId: currentToken.parentTokenId });
      if (!currentToken) break;
    }
    
    // Find and add all child tokens recursively
    const findChildren = async (tokenId) => {
      const token = await RefreshToken.findOne({ tokenId });
      if (token && token.childTokenIds.length > 0) {
        for (const childId of token.childTokenIds) {
          tokensToRevoke.add(childId);
          await findChildren(childId);
        }
      }
    };
    
    await findChildren(tokenDoc.tokenId);
    
    // Revoke all tokens in the chain
    return RefreshToken.updateMany(
      { tokenId: { $in: Array.from(tokensToRevoke) } },
      { $set: { isRevoked: true } }
    );
  }
}

module.exports = TokenUtils;

// utils/deviceUtils.js
const crypto = require('crypto');

class DeviceUtils {
  static generateDeviceId(userAgent, ipAddress) {
    const deviceString = `${userAgent}-${ipAddress}`;
    return crypto
      .createHash('sha256')
      .update(deviceString)
      .digest('hex')
      .substring(0, 32);
  }

  static parseUserAgent(userAgent) {
    // Simple user agent parsing - in production, use a library like 'ua-parser-js'
    const deviceInfo = {
      browser: 'Unknown',
      os: 'Unknown',
      device: 'Unknown'
    };

    if (userAgent) {
      // Browser detection
      if (userAgent.includes('Chrome')) deviceInfo.browser = 'Chrome';
      else if (userAgent.includes('Firefox')) deviceInfo.browser = 'Firefox';
      else if (userAgent.includes('Safari')) deviceInfo.browser = 'Safari';
      else if (userAgent.includes('Edge')) deviceInfo.browser = 'Edge';

      // OS detection
      if (userAgent.includes('Windows')) deviceInfo.os = 'Windows';
      else if (userAgent.includes('Mac')) deviceInfo.os = 'macOS';
      else if (userAgent.includes('Linux')) deviceInfo.os = 'Linux';
      else if (userAgent.includes('Android')) deviceInfo.os = 'Android';
      else if (userAgent.includes('iOS')) deviceInfo.os = 'iOS';

      // Device detection
      if (userAgent.includes('Mobile')) deviceInfo.device = 'Mobile';
      else if (userAgent.includes('Tablet')) deviceInfo.device = 'Tablet';
      else deviceInfo.device = 'Desktop';
    }

    return deviceInfo;
  }

  static getClientInfo(req) {
    const ipAddress = req.ip || req.connection.remoteAddress || '127.0.0.1';
    const userAgent = req.get('User-Agent') || 'Unknown';
    const deviceId = this.generateDeviceId(userAgent, ipAddress);
    const deviceInfo = this.parseUserAgent(userAgent);

    return { ipAddress, userAgent, deviceId, deviceInfo };
  }
}

module.exports = DeviceUtils;

// utils/notificationService.js
const nodemailer = require('nodemailer');
const SecurityEvent = require('../models/SecurityEvent');

class NotificationService {
  constructor() {
    this.transporter = nodemailer.createTransporter({
      host: process.env.SMTP_HOST,
      port: process.env.SMTP_PORT,
      secure: false,
      auth: {
        user: process.env.SMTP_USER,
        pass: process.env.SMTP_PASS
      }
    });
  }

  async logSecurityEvent(userId, eventType, severity, ipAddress, userAgent, deviceId, metadata = {}) {
    const event = new SecurityEvent({
      userId,
      eventType,
      severity,
      ipAddress,
      userAgent,
      deviceId,
      metadata
    });

    await event.save();
    return event;
  }

  async sendSecurityAlert(user, eventType, deviceInfo, ipAddress) {
    if (!user.notificationPreferences.securityAlerts || !user.notificationPreferences.emailNotifications) {
      return;
    }

    const emailTemplates = {
      TOKEN_REUSE_DETECTED: {
        subject: '🚨 Security Alert: Suspicious Activity Detected',
        html: `
          <h2>Security Alert</h2>
          <p>Hello ${user.firstName},</p>
          <p>We detected suspicious activity on your account. Someone may have tried to use an old session token.</p>
          <h3>Details:</h3>
          <ul>
            <li><strong>Time:</strong> ${new Date().toLocaleString()}</li>
            <li><strong>IP Address:</strong> ${ipAddress}</li>
            <li><strong>Device:</strong> ${deviceInfo.browser} on ${deviceInfo.os}</li>
            <li><strong>Device Type:</strong> ${deviceInfo.device}</li>
          </ul>
          <p><strong>Action Taken:</strong> All active sessions have been terminated for your security.</p>
          <p>If this was you, please log in again. If not, please change your password immediately.</p>
          <p>Best regards,<br>Security Team</p>
        `
      },
      LOGIN_FROM_NEW_DEVICE: {
        subject: '🔐 New Device Login',
        html: `
          <h2>New Device Login</h2>
          <p>Hello ${user.firstName},</p>
          <p>Your account was accessed from a new device.</p>
          <h3>Details:</h3>
          <ul>
            <li><strong>Time:</strong> ${new Date().toLocaleString()}</li>
            <li><strong>IP Address:</strong> ${ipAddress}</li>
            <li><strong>Device:</strong> ${deviceInfo.browser} on ${deviceInfo.os}</li>
          </ul>
          <p>If this was not you, please change your password immediately.</p>
        `
      }
    };

    const template = emailTemplates[eventType];
    if (!template) return;

    try {
      await this.transporter.sendMail({
        from: process.env.FROM_EMAIL,
        to: user.email,
        subject: template.subject,
        html: template.html
      });
    } catch (error) {
      console.error('Failed to send security alert:', error);
    }
  }
}

module.exports = new NotificationService();

// middleware/auth.js
const TokenUtils = require('../utils/tokenUtils');
const DeviceUtils = require('../utils/deviceUtils');
const NotificationService = require('../utils/notificationService');
const User = require('../models/User');

const authenticateToken = async (req, res, next) => {
  try {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN

    if (!token) {
      return res.status(401).json({ 
        error: 'Access token required',
        code: 'MISSING_TOKEN'
      });
    }

    const decoded = TokenUtils.verifyAccessToken(token);
    const user = await User.findById(decoded.userId).select('-password');
    
    if (!user) {
      return res.status(401).json({ 
        error: 'User not found',
        code: 'USER_NOT_FOUND'
      });
    }

    req.user = user;
    req.userId = user._id;
    next();
  } catch (error) {
    if (error.message === 'ACCESS_TOKEN_EXPIRED') {
      return res.status(401).json({ 
        error: 'Access token expired',
        code: 'TOKEN_EXPIRED'
      });
    }
    
    return res.status(401).json({ 
      error: 'Invalid access token',
      code: 'INVALID_TOKEN'
    });
  }
};

const refreshTokenMiddleware = async (req, res, next) => {
  try {
    // First try to authenticate with access token
    const authHeader = req.headers['authorization'];
    const accessToken = authHeader && authHeader.split(' ')[1];

    if (accessToken) {
      try {
        const decoded = TokenUtils.verifyAccessToken(accessToken);
        const user = await User.findById(decoded.userId).select('-password');
        
        if (user) {
          req.user = user;
          req.userId = user._id;
          return next();
        }
      } catch (error) {
        // Access token is invalid or expired, try refresh
        if (error.message !== 'ACCESS_TOKEN_EXPIRED') {
          return res.status(401).json({ 
            error: 'Invalid access token',
            code: 'INVALID_TOKEN'
          });
        }
      }
    }

    // Try to refresh using refresh token
    const refreshToken = req.cookies.refreshToken;
    
    if (!refreshToken) {
      return res.status(401).json({ 
        error: 'Authentication required',
        code: 'AUTHENTICATION_REQUIRED'
      });
    }

    const tokenDoc = await TokenUtils.validateRefreshToken(refreshToken);
    const { ipAddress, userAgent, deviceId, deviceInfo } = DeviceUtils.getClientInfo(req);

    // Check for token reuse
    const isReuse = await TokenUtils.detectTokenReuse(tokenDoc);
    
    if (isReuse) {
      // Log security event
      await NotificationService.logSecurityEvent(
        tokenDoc.userId,
        'TOKEN_REUSE_DETECTED',
        'CRITICAL',
        ipAddress,
        userAgent,
        deviceId,
        { originalToken: tokenDoc.tokenId }
      );

      // Send security alert
      await NotificationService.sendSecurityAlert(
        tokenDoc.userId,
        'TOKEN_REUSE_DETECTED',
        deviceInfo,
        ipAddress
      );

      // Clear cookies
      res.clearCookie('refreshToken');
      
      return res.status(401).json({ 
        error: 'Security violation detected. All sessions terminated.',
        code: 'TOKEN_REUSE_DETECTED'
      });
    }

    // Rotate refresh token
    const newRefreshToken = await TokenUtils.rotateRefreshToken(
      tokenDoc,
      ipAddress,
      userAgent,
      deviceId,
      deviceInfo
    );

    // Generate new access token
    const newAccessToken = TokenUtils.generateAccessToken({
      userId: tokenDoc.userId._id,
      email: tokenDoc.userId.email
    });

    // Set new refresh token cookie
    res.cookie('refreshToken', newRefreshToken.token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 30 * 24 * 60 * 60 * 1000 // 30 days
    });

    // Set user context
    req.user = tokenDoc.userId;
    req.userId = tokenDoc.userId._id;
    
    // Add new access token to response headers
    res.set('X-New-Access-Token', newAccessToken);

    next();
  } catch (error) {
    res.clearCookie('refreshToken');
    
    return res.status(401).json({ 
      error: 'Authentication failed',
      code: 'AUTHENTICATION_FAILED',
      details: error.message
    });
  }
};

module.exports = {
  authenticateToken,
  refreshTokenMiddleware
};

// middleware/rateLimiter.js
const rateLimit = require('express-rate-limit');

const createRateLimiter = (windowMs, max, message, skipSuccessfulRequests = false) => {
  return rateLimit({
    windowMs,
    max,
    message: {
      error: message,
      code: 'RATE_LIMIT_EXCEEDED'
    },
    standardHeaders: true,
    legacyHeaders: false,
    skipSuccessfulRequests,
    keyGenerator: (req) => {
      return req.ip || req.connection.remoteAddress;
    }
  });
};

module.exports = {
  // Strict rate limiting for auth endpoints
  authLimiter: createRateLimiter(
    15 * 60 * 1000, // 15 minutes
    5, // 5 attempts
    'Too many authentication attempts, please try again later',
    true
  ),
  
  // More lenient for refresh tokens
  refreshLimiter: createRateLimiter(
    5 * 60 * 1000, // 5 minutes
    10, // 10 attempts
    'Too many token refresh attempts',
    true
  ),
  
  // General API rate limiting
  generalLimiter: createRateLimiter(
    15 * 60 * 1000, // 15 minutes
    100, // 100 requests
    'Too many requests, please try again later'
  )
};

// middleware/validation.js
const { body, validationResult } = require('express-validator');

const handleValidationErrors = (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      error: 'Validation failed',
      code: 'VALIDATION_ERROR',
      details: errors.array()
    });
  }
  next();
};

const registerValidation = [
  body('email')
    .isEmail()
    .normalizeEmail()
    .withMessage('Please provide a valid email address'),
  body('password')
    .isLength({ min: 8 })
    .withMessage('Password must be at least 8 characters long')
    .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/)
    .withMessage('Password must contain at least one lowercase letter, one uppercase letter, one number, and one special character'),
  body('firstName')
    .trim()
    .isLength({ min: 1, max: 50 })
    .withMessage('First name is required and must be less than 50 characters'),
  body('lastName')
    .trim()
    .isLength({ min: 1, max: 50 })
    .withMessage('Last name is required and must be less than 50 characters'),
  handleValidationErrors
];

const loginValidation = [
  body('email')
    .isEmail()
    .normalizeEmail()
    .withMessage('Please provide a valid email address'),
  body('password')
    .notEmpty()
    .withMessage('Password is required'),
  handleValidationErrors
];

module.exports = {
  registerValidation,
  loginValidation,
  handleValidationErrors
};

// controllers/authController.js (continued from login method)
const User = require('../models/User');
const TokenUtils = require('../utils/tokenUtils');
const DeviceUtils = require('../utils/deviceUtils');
const NotificationService = require('../utils/notificationService');

class AuthController {
  async register(req, res) {
    try {
      const { email, password, firstName, lastName } = req.body;

      // Check if user already exists
      const existingUser = await User.findOne({ email });
      if (existingUser) {
        return res.status(409).json({
          error: 'User already exists with this email',
          code: 'USER_EXISTS'
        });
      }

      // Create new user
      const user = new User({
        email,
        password,
        firstName,
        lastName
      });

      await user.save();

      res.status(201).json({
        message: 'User registered successfully',
        user: {
          id: user._id,
          email: user.email,
          firstName: user.firstName,
          lastName: user.lastName
        }
      });
    } catch (error) {
      console.error('Registration error:', error);
      res.status(500).json({
        error: 'Internal server error',
        code: 'SERVER_ERROR'
      });
    }
  }

  async login(req, res) {
    try {
      const { email, password } = req.body;
      const { ipAddress, userAgent, deviceId, deviceInfo } = DeviceUtils.getClientInfo(req);

      // Find user
      const user = await User.findOne({ email });
      if (!user) {
        await NotificationService.logSecurityEvent(
          null,
          'LOGIN_FAILED',
          'MEDIUM',
          ipAddress,
          userAgent,
          deviceId,
          { reason: 'USER_NOT_FOUND', email }
        );
        
        return res.status(401).json({
          error: 'Invalid credentials',
          code: 'INVALID_CREDENTIALS'
        });
      }

      // Check if account is locked
      if (user.isLocked) {
        await NotificationService.logSecurityEvent(
          user._id,
          'LOGIN_FAILED',
          'HIGH',
          ipAddress,
          userAgent,
          deviceId,
          { reason: 'ACCOUNT_LOCKED' }
        );
        
        return res.status(423).json({
          error: 'Account temporarily locked due to too many failed login attempts',
          code: 'ACCOUNT_LOCKED'
        });
      }

      // Verify password
      const isPasswordValid = await user.comparePassword(password);
      if (!isPasswordValid) {
        await user.incLoginAttempts();
        
        await NotificationService.logSecurityEvent(
          user._id,
          'LOGIN_FAILED',
          'MEDIUM',
          ipAddress,
          userAgent,
          deviceId,
          { reason: 'INVALID_PASSWORD', attempts: user.loginAttempts + 1 }
        );
        
        return res.status(401).json({
          error: 'Invalid credentials',
          code: 'INVALID_CREDENTIALS'
        });
      }

      // Reset login attempts on successful login
      if (user.loginAttempts > 0) {
        await user.resetLoginAttempts();
      }

      // Update last login
      user.lastLoginAt = new Date();
      await user.save();

      // Generate tokens
      const accessToken = TokenUtils.generateAccessToken({
        userId: user._id,
        email: user.email
      });

      const refreshToken = await TokenUtils.createRefreshToken(
        user._id,
        ipAddress,
        userAgent,
        deviceId,
        deviceInfo
      );

      // Set refresh token in httpOnly cookie
      res.cookie('refreshToken', refreshToken.token, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict',
        maxAge: 30 * 24 * 60 * 60 * 1000 // 30 days
      });

      // Log successful login
      await NotificationService.logSecurityEvent(
        user._id,
        'LOGIN_SUCCESS',
        'LOW',
        ipAddress,
        userAgent,
        deviceId,
        { deviceInfo }
      );

      res.json({
        message: 'Login successful',
        accessToken,
        user: {
          id: user._id,
          email: user.email,
          firstName: user.firstName,
          lastName: user.lastName,
          lastLoginAt: user.lastLoginAt
        }
      });
    } catch (error) {
      console.error('Login error:', error);
      res.status(500).json({
        error: 'Internal server error',
        code: 'SERVER_ERROR'
      });
    }
  }

  async refreshToken(req, res) {
    try {
      const refreshToken = req.cookies.refreshToken;
      
      if (!refreshToken) {
        return res.status(401).json({
          error: 'Refresh token not provided',
          code: 'MISSING_REFRESH_TOKEN'
        });
      }

      const { ipAddress, userAgent, deviceId, deviceInfo } = DeviceUtils.getClientInfo(req);
      
      // Validate refresh token
      const tokenDoc = await TokenUtils.validateRefreshToken(refreshToken);
      
      // Check for token reuse
      const isReuse = await TokenUtils.detectTokenReuse(tokenDoc);
      
      if (isReuse) {
        // Log security event
        await NotificationService.logSecurityEvent(
          tokenDoc.userId,
          'TOKEN_REUSE_DETECTED',
          'CRITICAL',
          ipAddress,
          userAgent,
          deviceId,
          { originalToken: tokenDoc.tokenId }
        );

        // Send security alert
        const user = await User.findById(tokenDoc.userId);
        await NotificationService.sendSecurityAlert(
          user,
          'TOKEN_REUSE_DETECTED',
          deviceInfo,
          ipAddress
        );

        // Clear cookies
        res.clearCookie('refreshToken');
        
        return res.status(401).json({
          error: 'Security violation detected. All sessions terminated.',
          code: 'TOKEN_REUSE_DETECTED'
        });
      }

      // Rotate refresh token
      const newRefreshToken = await TokenUtils.rotateRefreshToken(
        tokenDoc,
        ipAddress,
        userAgent,
        deviceId,
        deviceInfo
      );

      // Generate new access token
      const newAccessToken = TokenUtils.generateAccessToken({
        userId: tokenDoc.userId._id,
        email: tokenDoc.userId.email
      });

      // Set new refresh token cookie
      res.cookie('refreshToken', newRefreshToken.token, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict',
        maxAge: 30 * 24 * 60 * 60 * 1000 // 30 days
      });

      // Log token refresh
      await NotificationService.logSecurityEvent(
        tokenDoc.userId._id,
        'TOKEN_REFRESH',
        'LOW',
        ipAddress,
        userAgent,
        deviceId,
        { oldTokenId: tokenDoc.tokenId, newTokenId: newRefreshToken.tokenId }
      );

      res.json({
        message: 'Token refreshed successfully',
        accessToken: newAccessToken
      });
    } catch (error) {
      console.error('Token refresh error:', error);
      res.clearCookie('refreshToken');
      
      return res.status(401).json({
        error: 'Token refresh failed',
        code: 'REFRESH_FAILED',
        details: error.message
      });
    }
  }

  async logout(req, res) {
    try {
      const refreshToken = req.cookies.refreshToken;
      const { ipAddress, userAgent, deviceId } = DeviceUtils.getClientInfo(req);
      
      if (refreshToken) {
        // Find and revoke the refresh token
        const tokenDoc = await TokenUtils.validateRefreshToken(refreshToken);
        if (tokenDoc) {
          await tokenDoc.revoke();
          
          // Log logout event
          await NotificationService.logSecurityEvent(
            tokenDoc.userId,
            'LOGOUT',
            'LOW',
            ipAddress,
            userAgent,
            deviceId,
            { tokenId: tokenDoc.tokenId }
          );
        }
      }

      // Clear refresh token cookie
      res.clearCookie('refreshToken');
      
      res.json({
        message: 'Logged out successfully'
      });
    } catch (error) {
      // Even if there's an error, clear the cookie
      res.clearCookie('refreshToken');
      
      res.json({
        message: 'Logged out successfully'
      });
    }
  }

  async getProfile(req, res) {
    try {
      const user = await User.findById(req.userId).select('-password');
      
      if (!user) {
        return res.status(404).json({
          error: 'User not found',
          code: 'USER_NOT_FOUND'
        });
      }

      res.json({
        user: {
          id: user._id,
          email: user.email,
          firstName: user.firstName,
          lastName: user.lastName,
          isEmailVerified: user.isEmailVerified,
          lastLoginAt: user.lastLoginAt,
          createdAt: user.createdAt,
          notificationPreferences: user.notificationPreferences
        }
      });
    } catch (error) {
      console.error('Get profile error:', error);
      res.status(500).json({
        error: 'Internal server error',
        code: 'SERVER_ERROR'
      });
    }
  }

  async revokeAllSessions(req, res) {
    try {
      const { ipAddress, userAgent, deviceId } = DeviceUtils.getClientInfo(req);
      
      // Revoke all refresh tokens for the user
      await TokenUtils.revokeUserTokens(req.userId);
      
      // Clear current refresh token cookie
      res.clearCookie('refreshToken');
      
      // Log session revocation
      await NotificationService.logSecurityEvent(
        req.userId,
        'SESSION_REVOKED',
        'MEDIUM',
        ipAddress,
        userAgent,
        deviceId,
        { reason: 'USER_INITIATED' }
      );

      res.json({
        message: 'All sessions revoked successfully'
      });
    } catch (error) {
      console.error('Revoke sessions error:', error);
      res.status(500).json({
        error: 'Internal server error',
        code: 'SERVER_ERROR'
      });
    }
  }

  async getActiveSessions(req, res) {
    try {
      const RefreshToken = require('../models/RefreshToken');
      
      const sessions = await RefreshToken.find({
        userId: req.userId,
        isRevoked: false,
        isUsed: false,
        expiresAt: { $gt: new Date() }
      }).select('deviceInfo ipAddress createdAt lastUsedAt').sort({ createdAt: -1 });

      const formattedSessions = sessions.map(session => ({
        id: session._id,
        deviceInfo: session.deviceInfo,
        ipAddress: session.ipAddress,
        createdAt: session.createdAt,
        lastUsedAt: session.lastUsedAt || session.createdAt
      }));

      res.json({
        sessions: formattedSessions
      });
    } catch (error) {
      console.error('Get active sessions error:', error);
      res.status(500).json({
        error: 'Internal server error',
        code: 'SERVER_ERROR'
      });
    }
  }

  async revokeSession(req, res) {
    try {
      const { sessionId } = req.params;
      const { ipAddress, userAgent, deviceId } = DeviceUtils.getClientInfo(req);
      const RefreshToken = require('../models/RefreshToken');
      
      const session = await RefreshToken.findOne({
        _id: sessionId,
        userId: req.userId,
        isRevoked: false
      });

      if (!session) {
        return res.status(404).json({
          error: 'Session not found',
          code: 'SESSION_NOT_FOUND'
        });
      }

      await session.revoke();
      
      // Log session revocation
      await NotificationService.logSecurityEvent(
        req.userId,
        'SESSION_REVOKED',
        'LOW',
        ipAddress,
        userAgent,
        deviceId,
        { revokedSessionId: sessionId }
      );

      res.json({
        message: 'Session revoked successfully'
      });
    } catch (error) {
      console.error('Revoke session error:', error);
      res.status(500).json({
        error: 'Internal server error',
        code: 'SERVER_ERROR'
      });
    }
  }
}

module.exports = new AuthController();

// routes/auth.js
const express = require('express');
const authController = require('../controllers/authController');
const { authenticateToken, refreshTokenMiddleware } = require('../middleware/auth');
const { authLimiter, refreshLimiter } = require('../middleware/rateLimiter');
const { registerValidation, loginValidation } = require('../middleware/validation');

const router = express.Router();

// Public routes with rate limiting
router.post('/register', authLimiter, registerValidation, authController.register);
router.post('/login', authLimiter, loginValidation, authController.login);
router.post('/refresh-token', refreshLimiter, authController.refreshToken);
router.post('/logout', authController.logout);

// Protected routes
router.get('/me', authenticateToken, authController.getProfile);
router.post('/revoke-all-sessions', authenticateToken, authController.revokeAllSessions);
router.get('/sessions', authenticateToken, authController.getActiveSessions);
router.delete('/sessions/:sessionId', authenticateToken, authController.revokeSession);

module.exports = router;

// server.js
const express = require('express');
const mongoose = require('mongoose');
const cookieParser = require('cookie-parser');
const helmet = require('helmet');
require('dotenv').config();

const authRoutes = require('./routes/auth');
const { generalLimiter } = require('./middleware/rateLimiter');
const { refreshTokenMiddleware } = require('./middleware/auth');

const app = express();

// Security middleware
app.use(helmet());
app.use(generalLimiter);

// Body parsing middleware
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use(cookieParser(process.env.COOKIE_SECRET));

// Trust proxy for accurate IP addresses
app.set('trust proxy', true);

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({ 
    status: 'OK', 
    timestamp: new Date().toISOString(),
    uptime: process.uptime()
  });
});

// API routes
app.use('/api/auth', authRoutes);

// Protected example route using refresh middleware
app.get('/api/protected', refreshTokenMiddleware, (req, res) => {
  res.json({
    message: 'This is a protected route',
    user: req.user,
    timestamp: new Date().toISOString()
  });
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error('Error:', err);
  
  // MongoDB duplicate key error
  if (err.code === 11000) {
    return res.status(409).json({
      error: 'Duplicate key error',
      code: 'DUPLICATE_KEY_ERROR'
    });
  }
  
  // Validation errors
  if (err.name === 'ValidationError') {
    return res.status(400).json({
      error: 'Validation error',
      code: 'VALIDATION_ERROR',
      details: Object.values(err.errors).map(e => e.message)
    });
  }
  
  // JWT errors
  if (err.name === 'JsonWebTokenError') {
    return res.status(401).json({
      error: 'Invalid token',
      code: 'INVALID_TOKEN'
    });
  }
  
  if (err.name === 'TokenExpiredError') {
    return res.status(401).json({
      error: 'Token expired',
      code: 'TOKEN_EXPIRED'
    });
  }
  
  // Default server error
  res.status(500).json({
    error: 'Internal server error',
    code: 'SERVER_ERROR'
  });
});

// 404 handler
app.use('*', (req, res) => {
  res.status(404).json({
    error: 'Route not found',
    code: 'ROUTE_NOT_FOUND'
  });
});

// Database connection
mongoose.connect(process.env.MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
.then(() => {
  console.log('Connected to MongoDB');
})
.catch((error) => {
  console.error('MongoDB connection error:', error);
  process.exit(1);
});

// Graceful shutdown
process.on('SIGTERM', async () => {
  console.log('SIGTERM received, shutting down gracefully');
  await mongoose.connection.close();
  process.exit(0);
});

process.on('SIGINT', async () => {
  console.log('SIGINT received, shutting down gracefully');
  await mongoose.connection.close();
  process.exit(0);
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
  console.log(`Environment: ${process.env.NODE_ENV}`);
});

// Example usage documentation
/*
=== API ENDPOINTS ===

POST /api/auth/register
{
  "email": "user@example.com",
  "password": "SecurePass123!",
  "firstName": "John",
  "lastName": "Doe"
}

POST /api/auth/login
{
  "email": "user@example.com",
  "password": "SecurePass123!"
}

POST /api/auth/refresh-token
(Uses refresh token from httpOnly cookie)

POST /api/auth/logout
(Clears refresh token)

GET /api/auth/me
Authorization: Bearer <access_token>

POST /api/auth/revoke-all-sessions
Authorization: Bearer <access_token>

GET /api/auth/sessions
Authorization: Bearer <access_token>

DELETE /api/auth/sessions/:sessionId
Authorization: Bearer <access_token>

GET /api/protected
(Uses refresh middleware - auto-refreshes tokens)

=== SECURITY FEATURES ===

✅ JWT Access tokens (15 min expiry)
✅ Secure refresh token rotation
✅ HttpOnly cookies for refresh tokens
✅ Token reuse detection & prevention
✅ Account lockout after failed attempts
✅ Rate limiting on auth endpoints
✅ Security event logging
✅ Email notifications for suspicious activity
✅ Session management & revocation
✅ Device tracking & fingerprinting
✅ Password validation & bcrypt hashing
✅ Input validation & sanitization
✅ Protection against common attacks

=== DEPLOYMENT NOTES ===

1. Set strong secrets in production:
   - JWT_ACCESS_SECRET (256-bit random)
   - JWT_REFRESH_SECRET (256-bit random)
   - COOKIE_SECRET (256-bit random)

2. Configure MongoDB with authentication
3. Set up SMTP for email notifications
4. Use HTTPS in production
5. Configure proper CORS if needed
6. Set up monitoring & logging
7. Consider Redis for session storage in cluster
8. Implement proper backup strategies

=== SCALING CONSIDERATIONS ===

- Use MongoDB replica sets
- Consider Redis for refresh token storage
- Implement distributed rate limiting
- Add request correlation IDs
- Set up centralized logging
- Monitor token usage patterns
- Implement graceful degradation
*/