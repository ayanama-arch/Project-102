// Login & Authorization Flow

// Login Flow

/**
 * Receives Email|Username & Password
 * Fetch the User using email/username
 * If user not present, send invalid credentials error
 * Compare provided password with hashed password using bcrypt.compare()
 * If password incorrect, return invalid credentials error
 * 
 * Generate JWT Tokens:
 *  ACCESS_TOKEN
 *    - Include _id, email, role in payload
 *    - Expiry: 15 minutes
 *  REFRESH_TOKEN
 *    - Same payload as access token (or minimal)
 *    - Expiry: 7 days (set dynamically)
 * 
 * Get client IP address and User-Agent
 * Store Refresh Token in DB with:
 *    {
 *      userId: String;
 *      token: String;
 *      ipAddress: String;
 *      userAgent: String;
 *      isActive: Boolean; // Used to deactivate old tokens
 *      expiresAt: Date;   // Set to 7 days from creation dynamically
 *      createdAt: Date;
 *    }
 * 
 * Deactivate (or delete) all previous active tokens for this user except the current one
 * Set Access Token and Refresh Token as HttpOnly, Secure cookies with appropriate expiry
 * Return user details excluding password
 */

// Authorization Middleware

/**
 * Check for Access Token in cookies
 * If missing, send invalid credentials error (401)
 * Verify token:
 *  - If expired, send TokenExpired error (401 with specific message)
 *  - If invalid, send invalid credentials error (401)
 * Attach decoded token payload to req.user
 * Forward request to next handler
 */

// Refresh Token Flow

/**
 * Read Refresh Token from cookies
 * Fetch stored token record from DB including IP and User-Agent
 * Compare request IP and User-Agent with stored values
 * If IP or User-Agent mismatch:
 *    - Reject refresh request (send unauthorized error)
 *    - Mark old refresh token as inactive or delete it
 *    - Optionally log the event and notify user
 * If token does not exist, inactive, or expired:
 *    - Send unauthorized error
 * If all valid:
 *    - Generate new Access Token (15 min) and new Refresh Token (7 days)
 *    - Store new Refresh Token in DB with updated metadata (IP, User-Agent, isActive = true)
 *    - Deactivate or delete all older active tokens for this user (including the old refresh token)
 *    - Set both tokens in HttpOnly, Secure cookies with proper expiry
 *    - Return success message or new token info as needed
 */

// Logout Flow

/**
 * Read refresh token from cookies
 * Mark token isActive = false or delete from DB
 * Clear access_token and refresh_token cookies
 * Return success response
 */

// Notes on IP & User-Agent Validation

/**
 * IP and User-Agent stored to improve security & session management
 * Validate IP and User-Agent only at /refresh token usage to detect suspicious usage
 * Do NOT validate IP/User-Agent on every API request (to avoid false positives)
 * Handle mismatch by rejecting refresh and forcing user to re-login
 * Log suspicious events and optionally notify user for transparency
 */
