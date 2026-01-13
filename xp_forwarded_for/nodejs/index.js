/**
 * X-XP-Forwarded-For Token Generator/Decoder
 * Node.js Implementation
 * 
 * This module provides encryption and decryption for Twitter/X's
 * x-xp-forwarded-for authentication tokens.
 */

const crypto = require('crypto');

// ============================================================================
// CONSTANTS
// ============================================================================

// AES-256-GCM encryption key (extracted from WASM binary)
const AES_KEY_HEX = '0e6be1f1e21ffc33590b888fd4dc81b19713e570e805d4e5df80a493c9571a05';
const AES_KEY = Buffer.from(AES_KEY_HEX, 'hex');

// GCM parameters
const IV_LENGTH = 12;      // 12 bytes (96 bits) - standard for GCM
const AUTH_TAG_LENGTH = 16; // 16 bytes (128 bits)

// Token validity duration
const TOKEN_VALIDITY_MS = 60 * 60 * 1000; // 1 hour

// ============================================================================
// DATA STRUCTURES
// ============================================================================

/**
 * @typedef {Object} NavigatorProperties
 * @property {string} user_agent - Browser user agent string
 * @property {boolean} has_been_active - Whether user has interacted with page
 * @property {boolean} webdriver - Whether browser is automated
 * @property {string} guest_id - Twitter guest_id cookie value
 */

/**
 * @typedef {Object} ClientSignals
 * @property {NavigatorProperties} navigator_properties - Browser fingerprint data
 * @property {number} created_at - Unix timestamp in milliseconds
 */

/**
 * @typedef {Object} TokenResult
 * @property {string} str - Base64-encoded encrypted token
 * @property {number} expiryTimeMillis - Token expiration timestamp
 */

/**
 * @typedef {Object} BrowserEnvironment
 * @property {string} userAgent - Browser user agent
 * @property {boolean} hasBeenActive - User activation state
 * @property {boolean} webdriver - Webdriver detection flag
 * @property {string} guestId - Twitter guest_id cookie value (from document.cookie)
 */

// ============================================================================
// ENCRYPTION / DECRYPTION
// ============================================================================

/**
 * Encrypt data using AES-256-GCM
 * 
 * @param {string|Buffer} plaintext - Data to encrypt
 * @param {Buffer} [key=AES_KEY] - 32-byte encryption key
 * @returns {Buffer} IV + ciphertext + auth tag
 */
function encrypt(plaintext, key = AES_KEY) {
    // Generate random 12-byte IV
    const iv = crypto.randomBytes(IV_LENGTH);
    
    // Create cipher
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
    
    // Encrypt
    const encrypted = Buffer.concat([
        cipher.update(plaintext, 'utf8'),
        cipher.final()
    ]);
    
    // Get auth tag
    const authTag = cipher.getAuthTag();
    
    // Combine: IV + ciphertext + authTag
    return Buffer.concat([iv, encrypted, authTag]);
}

/**
 * Decrypt data using AES-256-GCM
 * 
 * @param {Buffer} ciphertext - IV + encrypted data + auth tag
 * @param {Buffer} [key=AES_KEY] - 32-byte encryption key
 * @returns {string} Decrypted plaintext
 */
function decrypt(ciphertext, key = AES_KEY) {
    // Extract components
    const iv = ciphertext.slice(0, IV_LENGTH);
    const authTag = ciphertext.slice(-AUTH_TAG_LENGTH);
    const encrypted = ciphertext.slice(IV_LENGTH, -AUTH_TAG_LENGTH);
    
    // Create decipher
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAuthTag(authTag);
    
    // Decrypt
    const decrypted = Buffer.concat([
        decipher.update(encrypted),
        decipher.final()
    ]);
    
    return decrypted.toString('utf8');
}

// ============================================================================
// TOKEN GENERATION
// ============================================================================

/**
 * Build client signals from browser environment
 * 
 * @param {BrowserEnvironment} env - Browser environment details
 * @returns {ClientSignals} Client signals object
 */
function buildClientSignals(env) {
    return {
        navigator_properties: {
            user_agent: env.userAgent || 'Mozilla/5.0',
            has_been_active: env.hasBeenActive ?? false,
            webdriver: env.webdriver ?? false,
            guest_id: env.guestId || ''
        },
        created_at: Date.now()
    };
}

/**
 * Generate x-xp-forwarded-for token
 * 
 * @param {BrowserEnvironment} env - Browser environment details
 * @returns {TokenResult} Token and expiry
 */
function generateToken(env) {
    // Build client signals
    const signals = buildClientSignals(env);
    
    // Serialize to JSON
    const json = JSON.stringify(signals);
    
    // Use derived key if guestId is provided, otherwise use default key
    let key = AES_KEY;
    if (env.guestId) {
        key = deriveKeyFromGuestId(env.guestId);
    }
    
    // Encrypt
    const encrypted = encrypt(json, key);
    
    // Encode as base64
    const base64 = encrypted.toString('base64');
    
    return {
        str: base64,
        expiryTimeMillis: Date.now() + TOKEN_VALIDITY_MS
    };
}

/**
 * Decode and decrypt a token
 * 
 * @param {string} token - Base64-encoded token OR hex-encoded token
 * @returns {ClientSignals} Decoded client signals
 */
function decodeToken(token) {
    let buffer;
    
    // Check if hex or base64
    if (/^[0-9a-f]+$/i.test(token) && token.length % 2 === 0) {
        // Hex encoded
        buffer = Buffer.from(token, 'hex');
    } else {
        // Base64 encoded
        buffer = Buffer.from(token, 'base64');
    }
    
    // Decrypt
    const json = decrypt(buffer);
    
    // Parse JSON
    return JSON.parse(json);
}

// ============================================================================
// EXPORTS
// ============================================================================

module.exports = {
    // Core functions
    encrypt,
    decrypt,
    generateToken,
    decodeToken,
    buildClientSignals,
    
    // Constants
    AES_KEY_HEX,
    AES_KEY,
    IV_LENGTH,
    AUTH_TAG_LENGTH,
    TOKEN_VALIDITY_MS
};

// ============================================================================
// KEY DERIVATION
// ============================================================================

/**
 * Derive encryption key from guest_id
 * Formula: SHA256(defaultKey + guestId)
 * 
 * @param {string} guestId - Guest ID from cookie (e.g., "v1%3A176824413470818950")
 * @returns {Buffer} 32-byte derived key
 */
function deriveKeyFromGuestId(guestId) {
    const combined = AES_KEY_HEX + guestId;
    return crypto.createHash('sha256').update(combined).digest();
}

/**
 * Derive encryption key from guest_id (returns hex string)
 * 
 * @param {string} guestId - Guest ID from cookie
 * @returns {string} 64-character hex key
 */
function deriveKeyHexFromGuestId(guestId) {
    return deriveKeyFromGuestId(guestId).toString('hex');
}

// ============================================================================
// CUSTOM KEY SUPPORT
// ============================================================================

/**
 * Decrypt with a custom key
 * 
 * @param {string} token - Base64 or hex encoded token
 * @param {string} keyHex - 64-character hex key
 * @returns {ClientSignals} Decoded client signals
 */
function decodeTokenWithKey(token, keyHex) {
    const key = Buffer.from(keyHex, 'hex');
    
    let buffer;
    if (/^[0-9a-f]+$/i.test(token) && token.length % 2 === 0) {
        buffer = Buffer.from(token, 'hex');
    } else {
        buffer = Buffer.from(token, 'base64');
    }
    
    const json = decrypt(buffer, key);
    return JSON.parse(json);
}

/**
 * Decrypt token using guest_id for key derivation
 * This is the actual method used by Twitter/X
 * 
 * @param {string} token - Base64 or hex encoded token
 * @param {string} guestId - Guest ID from cookie
 * @returns {ClientSignals} Decoded client signals
 */
function decodeTokenWithGuestId(token, guestId) {
    const derivedKey = deriveKeyHexFromGuestId(guestId);
    return decodeTokenWithKey(token, derivedKey);
}

/**
 * Try to decrypt with multiple known keys
 * 
 * @param {string} token - Token to decrypt
 * @param {string[]} keys - Array of hex keys to try
 * @returns {{key: string, data: ClientSignals}|null} Result or null if all fail
 */
function tryDecryptWithKeys(token, keys) {
    for (const keyHex of keys) {
        try {
            const data = decodeTokenWithKey(token, keyHex);
            return { key: keyHex, data };
        } catch (e) {
            // Try next key
        }
    }
    return null;
}

module.exports.deriveKeyFromGuestId = deriveKeyFromGuestId;
module.exports.deriveKeyHexFromGuestId = deriveKeyHexFromGuestId;
module.exports.decodeTokenWithKey = decodeTokenWithKey;
module.exports.decodeTokenWithGuestId = decodeTokenWithGuestId;
module.exports.tryDecryptWithKeys = tryDecryptWithKeys;

// ============================================================================
// CLI / TEST
// ============================================================================

if (require.main === module) {
    console.log('='.repeat(60));
    console.log('X-XP-Forwarded-For Token Generator/Decoder');
    console.log('='.repeat(60));
    
    // Test encryption/decryption
    console.log('\n[TEST 1] Encryption/Decryption Round-Trip');
    console.log('-'.repeat(40));
    
    const testEnv = {
        userAgent: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
        hasBeenActive: true,
        webdriver: false,
        guestId: 'v1%3A173456789012345678'  // Example guest_id cookie value
    };
    
    const token = generateToken(testEnv);
    console.log('Generated token:', token.str.substring(0, 50) + '...');
    console.log('Expiry:', new Date(token.expiryTimeMillis).toISOString());
    
    // Use guest_id-derived key if guestId was provided
    let decoded;
    if (testEnv.guestId) {
        decoded = decodeTokenWithGuestId(token.str, testEnv.guestId);
    } else {
        decoded = decodeToken(token.str);
    }
    console.log('Decoded:', JSON.stringify(decoded, null, 2));
    
    // Test with real token from request headers
    console.log('\n[TEST 2] Decrypting Real Token with Guest ID');
    console.log('-'.repeat(40));
    
    const realToken = '973f0757e7cff62a248a1171e41070db1b0fbb7256a49323f86a9f96f3f4ecb5e4f85ed5e308d9e3f5f7480c0c139c3560dc2fa6ac71827a3124cb324bdbcd3c2a013392e5634018749fa1bc84a7458880cc333f3897af514fb1cc4a29c580cea44a9607b2d2c348b8c863c26aa8232e69ee1fbc4470d195b6ed705ce03e2ddc2a97b3dfa4846f9c037c8113c71439ae09a299e3bff9624c93b4455a1e7d10e14cf958b9b972f0042189d19bb25f455308992cffe00d1cc4a0a930ed409e35ec74541e2ac54c38162d646f3a64f2253578fca73a5e196f8c33d1b22c3297b44f74add1a8f123e60422bd294757da2d53d2fcfb0a19e5ca5b5e98f63d1b25f4cbc2';
    const realGuestId = 'v1%3A176824413470818950';
    
    console.log('Token (hex):', realToken.substring(0, 40) + '...');
    console.log('Token length:', realToken.length, 'chars =', realToken.length / 2, 'bytes');
    console.log('Guest ID:', realGuestId);
    console.log('');
    
    try {
        const decodedReal = decodeTokenWithGuestId(realToken, realGuestId);
        console.log('✅ SUCCESS! Decrypted with guest_id-derived key!');
        console.log('Decoded:', JSON.stringify(decodedReal, null, 2));
    } catch (err) {
        console.log('❌ Decryption failed:', err.message);
    }
    
    // Show token structure
    console.log('\n[TEST 3] Token Structure Analysis');
    console.log('-'.repeat(40));
    
    const tokenBytes = Buffer.from(realToken, 'hex');
    console.log('Total size:', tokenBytes.length, 'bytes');
    console.log('IV (first 12 bytes):', tokenBytes.slice(0, 12).toString('hex'));
    console.log('Auth tag (last 16 bytes):', tokenBytes.slice(-16).toString('hex'));
    console.log('Ciphertext:', tokenBytes.length - 12 - 16, 'bytes');
    
    console.log('\n[INFO] Key Derivation:');
    console.log('-'.repeat(40));
    console.log('Twitter/X uses: SHA256(defaultKey + guestId)');
    console.log('const { decodeTokenWithGuestId } = require("./index");');
    console.log('const data = decodeTokenWithGuestId(token, guestId);');
    
    console.log('\n[INFO] To decrypt with a custom key:');
    console.log('-'.repeat(40));
    console.log('const { decodeTokenWithKey } = require("./index");');
    console.log('const data = decodeTokenWithKey(token, "your64charhexkey...");');
    
    console.log('\n' + '='.repeat(60));
}

