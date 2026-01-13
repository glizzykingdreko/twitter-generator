// X-XP-Forwarded-For Token Generator/Decoder
// Go Implementation
//
// This module provides encryption and decryption for Twitter/X's
// x-xp-forwarded-for authentication tokens.

package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"time"
)

// ============================================================================
// CONSTANTS
// ============================================================================

// AES-256-GCM encryption key (extracted from WASM binary)
const AESKeyHex = "0e6be1f1e21ffc33590b888fd4dc81b19713e570e805d4e5df80a493c9571a05"

// GCM parameters
const (
	IVLength      = 12 // 12 bytes (96 bits) - standard for GCM
	AuthTagLength = 16 // 16 bytes (128 bits)
)

// Token validity duration
const TokenValidityMS = 60 * 60 * 1000 // 1 hour in milliseconds

// ============================================================================
// DATA STRUCTURES
// ============================================================================

// NavigatorProperties contains browser fingerprint data
type NavigatorProperties struct {
	UserAgent     string `json:"user_agent,userAgent"`
	HasBeenActive bool   `json:"has_been_active,hasBeenActive"`
	Webdriver     bool   `json:"webdriver"`
	GuestId       string `json:"guest_id,guestId"`
}

// ClientSignals is the main data structure that gets encrypted
type ClientSignals struct {
	NavigatorProperties NavigatorProperties `json:"navigator_properties"`
	CreatedAt           int64               `json:"created_at"`
}

// TokenResult contains the encrypted token and expiry
type TokenResult struct {
	Str              string `json:"str"`
	ExpiryTimeMillis int64  `json:"expiryTimeMillis"`
}

// BrowserEnvironment holds browser details for token generation
type BrowserEnvironment struct {
	UserAgent     string
	HasBeenActive bool
	Webdriver     bool
	GuestId       string // From document.cookie guest_id
}

// ============================================================================
// ENCRYPTION / DECRYPTION
// ============================================================================

// GetAESKey returns the decoded AES key
func GetAESKey() ([]byte, error) {
	return hex.DecodeString(AESKeyHex)
}

// DeriveKeyFromGuestId derives encryption key from guest_id
// Formula: SHA256(defaultKey + guestId)
func DeriveKeyFromGuestId(guestId string) []byte {
	combined := AESKeyHex + guestId
	hash := sha256.Sum256([]byte(combined))
	return hash[:]
}

// DeriveKeyHexFromGuestId derives encryption key and returns as hex string
func DeriveKeyHexFromGuestId(guestId string) string {
	return hex.EncodeToString(DeriveKeyFromGuestId(guestId))
}

// Encrypt encrypts data using AES-256-GCM
// Returns: IV + ciphertext + auth tag
func Encrypt(plaintext []byte, key []byte) ([]byte, error) {
	// Create AES cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("error creating AES cipher: %w", err)
	}

	// Create GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("error creating GCM: %w", err)
	}

	// Generate random nonce (12 bytes for GCM)
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("error generating nonce: %w", err)
	}

	// Encrypt and seal (nonce is prepended to ciphertext)
	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
}

// Decrypt decrypts data using AES-256-GCM
// Input format: IV + ciphertext + auth tag
func Decrypt(ciphertext []byte, key []byte) ([]byte, error) {
	// Create AES cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("error creating AES cipher: %w", err)
	}

	// Create GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("error creating GCM: %w", err)
	}

	// Check minimum length
	if len(ciphertext) < gcm.NonceSize() {
		return nil, fmt.Errorf("ciphertext too short")
	}

	// Extract nonce and encrypted data
	nonce := ciphertext[:gcm.NonceSize()]
	encryptedData := ciphertext[gcm.NonceSize():]

	// Decrypt
	plaintext, err := gcm.Open(nil, nonce, encryptedData, nil)
	if err != nil {
		return nil, fmt.Errorf("decryption failed: %w", err)
	}

	return plaintext, nil
}

// ============================================================================
// TOKEN GENERATION
// ============================================================================

// BuildClientSignals creates ClientSignals from browser environment
func BuildClientSignals(env BrowserEnvironment) ClientSignals {
	return ClientSignals{
		NavigatorProperties: NavigatorProperties{
			UserAgent:     env.UserAgent,
			HasBeenActive: env.HasBeenActive,
			Webdriver:     env.Webdriver,
			GuestId:       env.GuestId,
		},
		CreatedAt: time.Now().UnixMilli(),
	}
}

// GenerateToken generates an x-xp-forwarded-for token
func GenerateToken(env BrowserEnvironment) (*TokenResult, error) {
	// Use derived key if guestId is provided, otherwise use default key
	var key []byte
	var err error
	if env.GuestId != "" {
		key = DeriveKeyFromGuestId(env.GuestId)
	} else {
		key, err = GetAESKey()
		if err != nil {
			return nil, err
		}
	}

	// Build client signals
	signals := BuildClientSignals(env)

	// Serialize to JSON
	jsonData, err := json.Marshal(signals)
	if err != nil {
		return nil, fmt.Errorf("error marshaling JSON: %w", err)
	}

	// Encrypt
	encrypted, err := Encrypt(jsonData, key)
	if err != nil {
		return nil, err
	}

	// Encode as base64
	encoded := base64.StdEncoding.EncodeToString(encrypted)

	return &TokenResult{
		Str:              encoded,
		ExpiryTimeMillis: time.Now().UnixMilli() + TokenValidityMS,
	}, nil
}

// DecodeToken decodes and decrypts a token
// Accepts both base64 and hex-encoded tokens
func DecodeToken(token string) (*ClientSignals, error) {
	// Get key
	key, err := GetAESKey()
	if err != nil {
		return nil, err
	}

	var ciphertext []byte

	// Check if hex or base64
	hexPattern := regexp.MustCompile(`^[0-9a-fA-F]+$`)
	if hexPattern.MatchString(token) && len(token)%2 == 0 {
		// Hex encoded
		ciphertext, err = hex.DecodeString(token)
		if err != nil {
			return nil, fmt.Errorf("error decoding hex: %w", err)
		}
	} else {
		// Base64 encoded
		ciphertext, err = base64.StdEncoding.DecodeString(token)
		if err != nil {
			return nil, fmt.Errorf("error decoding base64: %w", err)
		}
	}

	// Decrypt
	plaintext, err := Decrypt(ciphertext, key)
	if err != nil {
		return nil, err
	}

	// Parse JSON
	var signals ClientSignals
	if err := json.Unmarshal(plaintext, &signals); err != nil {
		return nil, fmt.Errorf("error parsing JSON: %w", err)
	}

	return &signals, nil
}

// ============================================================================
// CUSTOM KEY SUPPORT
// ============================================================================

// DecodeTokenWithKey decodes a token using a custom key
func DecodeTokenWithKey(token string, keyHex string) (*ClientSignals, error) {
	key, err := hex.DecodeString(keyHex)
	if err != nil {
		return nil, fmt.Errorf("invalid key hex: %w", err)
	}

	var ciphertext []byte
	hexPattern := regexp.MustCompile(`^[0-9a-fA-F]+$`)
	if hexPattern.MatchString(token) && len(token)%2 == 0 {
		ciphertext, err = hex.DecodeString(token)
	} else {
		ciphertext, err = base64.StdEncoding.DecodeString(token)
	}
	if err != nil {
		return nil, err
	}

	plaintext, err := Decrypt(ciphertext, key)
	if err != nil {
		return nil, err
	}

	var signals ClientSignals
	if err := json.Unmarshal(plaintext, &signals); err != nil {
		return nil, err
	}

	return &signals, nil
}

// DecodeTokenWithGuestId decodes a token using guest_id for key derivation
// This is the actual method used by Twitter/X
func DecodeTokenWithGuestId(token string, guestId string) (*ClientSignals, error) {
	derivedKey := DeriveKeyHexFromGuestId(guestId)
	key, err := hex.DecodeString(derivedKey)
	if err != nil {
		return nil, err
	}

	var ciphertext []byte
	hexPattern := regexp.MustCompile(`^[0-9a-fA-F]+$`)
	if hexPattern.MatchString(token) && len(token)%2 == 0 {
		ciphertext, err = hex.DecodeString(token)
	} else {
		ciphertext, err = base64.StdEncoding.DecodeString(token)
	}
	if err != nil {
		return nil, err
	}

	plaintext, err := Decrypt(ciphertext, key)
	if err != nil {
		return nil, err
	}

	// Unmarshal into map to handle flexible formats (camelCase/snake_case, string/bool)
	var rawData map[string]interface{}
	if err := json.Unmarshal(plaintext, &rawData); err != nil {
		return nil, err
	}

	// Convert to ClientSignals
	signals := ClientSignals{}
	if navProps, ok := rawData["navigator_properties"].(map[string]interface{}); ok {
		// Handle both camelCase and snake_case
		if ua, ok := navProps["userAgent"].(string); ok {
			signals.NavigatorProperties.UserAgent = ua
		} else if ua, ok := navProps["user_agent"].(string); ok {
			signals.NavigatorProperties.UserAgent = ua
		}

		// Handle hasBeenActive (can be bool or string)
		if hba, ok := navProps["hasBeenActive"].(bool); ok {
			signals.NavigatorProperties.HasBeenActive = hba
		} else if hbaStr, ok := navProps["hasBeenActive"].(string); ok {
			signals.NavigatorProperties.HasBeenActive = (hbaStr == "true")
		} else if hba, ok := navProps["has_been_active"].(bool); ok {
			signals.NavigatorProperties.HasBeenActive = hba
		}

		// Handle webdriver (can be bool or string)
		if wd, ok := navProps["webdriver"].(bool); ok {
			signals.NavigatorProperties.Webdriver = wd
		} else if wdStr, ok := navProps["webdriver"].(string); ok {
			signals.NavigatorProperties.Webdriver = (wdStr == "true")
		}
	}

	if ca, ok := rawData["created_at"].(float64); ok {
		signals.CreatedAt = int64(ca)
	}

	return &signals, nil
}

// TryDecryptWithKeys attempts decryption with multiple keys
func TryDecryptWithKeys(token string, keys []string) (string, *ClientSignals, error) {
	for _, keyHex := range keys {
		signals, err := DecodeTokenWithKey(token, keyHex)
		if err == nil {
			return keyHex, signals, nil
		}
	}
	return "", nil, fmt.Errorf("no matching key found")
}

// ============================================================================
// MAIN / TEST
// ============================================================================

func main() {
	fmt.Println(strings(60, '='))
	fmt.Println("X-XP-Forwarded-For Token Generator/Decoder")
	fmt.Println(strings(60, '='))

	// Test encryption/decryption
	fmt.Println("\n[TEST 1] Encryption/Decryption Round-Trip")
	fmt.Println(strings(40, '-'))

	testEnv := BrowserEnvironment{
		UserAgent:     "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
		HasBeenActive: true,
		Webdriver:     false,
		GuestId:       "v1%3A173456789012345678", // Example guest_id cookie value
	}

	token, err := GenerateToken(testEnv)
	if err != nil {
		fmt.Printf("Error generating token: %v\n", err)
		return
	}

	fmt.Printf("Generated token: %s...\n", token.Str[:50])
	fmt.Printf("Expiry: %s\n", time.UnixMilli(token.ExpiryTimeMillis).Format(time.RFC3339))

	// Use guest_id-derived key if guestId was provided
	var decoded *ClientSignals
	if testEnv.GuestId != "" {
		decoded, err = DecodeTokenWithGuestId(token.Str, testEnv.GuestId)
	} else {
		decoded, err = DecodeToken(token.Str)
	}
	if err != nil {
		fmt.Printf("Error decoding token: %v\n", err)
		return
	}

	decodedJSON, _ := json.MarshalIndent(decoded, "", "  ")
	fmt.Printf("Decoded:\n%s\n", string(decodedJSON))

	// Test with real token from request headers
	fmt.Println("\n[TEST 2] Decrypting Real Token with Guest ID")
	fmt.Println(strings(40, '-'))

	realToken := "973f0757e7cff62a248a1171e41070db1b0fbb7256a49323f86a9f96f3f4ecb5e4f85ed5e308d9e3f5f7480c0c139c3560dc2fa6ac71827a3124cb324bdbcd3c2a013392e5634018749fa1bc84a7458880cc333f3897af514fb1cc4a29c580cea44a9607b2d2c348b8c863c26aa8232e69ee1fbc4470d195b6ed705ce03e2ddc2a97b3dfa4846f9c037c8113c71439ae09a299e3bff9624c93b4455a1e7d10e14cf958b9b972f0042189d19bb25f455308992cffe00d1cc4a0a930ed409e35ec74541e2ac54c38162d646f3a64f2253578fca73a5e196f8c33d1b22c3297b44f74add1a8f123e60422bd294757da2d53d2fcfb0a19e5ca5b5e98f63d1b25f4cbc2"
	realGuestId := "v1%3A176824413470818950"

	fmt.Printf("Token (hex): %s...\n", realToken[:40])
	fmt.Printf("Token length: %d chars = %d bytes\n", len(realToken), len(realToken)/2)
	fmt.Printf("Guest ID: %s\n", realGuestId)
	fmt.Println()

	decodedReal, err := DecodeTokenWithGuestId(realToken, realGuestId)
	if err != nil {
		fmt.Printf("❌ Decryption failed: %v\n", err)
	} else {
		fmt.Println("✅ SUCCESS! Decrypted with guest_id-derived key!")
		decodedJSON, _ := json.MarshalIndent(decodedReal, "", "  ")
		fmt.Printf("Decoded:\n%s\n", string(decodedJSON))
	}

	// Show token structure
	fmt.Println("\n[TEST 3] Token Structure Analysis")
	fmt.Println(strings(40, '-'))

	tokenBytes, _ := hex.DecodeString(realToken)
	fmt.Printf("Total size: %d bytes\n", len(tokenBytes))
	fmt.Printf("IV (first 12 bytes): %x\n", tokenBytes[:12])
	fmt.Printf("Auth tag (last 16 bytes): %x\n", tokenBytes[len(tokenBytes)-16:])
	fmt.Printf("Ciphertext: %d bytes\n", len(tokenBytes)-12-16)

	fmt.Println("\n[INFO] Key Derivation:")
	fmt.Println(strings(40, '-'))
	fmt.Println("Twitter/X uses: SHA256(defaultKey + guestId)")
	fmt.Println(`signals, err := DecodeTokenWithGuestId(token, guestId)`)
	fmt.Println()
	fmt.Println("[INFO] To decrypt with a custom key:")
	fmt.Println(strings(40, '-'))
	fmt.Println(`signals, err := DecodeTokenWithKey(token, "your64charhexkey...")`)

	fmt.Println("\n" + strings(60, '='))
}

// Helper function to create repeated string
func strings(n int, c rune) string {
	result := make([]byte, n)
	for i := range result {
		result[i] = byte(c)
	}
	return string(result)
}
