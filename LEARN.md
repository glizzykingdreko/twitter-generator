# How did we get here?

![How did we get here?](./images/hdwgh.png)

Let's break down each header's generation

<div align="center">
  <img src="https://img.shields.io/badge/Status-Complete-brightgreen" alt="Status: Complete">
  <img src="https://img.shields.io/badge/Type-Research-blue" alt="Type: Research">
  <img src="https://img.shields.io/badge/License-MIT-yellow" alt="License: MIT">
  <a href="https://github.com/GlizzyKingDreko/twitter_generator"><img src="https://img.shields.io/github/stars/GlizzyKingDreko/twitter_generator?style=flat-square&logo=github" alt="GitHub stars"></a>
  <a href="https://github.com/GlizzyKingDreko/twitter_generator"><img src="https://img.shields.io/badge/GitHub-Repo-black?logo=github&style=flat-square" alt="GitHub repo"></a>
</div>

<br>

<div align="center">
  <a href="https://github.com/GlizzyKingDreko/twitter_generator-python"><img src="https://img.shields.io/badge/Check%20the%20Python%20version-purple?logo=python&style=flat-square" alt="Check the Python version"></a>
  <a href="https://medium.com/@glizzykingdreko/x-former-twitter-login-flow-reconstruction-episode-1-headers-generation-68a23add39e1"><img src="https://img.shields.io/badge/Read%20the%20full%20article%20on%20Medium-12100E?logo=medium&logoColor=white&style=flat-square" alt="Read the full article on Medium"></a>
  <a href="https://buymeacoffee.com/glizzykingdreko"><img src="https://img.shields.io/badge/Support%20my%20researches%20by%20buying%20me%20a%20coffee-242424?style=flat-square&logo=buy-me-a-coffee&logoColor=yellow&labelColor=222&color=222" alt="Support my researches by buying me a coffee"></a>
</div>
<br>

## Table of Contents

1. [Before starting](#before-starting)
2. [X-Client-Transaction-Id](#x-client-transaction-id)
3. [X-Xp-Forwarded-For](#x-xp-forwarded-for)
   - [Step 1: Extracting the WASM Binary](#step-1-extracting-the-wasm-binary)
   - [Step 2: Converting WASM to WAT](#step-2-converting-wasm-to-wat)
   - [Step 3: Analyzing WASM Structure](#step-3-analyzing-wasm-structure)
   - [Step 4: Extracting Embedded Strings](#step-4-extracting-embedded-strings)
   - [Step 5: Understanding the Go Runtime](#step-5-understanding-the-go-runtime)
   - [Step 6: Identifying the Core Algorithm](#step-6-identifying-the-core-algorithm)
   - [Step 7: Key Derivation Discovery (guest_id)](#step-7-key-derivation-discovery-guest_id)
   - [Step 8: Recreating the JavaScript Implementation](#step-8-recreating-the-javascript-implementation)
   - [Step 9: Validation](#step-9-validation)
   - [Step 10: Multi-Language Implementations](#step-10-multi-language-implementations)
4. [Author](#author)



## Before starting
This is the first of a 3 episodes series about X (former Twitter) login flow protections.

Be sure to check the related [Medium Article](https://medium.com/@glizzykingdreko/x-former-twitter-login-flow-reconstruction-episode-1-headers-generation-68a23add39e1) and subscribe to my newsletter (from Medium) in order to get notified when the next episode will be out (a follow on Github would make me happy too).

Next one is going to be about the first antibot challenge.

## X-Client-Transaction-Id

The flow for the generation of it is:

1. Fetch [x.com](https://x.com/home) home page and extract the value of the meta tag named `twitter-site-verification`

2. Get *_on demand url_* via a regex like `["']ondemand\.s["']\s*:\s*["']([\w]+)["']` and load it 

3. Generation process

In few words is based on a hash that looks like
```py
f"{method}!{path}!{time_now}obfiowerehiring{animation_key}"
```

Where
| Key | Description |
|-----|-------------|
|method   | Request method (POST/GET/...) |
|path     | Endpoint where u sending the request (Ex. `https://api.x.com/1.1/onboarding/task.json` ) |
|time now | Current timestamp offset |
| animation_key | Generated based on the extracted key from the *_on demand url_* and the `twitter-site-verification` |

That is then XOR encoded and converted to b64

So, each time a request will be sent to X / Twitter a new token will be required since are based on the session (since we are extracting data from the loaded homepage and on demand url) as well as the current sending timestamp.

*Original code rewrote ina  more uman-redable way*
```js
// Calculate seconds elapsed since reference timestamp (April 2023)
var secondsSinceEpoch = Math.floor((Date.now() - 1682924400 * 1000) / 1000);

// Convert timestamp to bytes (Float64 → Uint8Array)
var timestampBytes = new Uint8Array(new Float64Array([secondsSinceEpoch]).buffer);

// Get fingerprint from DOM element
var fingerprint = new Uint8Array(atob(
    document.querySelectorAll("[name^=tw]")[0].getAttribute("content")
)["split"]("")["map"](function (n) {
    return n["charCodeAt"](0);
}));

var fingerprintHash = generateFingerprintHash(fingerprint);

// Random salt for the payload
var randomSalt = [Math.random() * 256];

// Convert fingerprint and timestamp to arrays
var fingerprintArray = Array.from(fingerprint);
var timestampArray = Array.from(timestampBytes);

// Build the hash input: "param2!param1!timestamp" + "obfiowerehiring" + fingerprintHash
var hashInput = [t, r, secondsSinceEpoch].join("!") + "obfiowerehiring" + fingerprintHash;

// Compute SHA-256 hash asynchronously
var hashResult = crypto.subtle.digest("sha-256", new TextEncoder().encode(hashInput));

// Build the final payload by concatenating:
// [randomSalt, fingerprintArray, timestampArray, transformed(slice16(arrayFrom(hashBytes).concat(HW))), 3]
var hashBytes = new Uint8Array(hashResult);
var hashArray = Array.from(hashBytes);
var transformed = hashArray.concat(HW)["slice"](0, Math.pow(2, 4));  // Take first 16 bytes

var payload = randomSalt.concat(fingerprintArray, timestampArray, transformed, [3]);

// Encode as base64 with optional XOR and return
var finalBytes = new Uint8Array(payload);

// base64 encode with optional XOR
MW = function (n, r, t) {
    return r ? n ^ t[0] : n;
}
sW = function (n) {
    return btoa(Array.from(n)["map"](function (n) {
        return String["fromCharCode"](n);
    })["join"](""))["replace"](/=/g, "");
}
var encoded = sW(finalBytes.map(MW));
```
*([on demand url source](https://abs.twimg.com/responsive-web/client-web/ondemand.s.05fedcda.js) keep in mind tha the urls are dynamic)*

Check [out the full code of this implementation](./twitter_generator/client_transaction/main.py)


## X-Xp-Forwarded-For

That's a bit harder.

So basically the javascript module `XPForwardedForSDK` [source](https://abs.twimg.com/responsive-web/client-web/loader.FwdForSdk.8ee16aca.js) (dynamic url/file) 

After beeing initialized with some env details, is going to use a GO based WASM script in order to encrypt via `AES-256-GCM` a JSON payload by using a static key and the session cookie `guest_id` for **key derivation**.

Here it follows the full process that lead me to the understanding and debugging of it.


### Step 1: Extracting the WASM Binary

#### Finding the WASM Bytes

The original [FwdForSdk](https://abs.twimg.com/responsive-web/client-web/loader.FwdForSdk.8ee16aca.js) file contains the WASM binary embedded as a byte array. Looking at the obfuscated code:

```javascript
// Obfuscated structure
864585: e => {
    var t = new ArrayBuffer(372549);
    new Uint8Array(t).set([0, 97, 115, 109, 1, 0, 0, 0, ...]);
    // ... 372,549 bytes total
}
```

#### Extraction Script

```javascript
const fs = require('fs');
const code = fs.readFileSync('x_xp_forwarded_for.js', 'utf8');

// Find the WASM bytes array using regex
const match = code.match(
    /864585:\s*e\s*=>\s*\{[^}]*var\s+t\s*=\s*new\s+ArrayBuffer\((\d+)\);\s*new\s+Uint8Array\(t\)\.set\(\[([^\]]+)\]/s
);

if (match) {
    const size = parseInt(match[1]);
    console.log('WASM size:', size, 'bytes');
    
    // Parse the bytes
    const allBytes = match[2].split(',').map(b => parseInt(b.trim()));
    const buffer = Buffer.from(allBytes);
    
    // Save to file
    fs.writeFileSync('xpforwarded.wasm', buffer);
    console.log('Saved to xpforwarded.wasm');
}
```

#### Verifying the Magic Number

Every WASM file starts with the magic bytes `\0asm` (0x00 0x61 0x73 0x6d):

```bash
$ xxd xpforwarded.wasm | head -1
00000000: 0061 736d 0100 0000 0180 043c 6002 7f7f  .asm.......<`.
```

So it is valid.

---

### Step 2: Converting WASM to WAT

#### Using wasm2wat

`wasm2wat` is used to convert the WASM binary to readable text format

```bash
$ wasm2wat xpforwarded.wasm -o xpforwarded.wat
```

---

### Step 3: Analyzing WASM Structure

#### Examining Exports

```wat
(export "memory" (memory 0))
(export "malloc" (func 429))
(export "free" (func 430))
(export "calloc" (func 431))
(export "realloc" (func 432))
(export "resume" (func 433))
(export "go_scheduler" (func 434))
(export "_start" (func 435))
(export "asyncify_start_unwind" (func 436))
(export "asyncify_stop_unwind" (func 437))
(export "asyncify_start_rewind" (func 438))
(export "asyncify_stop_rewind" (func 437))
(export "asyncify_get_state" (func 439))
```

By just looking at those exports we can already understand that:
- `go_scheduler`: Go runtime's goroutine scheduler (so is a Go-based script)
- `malloc/free/calloc/realloc`: Memory management (standard C-style)
- `asyncify_*`: Binaryen asyncify transform for async JS interop

#### Examining Imports

```wat
(import "gojs" "runtime.ticks" (func (;0;) (type 30)))
(import "wasi_snapshot_preview1" "fd_write" (func (;1;) (type 5)))
(import "gojs" "syscall/js.valueGet" (func (;2;) (type 31)))
(import "gojs" "syscall/js.valuePrepareString" (func (;3;) (type 12)))
(import "gojs" "syscall/js.valueLoadString" (func (;4;) (type 32)))
(import "gojs" "syscall/js.finalizeRef" (func (;5;) (type 33)))
(import "gojs" "syscall/js.stringVal" (func (;6;) (type 23)))
(import "gojs" "syscall/js.valueSet" (func (;7;) (type 34)))
(import "gojs" "syscall/js.valueNew" (func (;8;) (type 16)))
(import "gojs" "syscall/js.valueLength" (func (;9;) (type 20)))
(import "gojs" "syscall/js.valueInvoke" (func (;10;) (type 16)))
(import "gojs" "syscall/js.valueIndex" (func (;11;) (type 35)))
(import "gojs" "syscall/js.valueCall" (func (;12;) (type 17)))
(import "wasi_snapshot_preview1" "random_get" (func (;13;) (type 9)))
```

Main things we can point out are:
- Uses `gojs` namespace a Go's JS interop layer (`syscall/js` package)
- `syscall/js.valueGet/valueSet`: Access JavaScript object properties
- `syscall/js.valueCall`: Call JavaScript functions

So yeah we can already be sure that is a go based script

---

### Step 4: Extracting Embedded Strings

#### Method 1: Using `strings` Command

```bash
$ strings xpforwarded.wasm | grep -E "(forward|encrypt|sha|aes|guest|cookie)" | head -20
```

**Results:**
```
forwarded-for-sdk/javascript_fingerprint
crypto/aes
crypto/internal/fips140/aes
crypto/internal/fips140/aes/gcm
crypto/internal/fips140/sha256
documentcookie;=guest_id
navigatoruserActivationhasBeenActiveuserAgentwebdriverundefined
Error encrypting data:
getForwardedForStr
```

#### Method 2: Analyzing WAT Data Segments

The WAT file contains data segments with embedded strings:

```wat
(data (;0;) (i32.const 65536) "expand 32-byte k...")
(data (;1;) (i32.const 65842) "meta\00invalid syntax0123456789abcefz...")
```

**Key String Discoveries:**

| String | Interpretation |
|--------|----------------|
| `forwarded-for-sdk/javascript_fingerprint` | Go package name |
| `crypto/aes`, `crypto/internal/fips140/aes` | AES encryption used |
| `crypto/internal/fips140/aes/gcm` | GCM mode specifically |
| `crypto/internal/fips140/sha256` | SHA-256 hashing |
| `documentcookie;=guest_id` | Guest ID cookie extraction (used for key derivation, NOT in payload) |
| `navigatoruserActivationhasBeenActive` | User interaction check |
| `userAgentwebdriverundefined` | Bot detection via webdriver |
| `getForwardedForStr` | Exported JS function name |
| `strexpiryTimeMillis` | Return object properties |
| `json:"navigator_properties"` | JSON field tag |
| `json:"created_at"` | JSON field tag |

#### Finding the Base AES Key

An important discovery was finding a hex string embedded near crypto error messages:

```bash
# The key is embedded within a longer concatenated string
$ strings xpforwarded.wasm | grep "error creating AES"
\.+*?()|[]{}^$0e6be1f1e21ffc33590b888fd4dc81b19713e570e805d4e5df80a493c9571a05error creating AES cipher:...

# Extract just 64-char hex sequences that contain letters (not pure numbers)
$ strings xpforwarded.wasm | grep -oE "[0-9a-f]{64}" | grep -E "[a-f]"
0e6be1f1e21ffc33590b888fd4dc81b19713e570e805d4e5df80a493c9571a05
```

This is a 64-character hex string = 32 bytes = 256 bits, which is exactly the size for an AES-256 key. It appears immediately before the `error creating AES cipher:` confirming that it's used by the AES encryption code.

This is going to be the **base key**.

So at this point but just a first lookup on the strings we can already understand that we are facing an AES type of encryption based on an "original" GO file.

---

### Step 5: Understanding the Go Runtime

#### Go WASM Architecture

Go compiles to WASM using the `GOOS=js GOARCH=wasm` target. This requires:

1. **JS Glue Code**: A JavaScript file that implements the `gojs` imports
2. **Memory Management**: Go manages its own memory within WASM linear memory
3. **JS Interop**: The `syscall/js` package provides bidirectional communication

#### Value Reference System

Go WASM uses a reference system to pass values between Go and JavaScript:

```javascript
// Values are stored in an array, indexed by IDs
this._values = [
    NaN,        // 0: reserved
    0,          // 1: zero
    null,       // 2: null
    true,       // 3: true
    false,      // 4: false
    globalThis, // 5: global object
    this        // 6: Go instance
];
```

When Go calls `syscall/js.valueGet(obj, "property")`:
1. Go passes the object reference ID
2. The JS glue code looks up the object in `_values`
3. Gets the property
4. Stores the result in `_values` and returns the new ID

#### Asyncify Transform

The WASM module uses Binaryen's asyncify transform to handle async JavaScript operations:

```wat
(export "asyncify_start_unwind" (func 436))
(export "asyncify_stop_unwind" (func 437))
(export "asyncify_start_rewind" (func 438))
```

This allows the Go code to `await` JavaScript Promises, which is necessary for:
- `crypto.subtle.encrypt()` 
- `crypto.subtle.digest()`

---

### Step 6: Identifying the Core Algorithm

#### The approach

So, at this point we could just "pack" the wasm file into a NodeJS file and call it a day, but I would not be satisfied without deeply understanding and recreating from scratch this situation.

So let's point out what we have at the moment in our hands, there's no need to further debug or whatever, just analyze our output file.

#### Evidence Source 1: Embedded Strings as "Breadcrumbs"

The most powerful technique is analyzing embedded strings. Go binaries contain:
- Package names
- Error messages  
- JSON struct tags
- Type names

**Command used:**
```bash
strings xpforwarded.wasm | grep -v "^.$" | sort -u > all_strings.txt
```

**Key string discoveries and what they reveal:**

| String Found | What It Tells Us |
|--------------|------------------|
| `json:"navigator_properties"` | There's a Go struct with a field that serializes to `navigator_properties` |
| `json:"user_agent"` | Nested struct has `user_agent` field |
| `json:"has_been_active"` | Boolean field for user activation |
| `json:"webdriver"` | Boolean field for bot detection |
| `json:"created_at"` | Timestamp field |
| `navigatoruserActivationhasBeenActive` | Concatenated JS property access path |
| `userAgentwebdriverundefined` | More JS properties being accessed |
| `getForwardedForStr` | The exported function name |
| `strexpiryTimeMillis` | Return object has `str` and `expiryTimeMillis` keys |

**Reconstruction logic:**
```
json:"navigator_properties" + json:"user_agent" + json:"has_been_active" + json:"webdriver"
                                        ↓
                        NavigatorProperties struct with 3 fields

json:"navigator_properties" + json:"created_at"
                    ↓
        ClientSignals struct wrapping NavigatorProperties
```

#### Evidence Source 2: Package Paths

Go binaries embed full package paths:

```bash
$ strings xpforwarded.wasm | grep "crypto/"
crypto/aes
crypto/cipher
crypto/internal/fips140/aes
crypto/internal/fips140/aes/gcm
crypto/internal/fips140/sha256
```

What can we understand?
- `crypto/aes` → Uses AES encryption
- `crypto/cipher` → Uses cipher modes (block cipher interface)
- `crypto/internal/fips140/aes/gcm` → Specifically GCM mode
- NOT using CBC, CTR, or other modes

#### Evidence Source 3: Error Messages

Error messages reveal function behavior:

```bash
$ strings xpforwarded.wasm | grep -i "error"
error creating AES cipher:
error creating GCM:
Error encrypting data:
```

**Reconstruction:**
```go
// Error message "error creating AES cipher:" implies:
block, err := aes.NewCipher(key)
if err != nil {
    return nil, fmt.Errorf("error creating AES cipher: %w", err)
}

// Error message "error creating GCM:" implies:
gcm, err := cipher.NewGCM(block)
if err != nil {
    return nil, fmt.Errorf("error creating GCM: %w", err)
}
```

#### Evidence Source 4: WASM Imports Tell Us What JS APIs Are Used

```wat
(import "gojs" "syscall/js.valueGet" ...)    ; obj.property access
(import "gojs" "syscall/js.valueSet" ...)    ; obj.property = value
(import "gojs" "syscall/js.valueCall" ...)   ; obj.method()
(import "gojs" "syscall/js.valueNew" ...)    ; new Constructor()
(import "wasi_snapshot_preview1" "random_get" ...) ; crypto random bytes
```

This confirms:
- Code accesses JS object properties (navigator, document)
- Code calls JS methods
- Code needs random bytes (for IV/nonce generation)

#### Evidence Source 5: The 64-Character Hex String = AES-256 Key

The key is **not standalone**, it's embedded within a longer concatenated string. We find it by searching for hex patterns near crypto errors:

```bash
$ strings xpforwarded.wasm | grep "error creating AES"
\.+*?()|[]{}^$0e6be1f1e21ffc33590b888fd4dc81b19713e570e805d4e5df80a493c9571a05error creating AES cipher: error creating GCM: documentcookie;=guest_id
```

**Extracting the key from the string:**
```
\.+*?()|[]{}^$                                                    ← regex special chars
0e6be1f1e21ffc33590b888fd4dc81b19713e570e805d4e5df80a493c9571a05  ← THE KEY (64 hex chars)
error creating AES cipher: error creating GCM:                    ← error messages
documentcookie;=guest_id                                          ← other data
```

How can we be sure that `0e6be1f1...` is the AES key?
- 64 hex chars = 32 bytes = 256 bits = **exact AES-256 key size**
- It appears **immediately before** `error creating AES cipher:` error message
- Go's `crypto/aes` package embeds error messages near key operations
- The regex chars before it (`\.+*?...^$`) are from a different Go package (regexp)
- Go linker concatenates nearby string literals from the data segment

or a more obv way is just to run
```bash
# Extract 64-char sequences, filter to only those with letters (true hex, not just numbers)
$ strings xpforwarded.wasm | grep -oE "[0-9a-f]{64}" | grep -E "[a-f]"
0e6be1f1e21ffc33590b888fd4dc81b19713e570e805d4e5df80a493c9571a05
```

And this is the **only** 64-char hex string with letters in the entire binary.

#### Evidence Source 6: JS Property Access Paths

The string `navigatoruserActivationhasBeenActiveuserAgentwebdriverundefined` is concatenated property names. Go's `syscall/js` package stores property names as strings:

```go
// This Go code:
nav.Get("userAgent").String()
nav.Get("userActivation").Get("hasBeenActive").Bool()
nav.Get("webdriver").Bool()

// Results in these strings being embedded:
// "navigator", "userAgent", "userActivation", "hasBeenActive", "webdriver"
```

#### Evidence Source 7: Return Value Structure

The string `strexpiryTimeMillis` reveals the return object keys:

```go
// Concatenated: "str" + "expiryTimeMillis"
return map[string]interface{}{
    "str":              encoded,        // ← "str"
    "expiryTimeMillis": timestamp,      // ← "expiryTimeMillis"
}
```

#### Evidence Source 8: Type Names in WAT Data Segments

Looking at the WAT data segments:

```wat
(data (;33;) ... "javascript_fingerprint.ClientSignals" ...)
(data (;33;) ... "json.MarshalerError" ...)
```

This confirms:
- Package is named `javascript_fingerprint`
- Main type is `ClientSignals`
- Uses `encoding/json` for marshaling

#### Putting It All Together

**Step-by-step reconstruction:**

1. **Find the function name** → `getForwardedForStr` (from strings)

2. **Find what data is collected** → navigator properties (from JS property strings)

3. **Find the data structure** → JSON tags reveal struct fields:
   ```go
   type ClientSignals struct {
       NavigatorProperties NavigatorProperties `json:"navigator_properties"`
       CreatedAt          int64               `json:"created_at"`
   }
   ```

4. **Find the encryption method** → AES-GCM (from package paths)

5. **Find the encryption key** → 64-char hex string

6. **Find the return format** → `{str, expiryTimeMillis}` from concatenated strings

7. **Find error handling** → Error message strings reveal error paths

#### Reconstructing the Data Flow

From the strings and imports, we can reconstruct what the module does:

##### 1. Entry Point Setup

**Evidence:** String `getForwardedForStr` + Go WASM always exports to `window`

When `_start` is called:
```go
// Pseudocode from decompilation
func main() {
    js.Global().Set("getForwardedForStr", js.FuncOf(getForwardedForStr))
}
```

##### 2. Data Collection Function

**Evidence chain:**
```
String found: "json:\"user_agent\""           → Field name in struct
String found: "json:\"has_been_active\""      → Boolean field  
String found: "json:\"webdriver\""            → Boolean field
String found: "json:\"navigator_properties\"" → Parent struct field
String found: "json:\"created_at\""           → Timestamp field
String found: "navigatoruserActivation..."    → JS property access path
String found: "javascript_fingerprint.ClientSignals" → Type name
Import: "syscall/js.valueGet"                 → Confirms JS property access
```

```go
// Reconstructed from strings
type NavigatorProperties struct {
    UserAgent      string `json:"user_agent"`      // ← from json:"user_agent"
    HasBeenActive  bool   `json:"has_been_active"` // ← from json:"has_been_active"  
    Webdriver      bool   `json:"webdriver"`       // ← from json:"webdriver"
}

type ClientSignals struct {
    NavigatorProperties NavigatorProperties `json:"navigator_properties"` // ← from json:"navigator_properties"
    CreatedAt          int64               `json:"created_at"`            // ← from json:"created_at"
}

func collectSignals() ClientSignals {
    nav := js.Global().Get("navigator")  // ← from "navigator" in property strings
    
    return ClientSignals{
        NavigatorProperties: NavigatorProperties{
            UserAgent:     nav.Get("userAgent").String(),                          // ← "userAgent"
            HasBeenActive: nav.Get("userActivation").Get("hasBeenActive").Bool(),  // ← "userActivation" + "hasBeenActive"
            Webdriver:     nav.Get("webdriver").Bool(),                            // ← "webdriver"
        },
        CreatedAt: time.Now().UnixMilli(),  // ← "Datenow" string found
    }
}

// Note: guest_id is extracted separately for key derivation, not included in ClientSignals
func extractGuestId(cookieStr string) string {
    // Parse "guest_id=v1%3A..." from cookie string
    // Return value used for: SHA256(baseKey + guestId)
}
```

##### 3. Encryption Function

**Evidence chain:**
```
Package: "crypto/aes"                         → Uses AES algorithm
Package: "crypto/cipher"                      → Uses cipher modes
Package: "crypto/internal/fips140/aes/gcm"   → Specifically GCM mode
String: "error creating AES cipher:"          → Error message reveals aes.NewCipher() call
String: "error creating GCM:"                 → Error message reveals cipher.NewGCM() call
String: "0e6be1f1e21ffc33...c9571a05"        → 32-byte (256-bit) AES key
Import: "wasi_snapshot_preview1.random_get"   → Needs random bytes for nonce
String: "AES-GCM"                            → Confirms GCM mode
```

**How we know it's AES-256-GCM:**
1. Package path includes "gcm" → GCM mode
2. Key is 32 bytes (256 bits) → AES-256
3. `random_get` import → needs random IV/nonce
4. GCM standard nonce is 12 bytes

```go
// Reconstructed from crypto package usage
func encrypt(plaintext []byte, guestId string) ([]byte, error) {
    // Base key from embedded 64-char hex string (32 bytes = AES-256)
    baseKeyHex := "0e6be1f1e21ffc33590b888fd4dc81b19713e570e805d4e5df80a493c9571a05"
    
    // Derive per-user encryption key ← discovered from real token analysis
    // Formula: SHA256(baseKey + guestId)
    combined := baseKeyHex + guestId
    hash := sha256.Sum256([]byte(combined))
    key := hash[:]  // 32 bytes
    
    // Create AES cipher ← evidence: "error creating AES cipher:" error message
    block, err := aes.NewCipher(key)
    if err != nil {
        return nil, fmt.Errorf("error creating AES cipher: %w", err)  // ← exact string found
    }
    
    // Create GCM mode ← evidence: "error creating GCM:" + "crypto/.../gcm" package
    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return nil, fmt.Errorf("error creating GCM: %w", err)  // ← exact string found
    }
    
    // Generate random nonce ← evidence: random_get import, GCM standard = 12 bytes
    nonce := make([]byte, gcm.NonceSize())  // gcm.NonceSize() returns 12
    io.ReadFull(rand.Reader, nonce)
    
    // Encrypt and seal ← standard GCM operation
    // Output format: nonce + ciphertext + auth_tag (GCM appends 16-byte tag)
    ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
    return ciphertext, nil
}
```

**Key Derivation Discovery:**
- The base key alone does NOT work for decrypting real tokens
- Real tokens require: `SHA256(baseKey + guestId)` to derive the actual encryption key
- This was discovered by analyzing actual request headers and testing decryption
- The `guest_id` cookie value is extracted from `document.cookie` but NOT included in the payload

##### 4. Main Function

**Evidence chain:**
```
String: "getForwardedForStr"          → Exported function name
String: "encoding/json"               → Uses JSON marshaling  
Package: "encoding/base64"            → Uses base64 encoding
String: "strexpiryTimeMillis"         → Return object keys (concatenated)
String: "Error encrypting data:"      → Error handling path
Import: "syscall/js.valueSet"         → Sets values on JS objects (return value)
String: "ObjectstrexpiryTimeMillis"   → Confirms return is a JS object with these keys
```

How we know the return format:
1. `strexpiryTimeMillis` = `str` + `expiryTimeMillis` (concatenated keys)
2. `Object` prefix suggests it's a JS object/map
3. Standard Go WASM pattern returns `map[string]interface{}`

```go
func getForwardedForStr(this js.Value, args []js.Value) interface{} {
    // Extract guest_id from cookies ← evidence: "documentcookie;=guest_id" string
    doc := js.Global().Get("document")
    cookieStr := doc.Get("cookie").String()
    guestId := extractGuestId(cookieStr)  // e.g., "v1%3A176824413470818950"
    
    // Collect signals ← uses collectSignals() we reconstructed
    signals := collectSignals()
    
    // Serialize to JSON ← evidence: "encoding/json" package
    jsonData, _ := json.Marshal(signals)
    
    // Encrypt with guest_id-derived key ← uses encrypt() with key derivation
    encrypted, err := encrypt(jsonData, guestId)
    if err != nil {
        return map[string]interface{}{"error": err.Error()}  // ← "Error encrypting data:"
    }
    
    // Encode as base64 ← evidence: "encoding/base64" package, standard pattern
    encoded := base64.StdEncoding.EncodeToString(encrypted)
    
    // Return result ← evidence: "strexpiryTimeMillis" = "str" + "expiryTimeMillis"
    return map[string]interface{}{
        "str":              encoded,                              // ← "str"
        "expiryTimeMillis": time.Now().Add(time.Hour).UnixMilli(), // ← "expiryTimeMillis"
    }
}
```

Why we know it's base64:
- Output in browser is clearly base64 (A-Za-z0-9+/=)
- Go's `encoding/base64` package is present
- Standard pattern for binary-to-string encoding

---

### Step 7: Key Derivation Discovery (guest_id)

#### The Problem

Initially, I thought the base AES key (`0e6be1f1...`) was used directly for encryption. 

However, when I tried to decrypt real tokens from actual Twitter/X requests, decryption failed with authentication errors.

After running some tests based on every parameter provided from the request headers (almost a bruteforce, didn't wanted to spend more time debugging)
`SHA256(baseKey + guestId)` happeared to be the derivation way for the actual key.

#### Key Derivation Formula

```javascript
// Base key (found in WASM)
const baseKey = "0e6be1f1e21ffc33590b888fd4dc81b19713e570e805d4e5df80a493c9571a05";

// Guest ID from cookie (e.g., "v1%3A176824413470818950")
const guestId = extractGuestId(document.cookie);

// Derive per-user encryption key
const combined = baseKey + guestId;
const finalKey = SHA256(combined);
```

---

### Step 8: Recreating the JavaScript Implementation

#### Utility Functions

```javascript
// Convert hex string to bytes
function hexToBytes(hex) {
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < hex.length; i += 2) {
        bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
    }
    return bytes;
}

// Convert bytes to base64
function bytesToBase64(bytes) {
    let binary = '';
    for (let i = 0; i < bytes.length; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
}
```

#### Fingerprint Collection

```javascript
function collectClientSignals() {
    const navigatorProps = {
        user_agent: navigator.userAgent,
        has_been_active: navigator.userActivation?.hasBeenActive || false,
        webdriver: navigator.webdriver === true
    };
    
    return {
        navigator_properties: navigatorProps,
        created_at: Date.now()
    };
}
```

#### Key Derivation

```javascript
const BASE_KEY_HEX = "0e6be1f1e21ffc33590b888fd4dc81b19713e570e805d4e5df80a493c9571a05";

/**
 * Derive encryption key from guest_id
 * Formula: SHA256(baseKey + guestId)
 */
async function deriveKeyFromGuestId(guestId) {
    const combined = BASE_KEY_HEX + guestId;
    const hash = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(combined));
    return new Uint8Array(hash);
}
```

#### AES-GCM Encryption

```javascript
async function encryptAESGCM(plaintext, guestId) {
    // Derive per-user encryption key
    const key = await deriveKeyFromGuestId(guestId);
    
    // Generate random 12-byte IV (standard for GCM)
    const iv = crypto.getRandomValues(new Uint8Array(12));
    
    // Import the derived key
    const cryptoKey = await crypto.subtle.importKey(
        'raw',
        key,
        { name: 'AES-GCM' },
        false,
        ['encrypt']
    );
    
    // Encrypt
    const encoder = new TextEncoder();
    const plaintextBytes = encoder.encode(plaintext);
    
    const ciphertext = await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv: iv, tagLength: 128 },
        cryptoKey,
        plaintextBytes
    );
    
    // Combine: IV + ciphertext (includes auth tag)
    const result = new Uint8Array(iv.length + ciphertext.byteLength);
    result.set(iv, 0);
    result.set(new Uint8Array(ciphertext), iv.length);
    
    return result;
}
```

#### Main Implementation

```javascript
class XPForwardedForSDK {
    async getForwardedForStr() {
        // 1. Extract guest_id from cookies
        const guestId = this.getGuestId();  // e.g., "v1%3A176824413470818950"
        
        // 2. Collect fingerprint data
        const clientSignals = collectClientSignals();
        
        // 3. Serialize to JSON
        const jsonPayload = JSON.stringify(clientSignals);
        
        // 4. Encrypt with AES-GCM using guest_id-derived key
        const encryptedBytes = await encryptAESGCM(jsonPayload, guestId);
        
        // 5. Encode as base64
        const base64Token = bytesToBase64(encryptedBytes);
        
        // 6. Return result with expiry
        return {
            str: base64Token,
            expiryTimeMillis: Date.now() + (60 * 60 * 1000) // 1 hour
        };
    }
    
    getGuestId() {
        const cookies = document.cookie.split(';');
        for (const cookie of cookies) {
            const [name, value] = cookie.trim().split('=');
            if (name === 'guest_id') {
                return value;
            }
        }
        return '';
    }
}
```

---

### Step 9: Validation

#### Testing Token Structure

```javascript
// Generate a token
const sdk = new XPForwardedForSDK();
const result = await sdk.getForwardedForStr();

console.log("Token:", result.str);
console.log("Expiry:", new Date(result.expiryTimeMillis));

// Token format: base64(12-byte IV + encrypted JSON + 16-byte auth tag)
const decoded = atob(result.str);
console.log("Total bytes:", decoded.length);
console.log("IV (first 12):", [...decoded.slice(0,12)].map(c => c.charCodeAt(0)));
```

#### Decryption Test

```javascript
async function decryptToken(base64Token, guestId) {
    const bytes = Uint8Array.from(atob(base64Token), c => c.charCodeAt(0));
    
    const iv = bytes.slice(0, 12);
    const ciphertext = bytes.slice(12);
    
    // Derive the same key used for encryption
    const key = await deriveKeyFromGuestId(guestId);
    
    const cryptoKey = await crypto.subtle.importKey(
        'raw',
        key,
        { name: 'AES-GCM' },
        false,
        ['decrypt']
    );
    
    const decrypted = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: iv, tagLength: 128 },
        cryptoKey,
        ciphertext
    );
    
    return JSON.parse(new TextDecoder().decode(decrypted));
}

// Verify round-trip
const guestId = "v1%3A176824413470818950";  // From document.cookie as guest_id
const token = await sdk.getForwardedForStr();
const decrypted = await decryptToken(token.str, guestId);
console.log("Decrypted:", decrypted);
// Output: { navigator_properties: { userAgent: "...", hasBeenActive: "false", webdriver: "false" }, created_at: 1234567890 }
// Note: Real payload uses camelCase and string booleans
```

---

### Step 10: Multi-Language Implementations


So now that we have the JS part fully working, it was just time to cleanup the code, convert into a NodeJS module that you can find in:

- [GO Version](./xp_forwarded_for/go/main.go)
- [NodeJS Version](./xp_forwarded_for/nodejs/index.js)
- [Python Version](./twitter_generator/xp_forwarded_for/main.py)

---


## Author

If you found this project helpful or interesting, consider starring the repo and following me for more security research and tools, or buy me a coffee to keep me up.

<p align="center">
  <a href="https://github.com/GlizzyKingDreko"><img src="https://img.shields.io/badge/GitHub-100000?style=for-the-badge&logo=github&logoColor=white" alt="GitHub"></a>
  <a href="https://twitter.com/GlizzyKingDreko"><img src="https://img.shields.io/badge/Twitter-1DA1F2?style=for-the-badge&logo=twitter&logoColor=white" alt="Twitter"></a>
  <a href="https://medium.com/@GlizzyKingDreko"><img src="https://img.shields.io/badge/Medium-12100E?style=for-the-badge&logo=medium&logoColor=white" alt="Medium"></a>
  <a href="https://discord.com/users/GlizzyKingDreko"><img src="https://img.shields.io/badge/Discord-7289DA?style=for-the-badge&logo=discord&logoColor=white" alt="Discord"></a>
  <a href="mailto:glizzykingdreko@protonmail.com"><img src="https://img.shields.io/badge/ProtonMail-8B89CC?style=for-the-badge&logo=protonmail&logoColor=white" alt="Email"></a>
  <a href="https://buymeacoffee.com/glizzykingdreko"><img src="https://img.shields.io/badge/Buy%20Me%20a%20Coffee-yellow?style=for-the-badge&logo=buy-me-a-coffee&logoColor=white" alt="Buy Me a Coffee"></a>
</p>
