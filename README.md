# Frida Full-Featured Hook Framework

[English](README.md) | [简体中文](README-CN.md)

A powerful, modular Frida script framework for Android application analysis, penetration testing and security research. The framework provides comprehensive features including encryption monitoring, network monitoring, anti-debugging bypass, sensitive API monitoring, and automatic key extraction.

## Directory Structure

```
frdia/
│
├── frida_master.js          # Main entry file, configures and loads all modules
├── frida_master.js.bak      # Main file backup
│
├── modules/                 # Functional modules directory
│   ├── crypto_monitor.js    # Encryption monitoring module
│   ├── network_monitor.js   # Network monitoring module
│   ├── anti_debug.js        # Anti-debugging bypass module
│   ├── sensitive_api.js     # Sensitive API monitoring module
│   ├── auto_extractor.js    # Automatic key extraction module
│   ├── system_api_monitor.js # System function monitoring module
│   └── dex_dumper.js        # DEX unpacking module
│
├── examples/                # Example code directory
│   └── usage_example.js     # Usage example script
│
└── backup/                  # Backup script directory (single-function scripts)
    ├── hook_java_method.js  # Java method hook script
    ├── hook_native_function.js # Native function hook script
    ├── bypass_ssl_pinning.js # SSL certificate pinning bypass
    ├── dump_stack.js        # Stack trace script
    └── ...                  # Other single-function scripts
```

## Requirements

- Frida >= 14.0.0
- Android device (physical or emulator)
- Python 3.x (if using Frida-tools)

## Quick Start

### Basic Usage

1. Clone the code to your local machine:

```bash
git clone https://github.com/laozig/frdia-hook.git
cd frdia
```

2. Inject the script using Frida:

```bash
# Specify package name for injection (recommended)
frida -U -f com.example.app -l frida_master.js --no-pause

# Or attach to a running process
frida -U -n "Application Name" -l frida_master.js

# Attach using process ID
frida -U -p <PID> -l frida_master.js
```

### Log Output

- Real-time monitoring information output to console
- Log file saved at: `/sdcard/frida_log.txt`
- Extracted keys saved at: `/sdcard/frida_extracted_keys.json`

## Main Framework File: frida_master.js

The main entry file is responsible for configuring the framework and loading various functional modules.

### Configuration Parameters

In `frida_master.js`, you can modify the following configuration:

```javascript
var config = {
    logLevel: 'info',           // Log level: debug, info, warn, error
    fileLogging: true,          // Whether to save logs to a file
    logFilePath: '/sdcard/frida_log.txt',  // Log file path
    autoExtractKeys: true,      // Automatically extract encryption keys
    bypassAllDetection: true,   // Bypass all detection mechanisms
    colorOutput: true,          // Console color output
    stackTrace: false,          // Print call stack
    fridaCompatMode: false      // Frida 14.x compatibility mode
};
```

### Main Features

- **Logging System**: Provides four log levels (debug, info, warn, error) and color output
- **Utility Functions**: Provides hex dumps, byte array conversion, and other utility functions
- **Module Loading**: Loads functional modules as needed
- **Environment Check**: Checks the running environment and creates log files
- **Version Detection**: Automatically checks Frida version and enables compatibility mode when needed

### Logging System

The framework provides four log levels:
- **debug**: Most detailed debug information
- **info**: General information (default)
- **warn**: Warning messages
- **error**: Error messages

Example:
```javascript
logger.debug("TAG", "Debug information");
logger.info("TAG", "General information");
logger.warn("TAG", "Warning message");
logger.error("TAG", "Error message");
```

### Utility Functions

The main framework provides common utility functions:
- `utils.hexdump()`: Generates a hexadecimal representation of binary data
- `utils.bytesToString()`: Converts byte array to string
- `utils.stringToBytes()`: Converts string to byte array
- `utils.getStackTrace()`: Gets the current call stack
- `utils.readMemory()`: Compatible memory reading function across Frida versions

## Detailed Module Description

### 1. Encryption Monitoring Module: modules/crypto_monitor.js

#### Feature Overview

Monitors and records the use of common encryption algorithms, automatically extracting keys, IVs, plaintext, and ciphertext.

#### Detailed Parameter Description

The encryption monitoring module supports the following parameter configurations, which can be passed through the API when loading the module:

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `enableKeyExtraction` | Boolean | true | Whether to extract encryption keys |
| `logPlaintext` | Boolean | true | Whether to log plaintext data |
| `logCiphertext` | Boolean | true | Whether to log ciphertext data |
| `maxDataSize` | Integer | 1024 | Maximum bytes of data to log |
| `algorithmFilter` | String[] | [] | Only monitor specified algorithms, empty array means monitor all |

#### Parameter Configuration Method

```javascript
// Manually load and configure the crypto monitoring module
var cryptoModule = require('./modules/crypto_monitor.js')(config, logger, utils);

// Configure algorithm filter, only monitor specific algorithms
cryptoModule.setAlgorithmFilter(["AES/CBC/PKCS5Padding", "RSA/ECB/PKCS1Padding"]);

// Set maximum data logging size (bytes)
cryptoModule.setMaxDataSize(2048);

// Enable or disable specific features
cryptoModule.enableKeyExtraction(true);  // Enable key extraction
cryptoModule.enablePlaintextLogging(false);  // Disable plaintext logging
```

#### Supported Encryption APIs

- **Java Cryptography Standard Library**:
  - `javax.crypto.Cipher` (AES/DES and other symmetric encryption)
  - `java.security.MessageDigest` (MD5/SHA and other hash algorithms)
  - `android.util.Base64` (Base64 encoding/decoding)
  - RSA key generation and encryption/decryption

- **Third-Party Encryption Libraries**:
  - BouncyCastle
  - Apache Commons Codec

#### Best Usage Methods

**Scenario 1: General Monitoring**
```javascript
// Default configuration, monitor all encryption operations
require('./modules/crypto_monitor.js')(config, logger, utils);
```

**Scenario 2: Performance-Optimized Monitoring**
```javascript
// Reduce log volume, improve performance
var cryptoModule = require('./modules/crypto_monitor.js')(config, logger, utils);
cryptoModule.setAlgorithmFilter(["AES", "RSA"]); // Only monitor important algorithms
cryptoModule.enablePlaintextLogging(false);  // Don't log plaintext data
cryptoModule.enableCiphertextLogging(false); // Don't log ciphertext data
cryptoModule.setMaxDataSize(128); // Limit record size
```

**Scenario 3: App-Specific Optimization**
```javascript
// For a banking app using AES encryption
var cryptoModule = require('./modules/crypto_monitor.js')(config, logger, utils);
cryptoModule.setAlgorithmFilter(["AES"]);
cryptoModule.addCustomHook("com.bankapp.security.CryptoUtil", "encrypt");
```

#### View Monitoring Results

All encryption operations will be displayed in the console and log file, in the following format:

```
[12:34:56][INFO] (CRYPTO) ====== Encryption Key Found ======
[12:34:56][INFO] (CRYPTO) Algorithm: AES
[12:34:56][INFO] (CRYPTO) Key: [byte array]
[12:34:56][INFO] (CRYPTO) Key(HEX): A1B2C3D4E5F6...
[12:34:56][INFO] (CRYPTO) Key(B64): a1b2c3d4e5f6...
[12:34:56][INFO] (CRYPTO) IV: [byte array]
[12:34:56][INFO] (CRYPTO) IV(HEX): 0102030405060708...
[12:34:56][INFO] (CRYPTO) IV(B64): AAECAwQFBgcICQ==
[12:34:56][INFO] (CRYPTO) Plaintext Sample: Data to be encrypted
[12:34:56][INFO] (CRYPTO) Ciphertext Sample: [Encrypted data]
[12:34:56][INFO] (CRYPTO) ==========================
```

#### Advantages and Limitations

**Advantages:**
- Comprehensive monitoring of all encryption/decryption operations
- Automatic extraction of keys, IVs and sensitive information
- Support for mainstream encryption libraries and custom implementations
- Highly configurable, can adjust monitoring granularity as needed
- Real-time view of encryption parameters without reverse engineering

**Limitations:**
- Cannot directly monitor Native layer encryption (needs to be combined with native_function.js)
- Heavy monitoring may impact application performance
- May capture incomplete keys for rapidly changing memory keys
- Some heavily obfuscated code might require manual adjustment of hook points

### 2. Anti-Debug Bypass Module: modules/anti_debug.js

#### Feature Overview

Automatically bypasses various anti-debugging, anti-root, anti-emulator, anti-injection, and anti-packet capture detection mechanisms.

#### Detailed Parameter Description

The anti-debug bypass module supports the following parameter configurations, which can be set through the API when loading the module:

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `bypassAllDetection` | Boolean | true | Whether to enable all bypass features |
| `bypassRootDetection` | Boolean | true | Whether to bypass root detection |
| `bypassEmulatorDetection` | Boolean | true | Whether to bypass emulator detection |
| `bypassDebugDetection` | Boolean | true | Whether to bypass debugging detection |
| `bypassFridaDetection` | Boolean | true | Whether to bypass Frida detection |
| `bypassXposedDetection` | Boolean | true | Whether to bypass Xposed detection |
| `bypassSslPinning` | Boolean | true | Whether to bypass SSL certificate pinning |
| `bypassSignatureVerification` | Boolean | true | Whether to bypass signature verification |
| `fakeDeviceInfo` | Object | null | Custom device info for device spoofing |
| `preventExit` | Boolean | true | Prevent application from force exiting |
| `logBypassedDetections` | Boolean | true | Whether to log bypassed detections |
| `bypassNativeDetection` | Boolean | true | Whether to bypass Native layer detection |

#### Parameter Configuration Method

```javascript
// Manually load and configure anti-debug bypass module
var antiDebugModule = require('./modules/anti_debug.js')(config, logger, utils);

// Selectively enable/disable specific bypass features
antiDebugModule.disableRootDetectionBypass();  // Disable root detection bypass
antiDebugModule.enableEmulatorDetectionBypass(true);  // Enable emulator detection bypass

// Set custom device info for device spoofing
antiDebugModule.setFakeDeviceInfo({
    brand: "samsung",
    model: "SM-G973F",
    manufacturer: "Samsung",
    fingerprint: "samsung/beyond1ltexx/beyond1:10/QP1A.190711.020/G973FXXU3BSL1:user/release-keys",
    sdkInt: 29,
    androidVersion: "10"
});

// Configure SSL unpinning options
antiDebugModule.setSslUnpinningOptions({
    enableOkHttp: true,
    enableConscrypt: true,
    enableOpenSSL: true,
    enableCustomTrustManager: true
});

// Add custom detection bypass (for app-specific anti-debug mechanisms)
antiDebugModule.addCustomHook({
    className: "com.example.app.SecurityUtils",
    methodName: "checkDeviceIntegrity",
    returnValue: true
});
```

#### Bypass Detection Types

- **Java Layer Anti-Debug Bypass**:
  - `Debug.isDebuggerConnected()`
  - `ApplicationInfo.FLAG_DEBUGGABLE`
  - `System.exit()` to prevent application from force exiting
  - `Process.killProcess()` to prevent process termination

- **Root Detection Bypass**:
  - Sensitive file detection (`/system/bin/su` etc.)
  - Runtime.exec("su") detection
  - Shell.exec detection

- **Emulator Detection Bypass**:
  - Build attribute detection (modifying BRAND,MODEL etc.)
  - TelephonyManager related detection (IMEI etc.)
  - Sensor detection

- **Frida/Xposed Detection Bypass**:
  - Keyword detection
  - Sensitive file detection
  - /proc/self/maps detection
  - Reflection call detection

- **SSL Pinning Bypass**:
  - X509TrustManager bypass
  - OkHttp certificate pinning bypass
  - TrustManagerImpl bypass

- **Signature Verification Bypass**:
  - PackageManager.getPackageInfo bypass
  - Signature.equals bypass

- **Native Layer Detection Bypass**:
  - ptrace anti-debug bypass
  - /proc/maps detection bypass
  - Native layer Root detection bypass

#### Best Usage Methods

**Scenario 1: Standard Application Analysis**
```javascript
// Use default configuration, enable all bypasses
require('./modules/anti_debug.js')(config, logger, utils);
```

**Scenario 2: Banking/Financial App Analysis**
```javascript
var antiDebugModule = require('./modules/anti_debug.js')(config, logger, utils);

// Optimize bypass settings for financial apps
antiDebugModule.enableAdvancedDetectionBypass(true);  // Enable advanced detection bypass
antiDebugModule.setSslUnpinningOptions({   // Custom SSL bypass options
    enableOkHttp: true,
    enableCustomTrustManager: true,
    enableNativeTLS: true,
    trustAllCertificates: true
});

// Disguise as normal device, avoid extra detection from banking apps
antiDebugModule.setFakeDeviceInfo({
    brand: "samsung",
    model: "SM-G973F",
    bootloaderUnlocked: false,
    developerMode: false
});
```

**Scenario 3: Game Protection Bypass**
```javascript
var antiDebugModule = require('./modules/anti_debug.js')(config, logger, utils);

// Configure for game protection mechanisms
antiDebugModule.enableNativeDetectionBypass(true);  // Enhance Native layer bypass
antiDebugModule.enableTimingDetectionBypass(true);  // Bypass timing detection
antiDebugModule.disableLogEvents(true);  // Avoid excessive detection event logging
```

#### Advantages and Limitations

**Advantages:**
- Comprehensive coverage of common Android anti-debugging/anti-root/anti-emulator detection mechanisms
- Modular design, can enable/disable specific bypass features as needed
- Automatically handles Native and Java layer detections
- Supports device info spoofing to hide real environment characteristics
- Built-in SSL certificate pinning bypass
- Can dynamically add custom bypass rules for specific applications
- Records bypassed detection points for protection mechanism analysis

**Limitations:**
- May require additional configuration for highly customized protection schemes
- Some advanced anti-debugging techniques may require Native modules
- Bypassing many detection points could cause performance degradation
- May not bypass hardware-based detections (like SafetyNet attestation)
- Not suitable for apps with custom VM protection
- Excessive bypassing may cause application functionality issues in extreme cases
- Latest anti-debugging techniques may require module updates

### 3. Network Monitoring Module: modules/network_monitor.js

#### Feature Overview

Monitors and records HTTP/HTTPS requests and responses, WebSocket communications, Socket communications, etc.

#### Detailed Parameter Description

The network monitoring module supports the following parameter configurations, which can be set through the API when loading the module:

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `logRequestBody` | Boolean | true | Whether to log request body content |
| `logResponseBody` | Boolean | true | Whether to log response body content |
| `maxBodySize` | Integer | 5120 | Maximum bytes of request/response body to log |
| `enableSslUnpinning` | Boolean | true | Whether to automatically bypass SSL certificate pinning |
| `urlFilters` | String[] | [] | URL filters, empty array means monitor all URLs |
| `headerFilters` | Object | {} | Request header filters, for filtering requests with specific headers |
| `contentTypeFilters` | String[] | [] | Content type filters, empty array means monitor all content types |
| `excludeUrlPatterns` | RegExp[] | [] | Patterns to exclude specific URLs |
| `logBinaryResponses` | Boolean | false | Whether to log binary response data |

#### Parameter Configuration Method

```javascript
// Manually load and configure network monitoring module
var networkModule = require('./modules/network_monitor.js')(config, logger, utils);

// Set URL filters, only monitor specific domains
networkModule.addUrlFilter("api.example.com");
networkModule.addUrlFilter("login.example.com");

// Exclude specific URLs
networkModule.addExcludeUrlPattern(/\.jpg$|\.png$|\.gif$/);  // Exclude image requests

// Filter by content type
networkModule.addContentTypeFilter("application/json");
networkModule.addContentTypeFilter("application/x-www-form-urlencoded");

// Set request/response body size limits
networkModule.setMaxBodySize(10240);  // Set to 10KB

// Configure request header filters
networkModule.addHeaderFilter("Authorization");  // Only monitor requests with Authorization header

// Enable/disable specific features
networkModule.enableResponseBodyLogging(false);  // Don't log response bodies
networkModule.enableBinaryResponseLogging(true); // Log binary responses
```

#### Supported Network APIs

- **HTTP Clients**:
  - OkHttp3
  - HttpURLConnection
  - Volley

- **Web Components**:
  - WebView
  - WebSocket

- **Low-Level Communication**:
  - Socket

#### Best Usage Methods

**Scenario 1: General Monitoring**
```javascript
// Default configuration, monitor all network activity
require('./modules/network_monitor.js')(config, logger, utils);
```

**Scenario 2: API Debugging Optimization**
```javascript
var networkModule = require('./modules/network_monitor.js')(config, logger, utils);

// Only focus on specific API endpoints
networkModule.addUrlFilter("api.example.com/v1");

// Only monitor JSON content
networkModule.addContentTypeFilter("application/json");

// Exclude heartbeat requests
networkModule.addExcludeUrlPattern(/\/heartbeat$/);

// Increase response body size limit for large API responses
networkModule.setMaxBodySize(20480);
```

**Scenario 3: Performance-Optimized Monitoring**
```javascript
var networkModule = require('./modules/network_monitor.js')(config, logger, utils);

// Only log requests, not response bodies (reduce memory usage)
networkModule.enableResponseBodyLogging(false);

// Exclude static resources, reduce log volume
networkModule.addExcludeUrlPattern(/\.(jpg|png|gif|css|js)$/);

// Reduce recording size
networkModule.setMaxBodySize(1024);
```

#### Advantages and Limitations

**Advantages:**
- Comprehensive monitoring of all application network communications, including HTTPS encrypted traffic
- Rich filtering functionality, can customize monitoring for specific needs
- Automatically extracts and parses common authentication tokens (such as JWT)
- Supports mainstream HTTP client libraries and WebSocket implementations
- Can simultaneously monitor multiple types of network communication in the application
- Automatically bypasses SSL certificate pinning without additional configuration

**Limitations:**
- Large numbers of network requests will generate large logs, potentially affecting performance
- Complex binary protocols require additional parsers to understand content
- Some highly customized network libraries may require additional hook points
- Cannot directly monitor Native layer network requests (needs to be combined with native_function.js)
- May not support some non-standard WebSocket implementations or custom protocols
- Monitoring all response bodies may increase memory usage

### 4. Sensitive API Monitoring Module: modules/sensitive_api.js

#### Feature Overview

Monitors calls to sensitive APIs in the application, such as file access, clipboard operations, location services, camera, etc.

#### Detailed Parameter Description

The sensitive API monitoring module supports the following parameter configurations:

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `enableAllCategories` | Boolean | true | Whether to monitor all API categories |
| `categoriesEnabled` | Object | {} | Enabled status for each API category |
| `logParameters` | Boolean | true | Whether to log API call parameters |
| `logReturnValues` | Boolean | true | Whether to log API return values |
| `maxParameterSize` | Integer | 1024 | Maximum bytes of parameter values to log |
| `logStackTrace` | Boolean | false | Whether to log call stack |
| `fileExtensionFilter` | String[] | [] | File extension filter for file operations monitoring |
| `contentProviderFilter` | String[] | [] | ContentProvider URI filter |
| `customHooks` | Object[] | [] | Custom API monitoring configuration |
| `excludeMethods` | String[] | [] | Methods to exclude from monitoring |

#### Supported API Categories

The module categorizes monitored APIs into the following categories, each can be enabled or disabled individually:

1. **FILE_SYSTEM**: File system operations
2. **SHARED_PREFS**: SharedPreferences operations
3. **DATABASE**: Database operations
4. **CLIPBOARD**: Clipboard operations
5. **LOCATION**: Location services
6. **CAMERA**: Camera operations
7. **MICROPHONE**: Microphone operations
8. **CONTACTS**: Contacts access
9. **SMS**: SMS operations
10. **PHONE**: Phone operations
11. **DEVICE_INFO**: Device information retrieval
12. **ACCOUNT**: Account operations
13. **PACKAGE_MANAGER**: Package manager operations
14. **CRYPTO**: Crypto-related operations
15. **NETWORK_INFO**: Network information retrieval
16. **CONTENT_PROVIDER**: ContentProvider access
17. **WEBVIEW**: WebView-related operations
18. **IPC**: Inter-process communications

#### Parameter Configuration Method

```javascript
// Manually load and configure sensitive API monitoring module
var apiModule = require('./modules/sensitive_api.js')(config, logger, utils);

// Enable/disable specific API categories
apiModule.enableCategory('FILE_SYSTEM', true);    // Enable file system monitoring
apiModule.enableCategory('LOCATION', true);       // Enable location service monitoring
apiModule.enableCategory('DEVICE_INFO', false);   // Disable device info monitoring

// Only enable specified categories, disable all others
apiModule.enableOnly(['FILE_SYSTEM', 'SHARED_PREFS', 'CLIPBOARD']);

// Adjust logging options
apiModule.setLogParameters(true);      // Log call parameters
apiModule.setLogReturnValues(true);    // Log return values
apiModule.setLogStackTrace(true);      // Log call stack

// Set file extension filter
apiModule.setFileExtensionFilter(['.xml', '.db', '.json']);

// Add custom API monitoring
apiModule.addCustomHook({
    className: "com.example.app.DataManager",
    methodName: "readSensitiveData",
    parameterLogging: true,
    returnValueLogging: true,
    category: "CUSTOM"
});
```

#### Best Usage Methods

**Scenario 1: General Monitoring**
```javascript
// Default configuration, monitor all sensitive APIs
require('./modules/sensitive_api.js')(config, logger, utils);
```

**Scenario 2: Privacy Audit**
```javascript
var apiModule = require('./modules/sensitive_api.js')(config, logger, utils);

// Only monitor privacy-related API categories
apiModule.enableOnly([
    'LOCATION',
    'CAMERA',
    'MICROPHONE',
    'CONTACTS',
    'SMS',
    'PHONE',
    'DEVICE_INFO'
]);

// Enable stack trace logging for call source analysis
apiModule.setLogStackTrace(true);
```

**Scenario 3: Data Security Audit**
```javascript
var apiModule = require('./modules/sensitive_api.js')(config, logger, utils);

// Focus on data storage and encryption operations
apiModule.enableOnly([
    'FILE_SYSTEM',
    'SHARED_PREFS',
    'DATABASE',
    'CRYPTO'
]);

// Record detailed parameter and return value information
apiModule.setMaxParameterSize(4096);  // Increase parameter size logging
```

#### Advantages and Limitations

**Advantages:**
- Comprehensive coverage of Android sensitive APIs, clearly categorized for auditing
- Modular design, can enable/disable specific categories as needed
- Supports logging parameters and return values for in-depth analysis
- Can log call stack to track call origins
- Flexible filtering mechanisms for focusing on specific file types or URIs
- Can dynamically add custom monitoring points for specific applications
- Low-overhead configuration options suitable for long-term monitoring

**Limitations:**
- Monitoring many APIs will generate large logs, potentially affecting performance
- Some sensitive APIs may be implemented at the Native layer, requiring native_function.js
- For highly obfuscated apps, may need manual adjustment of class/method names
- Cannot monitor APIs called via reflection (unless specially handled)
- Excessive parameter and return value logging may increase memory usage
- Some API parameters or return values may be too complex for direct logging
- Some system-level APIs may differ between Android versions, requiring adaptation

### 5. Automatic Key Extraction Module: modules/auto_extractor.js

#### Feature Overview

Automatically identifies, extracts, and saves encryption keys, tokens, API keys, and configuration information from the application.

#### Detailed Parameter Description

The automatic key extraction module supports the following parameter configurations:

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `autoExtractKeys` | Boolean | true | Whether to enable automatic extraction |
| `outputFilePath` | String | '/sdcard/frida_extracted_keys.json' | Output file path for extracted data |
| `extractionSources` | Object | {} | Enabled status for each extraction source |
| `keyPatterns` | Object[] | [] | Regex patterns for key identification |
| `sensitiveKeywords` | String[] | [] | Sensitive keywords for identifying potential keys |
| `minKeyLength` | Integer | 16 | Minimum key length |
| `maxEntries` | Integer | 1000 | Maximum number of key entries to store |
| `saveInterval` | Integer | 5000 | Auto-save interval (milliseconds) |
| `removeDuplicates` | Boolean | true | Whether to remove duplicate keys |
| `customExtractionRules` | Object[] | [] | Custom extraction rules |
| `classPatterns` | String[] | [] | Class name patterns for static field extraction |

#### Extraction Sources

The module extracts keys from the following sources:

1. **Static Field Extraction**:
   - Analyzes static fields in common configuration classes
   - Examples: `Config.API_KEY`, `Constants.SECRET_KEY`, etc.
   - Special focus on field names with sensitive keywords

2. **Configuration File Extraction**:
   - Monitors file read operations, extracts configuration file contents
   - Supported formats: JSON, XML, Properties, YAML
   - Primarily focuses on `.properties`, `.json`, `.xml` files

3. **Network Request Extraction**:
   - Analyzes authentication information in HTTP request headers
   - Extracts tokens and keys from responses
   - Special focus on `Authorization`, `X-API-Key`, etc. headers

4. **SharedPreferences Extraction**:
   - Monitors SharedPreferences read/write operations
   - Extracts sensitive configuration items such as tokens, keys, etc.
   - Focuses on items with key names containing "key", "token", "secret", etc.

5. **Memory Key Extraction**:
   - Monitors key generation and encryption initialization operations
   - Captures keys from `javax.crypto.spec.SecretKeySpec`
   - Captures initialization vectors from `IvParameterSpec`

6. **Code Hardcoded Extraction**:
   - Analyzes string constants in code
   - Identifies hardcoded keys matching specific formats
   - Examples: Base64 encoded strings, hexadecimal strings, etc.

#### Parameter Configuration Method

```javascript
// Manually load and configure auto key extraction module
var extractorModule = require('./modules/auto_extractor.js')(config, logger, utils);

// Configure extraction options
extractorModule.setOutputFilePath('/sdcard/custom_keys.json');  // Custom output path
extractorModule.setSaveInterval(10000);  // Set save interval to 10 seconds

// Enable or disable specific extraction sources
extractorModule.enableExtractionSource('STATIC_FIELDS', true);
extractorModule.enableExtractionSource('NETWORK', true);
extractorModule.enableExtractionSource('SHARED_PREFS', false);  // Disable SharedPreferences extraction

// Add custom key identification patterns
extractorModule.addKeyPattern('API_KEY', /[Aa][Pp][Ii][_-]?[Kk][Ee][Yy][=:]\s*["']?([A-Za-z0-9_\-]{16,})["']?/);
extractorModule.addKeyPattern('JWT', /eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/);

// Add sensitive keywords
extractorModule.addSensitiveKeywords(['apikey', 'secret', 'password', 'token', 'auth', 'credential']);

// Add custom extraction rule
extractorModule.addCustomExtractionRule({
    className: "com.example.app.ApiClient",
    methodName: "authenticate",
    parameterIndex: 1,  // Extract second parameter as API key
    type: "API_KEY"
});

// Set class name patterns for static field scanning
extractorModule.setClassPatterns([
    "com.example.app.Config",
    "com.example.app.Constants",
    "com.example.app.util.Security"
]);
```

#### Key Identification Rules

The module uses the following rules to identify potential keys:

1. **Name Matching**:
   - Contains keywords: key, token, secret, password, auth, api, credential, etc.
   - Examples: `API_KEY`, `auth_token`, `secret_key`, etc.

2. **Format Matching**:
   - **Base64 Format**: `^[A-Za-z0-9+/=]{24,}$`
   - **Hex Format**: `^[A-Fa-f0-9]{16,}$`
   - **JWT Format**: `^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$`
   - **OAuth Format**: `^[a-zA-Z0-9]{32,}$`
   - **API Key Format**: Various regex patterns for common API key formats

3. **Context Matching**:
   - Appears in authentication-related method parameters or return values
   - Appears in specific request header fields (`Authorization`, `API-Key`, etc.)
   - Stored in configuration items with sensitive keywords in names

4. **Content Characteristics**:
   - Sufficient length (default 16+ characters)
   - High entropy (highly random strings)
   - Matches specific platform key formats (like AWS, Firebase, etc.)

#### Best Usage Methods

**Scenario 1: General Monitoring**
```javascript
// Use default configuration, monitor all extraction sources
require('./modules/auto_extractor.js')(config, logger, utils);
```

**Scenario 2: Network API Key Extraction**
```javascript
var extractorModule = require('./modules/auto_extractor.js')(config, logger, utils);

// Focus on extracting network API keys
extractorModule.disableAllSources();
extractorModule.enableExtractionSource('NETWORK', true);

// Add common API key formats
extractorModule.addKeyPattern('Twitter', /[tT][wW][iI][tT][tT][eE][rR].*["']([0-9a-zA-Z]{35,44})["']/);
extractorModule.addKeyPattern('Facebook', /[fF][aA][cC][eE][bB][oO][oO][kK].*["']([0-9a-f]{32})["']/);
extractorModule.addKeyPattern('GitHub', /[gG][iI][tT][hH][uU][bB].*["']([0-9a-zA-Z]{35,40})["']/);
extractorModule.addKeyPattern('Google', /[gG][oO][oO][gG][lL][eE].*["']([A-Za-z0-9_-]{39})["']/);

// Add HTTP header monitoring
extractorModule.addHeadersToMonitor([
    'x-api-key', 
    'authorization', 
    'client-secret',
    'client-id'
]);
```

**Scenario 3: Encryption Key Extraction**
```javascript
var extractorModule = require('./modules/auto_extractor.js')(config, logger, utils);

// Focus on extracting encryption keys
extractorModule.disableAllSources();
extractorModule.enableExtractionSource('CRYPTO_KEYS', true);
extractorModule.enableExtractionSource('STATIC_FIELDS', true);

// Configure extraction options
extractorModule.setMinKeyLength(8);  // AES keys might only be 16 bytes
extractorModule.addClassPatterns(["com.example.app.crypto", "com.example.security"]);  // Focus on specific packages
```

#### Advantages and Limitations

**Advantages:**
- Fully automatic extraction of various keys and sensitive information from applications
- Comprehensive analysis from multiple sources increases detection rate
- Intelligent identification of common key formats and characteristics
- Supports custom extraction rules and patterns
- Structured storage of extraction results for subsequent analysis
- Automatic deduplication and classification improves extraction quality
- Can view extraction progress in real-time without waiting for application completion

**Limitations:**
- May produce false positives, misidentifying ordinary strings as keys
- Highly encrypted or obfuscated keys may be difficult to identify
- Too many extraction rules may affect application performance
- Frequent file writing may cause IO pressure
- Cannot extract keys used only at the Native layer
- Custom format keys require manual configuration rules
- Large key extraction may increase memory usage

### 6. DEX Dumper Module: modules/dex_dumper.js

Extract DEX files from memory, supporting unpacking of various protection mechanisms, including Bangcle, ijiami, 360, and Tencent.

**File Path**: `modules/dex_dumper.js`

#### Detailed Parameter Description

The DEX dumper module supports the following configuration parameters:

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `outputDir` | String | '/sdcard/frida_dumps/' | Output directory for DEX files |
| `filterSystemClasses` | Boolean | true | Whether to filter system classes |
| `autoLoadClasses` | Boolean | true | Whether to automatically load all classes |
| `dumpClassLoaders` | Boolean | true | Whether to dump DEX from all ClassLoaders |
| `dumpMemory` | Boolean | true | Whether to scan memory for DEX files |
| `dumpOnClassLoad` | Boolean | true | Whether to extract DEX on class loading |
| `minDexSize` | Integer | 4096 | Minimum DEX file size (bytes) |
| `maxDexSize` | Integer | 20 * 1024 * 1024 | Maximum DEX file size (20MB) |
| `memScanIntervalMs` | Integer | 5000 | Memory scanning interval (milliseconds) |
| `supportedProtections` | String[] | ['Bangcle', 'ijiami', '360', 'Tencent', 'Ali Security', 'Baidu', 'Nagapt', 'Shenda', 'NetQin', 'Kiwisec', 'Tongfudun', 'Rising', 'APKProtect', 'TopJohnson', 'Coral', 'Canary', 'Huawei HMS', 'Huawei Security', 'HiSilicon', 'New ijiami', 'Ctrip', 'WeChat Mini-program', 'ByteDance', 'Cheetah Mobile', 'OPPO', 'vivo'] | Supported protection types |

#### Parameter Configuration Methods

```javascript
// Manually load and configure DEX dumper module
var dexDumper = require('./modules/dex_dumper.js')(config, logger, utils);

// Set the dumping output directory
dexDumper.setOutputDirectory('/sdcard/my_dumps/');

// Disable system class filtering, extract all classes
dexDumper.setFilterSystemClasses(false);

// Set DEX size limits (min 1KB, max 30MB)
dexDumper.setDexSizeLimit(1024, 30 * 1024 * 1024);

// Add support for other protection mechanisms
dexDumper.addProtectionSupport('SomeProtection');

// Display statistics after dumping is complete
setTimeout(function() {
    dexDumper.showStats();
}, 20000);  // Show stats after 20 seconds
```

#### Unpacking Principles

1. **ClassLoader Tracking**
   - Intercept BaseDexClassLoader/DexClassLoader/InMemoryDexClassLoader creation
   - Access ClassLoader internal structure via reflection to obtain DEX files
   - Extract real DEX from DexPathList and dexElements array

2. **Class Loading Monitoring**
   - Intercept Class.forName and ClassLoader.loadClass methods
   - Extract DEX from ClassLoader immediately after class loading
   - Record unique ClassLoaders to avoid duplicate extraction

3. **Memory Scanning**
   - Scan readable regions of process memory
   - Identify DEX files by their signature (magic number "dex\n")
   - Validate and extract complete DEX files

4. **Protection-Specific Handling**
   - For Bangcle: hook specific classes (e.g., "com.secneo.apkwrapper.AW")
   - For ijiami: hook key methods (e.g., "s.h.e.a.a.d")
   - For 360: hook "com.qihoo.util.StubApp" class
   - For Tencent: hook "com.tencent.StubShell.TxAppEntry" class
   - For Huawei HMS: hook HMS SDK key classes and methods
   - For Huawei Security: hook SecAppApplication class
   - For HiSilicon: hook HiSecureApplication and SecDexLoader classes  
   - For New ijiami: hook SuperApplication and DXApplication classes
   - For Ctrip: hook Shield related classes
   - For WeChat Mini-program: hook WeChat application and Tinker loader
   - For ByteDance: hook ShadowHook and Douyin app classes
   - For Phone Manufacturer Protections: target OPPO, vivo specific protection mechanisms

#### Automatic Extraction Process

1. **Initialization Phase**:
   - Create output directory
   - Set up all hooks
   - Delay memory scanning, waiting for application initialization

2. **Runtime Extraction**:
   - Monitor all ClassLoader creation after application starts
   - Extract DEX in real-time from newly discovered ClassLoaders
   - Periodically scan memory regions for unloaded DEX

3. **Class Loading Optimization**:
   - Provide automatic loading of all application classes
   - Force trigger class loading to decrypt encrypted DEX into memory

4. **Deduplication and Validation**:
   - Use hash values to avoid extracting the same DEX multiple times
   - Validate DEX file integrity, filter invalid files

#### Best Usage Practices

**Scenario 1: General Unpacking**
```javascript
// Use default configuration
require('./modules/dex_dumper.js')(config, logger, utils);
```

**Scenario 2: Memory Usage Optimization**
```javascript
var dexDumper = require('./modules/dex_dumper.js')(config, logger, utils);

// Disable periodic memory scanning to reduce memory usage
var customConfig = {
    dumpClassLoaders: true,
    dumpOnClassLoad: true,
    dumpMemory: false,  // Disable memory scanning
    autoLoadClasses: false  // Don't automatically load all classes
};

// Manually set configuration
Object.keys(customConfig).forEach(key => {
    if (typeof dexDumper[`set${key.charAt(0).toUpperCase() + key.slice(1)}`] === 'function') {
        dexDumper[`set${key.charAt(0).toUpperCase() + key.slice(1)}`](customConfig[key]);
    }
});
```

**Scenario 3: Protection-Specific Optimization**
```javascript
var dexDumper = require('./modules/dex_dumper.js')(config, logger, utils);

// If only targeting 360 protection
var customConfig = {
    supportedProtections: ['360'],
    dumpClassLoaders: true,
    dumpOnClassLoad: true,
    dumpMemory: true,
    autoLoadClasses: true
};

// Delayed execution, allowing protection code to initialize first
setTimeout(function() {
    // Show statistics after 20 seconds
    dexDumper.showStats();
}, 20000);
```

#### Output Format Details

1. **File Naming Format**:
   - DEX extracted from ClassLoader: `classes_XX.dex` (XX is a sequence number)
   - DEX extracted from memory: `memory_XX.dex`

2. **Log Output**:
```
[12:34:56][INFO] (DUMPER) DEX dumper module initialized
[12:34:56][INFO] (DUMPER) Output directory: /sdcard/frida_dumps/
[12:34:56][INFO] (DUMPER) Supported protections: Bangcle, ijiami, 360, Tencent, Ali Security, Baidu, Nagapt, Shenda, NetQin, Kiwisec, Tongfudun, Rising, APKProtect, TopJohnson, Coral, Canary, Huawei HMS, Huawei Security, HiSilicon, New ijiami, Ctrip, WeChat Mini-program, ByteDance, Cheetah Mobile, OPPO, vivo
[12:34:56][INFO] (DUMPER) ClassLoader hooks set up successfully
[12:34:56][INFO] (DUMPER) Class loading hooks set up successfully
[12:34:57][DEBUG] (DUMPER) ClassLoader created: /data/app/app-1.apk
[12:34:58][INFO] (DUMPER) Extracted DEX file: /sdcard/frida_dumps/classes_01.dex [Size: 4194304 bytes, from ClassLoader]
[12:34:59][INFO] (DUMPER) Extracted DEX file: /sdcard/frida_dumps/memory_02.dex [Size: 2097152 bytes, from memory]
```

3. **Extraction Statistics**:
```
[12:39:56][INFO] (DUMPER) ==== DEX Extraction Statistics ====
[12:39:56][INFO] (DUMPER) Extracted DEX files: 5
[12:39:56][INFO] (DUMPER) Extracted class files: 1024
[12:39:56][INFO] (DUMPER) Total size: 12 MB
[12:39:56][INFO] (DUMPER) Unique ClassLoaders: 3
[12:39:56][INFO] (DUMPER) Runtime: 300.45 seconds
[12:39:56][INFO] (DUMPER) Output directory: /sdcard/frida_dumps/
[12:39:56][INFO] (DUMPER) =========================
```

#### Advantages and Limitations

**Advantages:**
- Fully automatic extraction of DEX files from memory, no manual intervention needed
- Supports mainstream app protection schemes
- Uses multiple extraction methods simultaneously to increase success rate
- Can extract dynamically loaded DEX files in real-time
- Built-in recognition and special handling of common protection features
- Automatic validation and deduplication, filtering invalid DEX files
- Provides detailed statistics and analysis information

**Limitations:**
- May have limited effectiveness against high-strength obfuscation and custom protection schemes
- Scanning large memory areas may cause application lag
- Some extreme protection measures (like VM-based protection) may be ineffective
- Extraction process may use significant memory and storage space
- Cannot handle scenarios where DEX is decrypted and immediately destroyed
- Some advanced protections may require additional technical approaches
- Not applicable to system-level protection schemes (like Alibaba's KSLR)

#### Real-world Application Cases

**Case 1: Unpacking a 360-protected App**
```
[12:34:56][INFO] (DUMPER) DEX dumper module initialized
[12:34:57][INFO] (DUMPER) 360 protection hook set up: com.qihoo.util.StubApp
[12:35:02][DEBUG] (DUMPER) 360 protection API call: com.qihoo.util.StubApp.a
[12:35:03][INFO] (DUMPER) Extracted DEX file: /sdcard/frida_dumps/classes_01.dex [Size: 8392134 bytes, from ClassLoader]
[12:35:05][INFO] (DUMPER) Extracted DEX file: /sdcard/frida_dumps/classes_02.dex [Size: 5923412 bytes, from ClassLoader]
[12:35:10][INFO] (DUMPER) ==== DEX Extraction Statistics ====
[12:35:10][INFO] (DUMPER) Extracted DEX files: 2
[12:35:10][INFO] (DUMPER) Total size: 14 MB
```
Successfully extracted real DEX files from 360 protection.

**Case 2: Unpacking a Bangcle-protected App**
```
[12:34:56][INFO] (DUMPER) Bangcle protection hook set up: com.secneo.apkwrapper.AW
[12:35:01][DEBUG] (DUMPER) Bangcle protection API call: com.secneo.apkwrapper.AW.attachBaseContext
[12:35:02][DEBUG] (DUMPER) Starting to load all classes...
[12:35:45][INFO] (DUMPER) Finished loading classes, loaded 2143 classes
[12:35:46][INFO] (DUMPER) Extracted DEX file: /sdcard/frida_dumps/memory_01.dex [Size: 3145728 bytes, from memory]
[12:35:47][INFO] (DUMPER) Extracted DEX file: /sdcard/frida_dumps/memory_02.dex [Size: 2097152 bytes, from memory]
```
Extracted real DEX from memory of Bangcle-protected app.

**Case 3: Handling Mixed Protection App**
An app using multiple layers of protection: Tencent protection on the outside, with custom encryption on internal DEX:
```
[12:34:56][INFO] (DUMPER) Tencent protection hook set up: com.tencent.StubShell.TxAppEntry
[12:35:05][DEBUG] (DUMPER) Tencent protection API call: com.tencent.StubShell.TxAppEntry.onCreate
[12:35:10][INFO] (DUMPER) Extracted DEX file: /sdcard/frida_dumps/classes_01.dex [Size: 12582912 bytes, from ClassLoader]
// Later, when internal DEX is dynamically loaded
[12:36:45][DEBUG] (DUMPER) ClassLoader created: memory buffer
[12:36:46][INFO] (DUMPER) Extracted DEX file: /sdcard/frida_dumps/classes_02.dex [Size: 6291456 bytes, from ClassLoader]
```
Successfully extracted DEX files with multi-layer protection.

#### Advanced Usage: Custom Unpacking Configuration

For special applications, you can create customized unpacking configurations:

```javascript
// Create custom_dumper.js
var customDumperConfig = {
    // Precisely target DEX files
    targetClassLoaders: [
        "dalvik.system.PathClassLoader",
        "dalvik.system.InMemoryDexClassLoader"
    ],
    
    // Custom memory search regions
    memoryRegions: [
        { start: "0x70000000", end: "0x80000000" }
    ],
    
    // Specific class loading events
    classLoadEvents: [
        { className: "com.example.security.DexLoader", methodName: "loadEncryptedDex" }
    ],
    
    // Specific class triggers extraction
    triggerClasses: [
        "com.example.app.MainActivity",
        "com.example.app.SplashActivity"
    ],
    
    // Delayed extraction configuration
    delayExtraction: 10000, // Delay extraction by 10 seconds
    
    // Focus on specific classes
    focusOnClasses: [
        "com.example.app.api", 
        "com.example.app.core"
    ]
};

// Load the module with custom configuration
var dexDumper = require('./modules/dex_dumper.js')(config, logger, utils);

// Apply custom configuration
Object.keys(customDumperConfig).forEach(key => {
    if (typeof dexDumper["set" + key.charAt(0).toUpperCase() + key.slice(1)] === "function") {
        dexDumper["set" + key.charAt(0).toUpperCase() + key.slice(1)](customDumperConfig[key]);
    }
});
```

## Backup Script Directory (backup/)

The backup directory contains split single-function script files that can be used individually as needed, without loading the entire framework.

### Hook Class Scripts

**File List**:
- **hook_java_method.js**: General Java method hook script
  - Function: Intercepts arbitrary Java method calls
  - Usage: `frida -U -f com.example.app -l backup/hook_java_method.js`
  
- **hook_native_function.js**: Native function hook script
  - Function: Intercepts calls to native library functions
  - Usage: `frida -U -f com.example.app -l backup/hook_native_function.js`
  
- **hook_constructor.js**: Constructor hook script
  - Function: Intercepts instance creation
  - Usage: `frida -U -f com.example.app -l backup/hook_constructor.js`

- **hook_all_methods.js**: Hook script for all methods of a class
  - Function: Monitors all method calls of a class
  - Usage: `frida -U -f com.example.app -l backup/hook_all_methods.js`

### Anti-Debug Related Scripts

**File List**:
- **hook_anti_debug.js**: Simplified anti-debug bypass
  - Function: Bypasses basic debugging detection
  - Usage: `frida -U -f com.example.app -l backup/hook_anti_debug.js`
  
- **bypass_ssl_pinning.js**: SSL certificate pinning bypass
  - Function: Bypasses common certificate pinning implementations
  - Usage: `frida -U -f com.example.app -l backup/bypass_ssl_pinning.js`

- **hook_ptrace.js**: ptrace anti-debug bypass
  - Function: Bypasses Native layer ptrace detection
  - Usage: `frida -U -f com.example.app -l backup/hook_ptrace.js`

- **hook_frida_detection.js**: Frida detection bypass
  - Function: Bypasses common Frida detection mechanisms
  - Usage: `frida -U -f com.example.app -l backup/hook_frida_detection.js`

- **hook_debug_detect_flags.js**: Anti-debugging detection bypass
  - Function: Bypasses FLAG_DEBUGGABLE etc. detection
  - Usage: `frida -U -f com.example.app -l backup/hook_debug_detect_flags.js`

### Information Extraction Scripts

**File List**:
- **dump_stack.js**: Stack trace script
  - Function: Prints the current execution stack
  - Usage: `frida -U -f com.example.app -l backup/dump_stack.js`
  
- **hook_okhttp_request.js**: OkHttp request extraction
  - Function: Monitors OkHttp network requests
  - Usage: `frida -U -f com.example.app -l backup/hook_okhttp_request.js`

- **hook_okhttp_response.js**: OkHttp response extraction
  - Function: Monitors OkHttp responses
  - Usage: `frida -U -f com.example.app -l backup/hook_okhttp_response.js`

- **hook_base64_decode.js**: Base64 decoding monitoring
  - Function: Monitors Base64 encoding/decoding operations
  - Usage: `frida -U -f com.example.app -l backup/hook_base64_decode.js`

- **hook_cipher.js**: Encryption algorithm monitoring
  - Function: Monitors Cipher encryption/decryption
  - Usage: `frida -U -f com.example.app -l backup/hook_cipher.js`

- **hook_message_digest.js**: Message digest monitoring
  - Function: Monitors hash calculation
  - Usage: `frida -U -f com.example.app -l backup/hook_message_digest.js`

### Other Utility Scripts

**File List**:
- **hook_system_exit.js**: Prevents application exit
  - Function: Intercepts System.exit calls
  - Usage: `frida -U -f com.example.app -l backup/hook_system_exit.js`

- **hook_build_model.js**: Modifies Build.MODEL return value
  - Function: Modifies Build.MODEL return value
  - Usage: `frida -U -f com.example.app -l backup/hook_build_model.js`
  
- **hook_webview_loadurl.js**: WebView URL monitoring
  - Function: Monitors WebView loaded URLs
  - Usage: `frida -U -f com.example.app -l backup/hook_webview_loadurl.js`

- **hook_sharedpreferences.js**: Application configuration monitoring
  - Function: Monitors reading and writing of SharedPreferences
  - Usage: `frida -U -f com.example.app -l backup/hook_sharedpreferences.js`

- **hook_network_proxy.js**: Network proxy configuration
  - Function: Modifies network proxy settings
  - Usage: `frida -U -f com.example.app -l backup/hook_network_proxy.js`

### New Addition: System Function Monitoring Module (system_api_monitor.js)

Monitors and records calls to common Java/Android system functions, including collection operations, string processing, logging, and UI interactions.

**File Path**: `modules/system_api_monitor.js`

#### Detailed Parameter Description

The system function monitoring module supports the following configuration parameters:

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `enableAllCategories` | Boolean | true | Whether to monitor all categories of system functions |
| `categoriesEnabled` | Object | {} | Enabled status for each category |
| `logParameters` | Boolean | true | Whether to log function call parameters |
| `logReturnValues` | Boolean | true | Whether to log function return values |
| `maxDataSize` | Integer | 1024 | Maximum bytes of data to log |
| `stackTraceDepth` | Integer | 3 | Stack trace recording depth |
| `customHooks` | Object[] | [] | Custom hook configurations |
| `excludeStackPatterns` | String[] | [] | Patterns to exclude specific stack sources |

#### Monitored System Function Categories

The module categorizes monitored system functions as follows:

1. **Collection Operations**
   - `java.util.HashMap`: All methods (put, get, remove, etc.)
   - `java.util.LinkedHashMap`: All methods
   - `java.util.ArrayList`: Main methods (add, addAll, set, remove, etc.)
   - `java.util.Collections`: Static methods (sort, shuffle, etc.)

2. **String Processing**
   - `android.text.TextUtils`: All static methods (isEmpty, equals, etc.)
   - `java.lang.String`: Main methods (getBytes, substring, split, etc.) and constructors
   - `java.lang.StringBuilder`: All methods (append, insert, toString, etc.)

3. **Encoding and Encryption**
   - `android.util.Base64`: Encoding/decoding methods (encode, decode)
   - `java.util.zip.GZIPOutputStream`: Compression
   - `java.util.zip.GZIPInputStream`: Decompression

4. **System Interactions**
   - `android.util.Log`: Log level methods (v, d, i, w, e)
   - `android.widget.Toast`: Display methods (show)
   - `android.os.Handler`: Message handling methods (sendMessage, post, etc.)

#### Parameter Configuration Methods

```javascript
// Manually load and configure the system function monitoring module
var sysMonitor = require('./modules/system_api_monitor.js')(config, logger, utils);

// Enable or disable specific categories
sysMonitor.enableCategory('COLLECTIONS', true);    // Enable collection operations monitoring
sysMonitor.enableCategory('STRING_PROCESSING', true);  // Enable string processing monitoring
sysMonitor.enableCategory('SYSTEM_INTERACTION', false);  // Disable system interaction monitoring

// Only enable specific categories, disable all others
sysMonitor.enableOnly(['COLLECTIONS', 'STRING_PROCESSING']);

// Add custom hook
sysMonitor.addCustomHook({
    className: "java.util.HashMap",
    methodName: "put",
    parameterLogging: true,
    returnValueLogging: true
});

// Adjust logging options
sysMonitor.setLogParameters(true);      // Log call parameters
sysMonitor.setLogReturnValues(true);    // Log return values

// Exclude specific stack sources
sysMonitor.addExcludeStackPattern("com.android.internal");
```

#### Best Usage Practices

**Scenario 1: General Monitoring**
```javascript
// Use default configuration to monitor all system functions
require('./modules/system_api_monitor.js')(config, logger, utils);
```

**Scenario 2: Data Flow Analysis**
```javascript
var sysMonitor = require('./modules/system_api_monitor.js')(config, logger, utils);

// Focus on data processing related functions
sysMonitor.enableOnly(['COLLECTIONS', 'STRING_PROCESSING', 'ENCODING']);

// Record complete data flow
sysMonitor.setMaxDataSize(4096);  // Increase data recording size
sysMonitor.setStackTraceDepth(5); // Increase call stack depth
```

**Scenario 3: Simplified Log Debugging**
```javascript
var sysMonitor = require('./modules/system_api_monitor.js')(config, logger, utils);

// Only monitor logs and Toast displays
sysMonitor.disableAllCategories();
sysMonitor.enableCategory('SYSTEM_INTERACTION', true);

// Add custom function filters
sysMonitor.setMethodFilter({
    'android.util.Log': ['e', 'w', 'i'],  // Only monitor these three log levels
    'android.widget.Toast': ['show']      // Only monitor Toast displays
});
```

#### Detailed List of Monitored System Functions

1. **Collection Functions**
   - `java.util.HashMap.put(Object key, Object value)`
   - `java.util.HashMap.get(Object key)`
   - `java.util.LinkedHashMap.put(Object key, Object value)`
   - `java.util.LinkedHashMap.get(Object key)`
   - `java.util.ArrayList.add(Object element)`
   - `java.util.ArrayList.addAll(Collection collection)`
   - `java.util.ArrayList.set(int index, Object element)`
   - `java.util.Collections.sort(List list)`
   - `java.util.Collections.shuffle(List list)`

2. **String Processing**
   - `java.lang.String.getBytes(String charsetName)`
   - `java.lang.String.substring(int beginIndex, int endIndex)`
   - `java.lang.String.matches(String regex)`
   - `java.lang.String.<init>(byte[] bytes, String charsetName)`
   - `java.lang.StringBuilder.append(Object obj)`
   - `java.lang.StringBuilder.toString()`
   - `android.text.TextUtils.isEmpty(CharSequence str)`
   - `android.text.TextUtils.equals(CharSequence a, CharSequence b)`

3. **Encoding Functions**
   - `android.util.Base64.encode(byte[] input, int flags)`
   - `android.util.Base64.decode(byte[] input, int flags)`
   - `android.util.Base64.encodeToString(byte[] input, int flags)`
   - `java.net.URLEncoder.encode(String s, String charset)`
   - `java.net.URLDecoder.decode(String s, String charset)`

4. **System Interaction**
   - `android.util.Log.v/d/i/w/e(String tag, String msg)`
   - `android.widget.Toast.makeText(Context context, CharSequence text, int duration)`
   - `android.widget.Toast.show()`
   - `android.os.Handler.sendMessage(Message msg)`
   - `android.os.Handler.post(Runnable r)`

#### Real-World Use Cases

Here are some practical use cases for the system function monitoring module:

**Case 1: Tracking Encryption Data Flow**
```javascript
// Load system functions and crypto modules
var sysMonitor = require('./modules/system_api_monitor.js')(config, logger, utils);
var cryptoModule = require('./modules/crypto_monitor.js')(config, logger, utils);

// Focus system functions on data processing and encoding
sysMonitor.enableOnly(['COLLECTIONS', 'STRING_PROCESSING', 'ENCODING']);
sysMonitor.setMaxDataSize(4096);  // Increase data recording size

// Focus crypto module on key algorithms
cryptoModule.setTargetAlgorithms(['AES', 'RSA']);

// Exclude system framework interference
sysMonitor.addExcludeStackPattern("com.google.gson");
sysMonitor.addExcludeStackPattern("com.alibaba.fastjson");
```

This scenario can clearly track the complete flow of data from creation to encoding and final encryption. Monitoring log example:

```
[12:34:56][INFO] (SYSTEM) Function call: HashMap.put
[12:34:56][INFO] (SYSTEM) Call location: com.example.app.DataManager.prepareData
[12:34:56][DEBUG] (SYSTEM) Parameters: {"key":"user_id","value":"12345"}

[12:34:56][INFO] (SYSTEM) Function call: String.getBytes
[12:34:56][INFO] (SYSTEM) Call location: com.example.app.DataManager.encodeData
[12:34:56][DEBUG] (SYSTEM) Parameters: {"charset":"UTF-8"}

[12:34:56][INFO] (SYSTEM) Function call: Base64.encodeToString
[12:34:56][INFO] (SYSTEM) Call location: com.example.app.DataManager.encodeData

[12:34:56][INFO] (CRYPTO) Encryption operation: javax.crypto.Cipher.doFinal
[12:34:56][INFO] (CRYPTO) Algorithm: AES/ECB/PKCS5Padding
[12:34:56][INFO] (CRYPTO) Key: A1B2C3D4E5F6G7H8...
```

**Case 2: Detecting Sensitive Information Leakage**
```javascript
// Load system functions and network monitoring modules
var sysMonitor = require('./modules/system_api_monitor.js')(config, logger, utils);
var networkModule = require('./modules/network_monitor.js')(config, logger, utils);

// Focus system functions on clipboard and UI interactions
sysMonitor.enableOnly(['SYSTEM_INTERACTION']);
sysMonitor.setMethodFilter({
  'android.content.ClipboardManager': ['setPrimaryClip', 'getPrimaryClip'],
  'android.widget.Toast': ['show'],
  'android.app.AlertDialog': ['show', 'setMessage']
});

// Focus network monitoring on data uploads
networkModule.setIncludeUrls(["upload", "log", "report", "collect"]);
```

This scenario can detect whether an application leaks sensitive information through system UI components or sends clipboard contents over the network.

**Case 3: Analyzing Obfuscated Code Functionality**
```javascript
// Load system function monitoring and auto extraction modules
var sysMonitor = require('./modules/system_api_monitor.js')(config, logger, utils);
var extractor = require('./modules/auto_extractor.js')(config, logger, utils);

// Monitor all system API categories
sysMonitor.enableCategory('COLLECTIONS', true);
sysMonitor.enableCategory('STRING_PROCESSING', true);
sysMonitor.enableCategory('ENCODING', true);
sysMonitor.enableCategory('SYSTEM_INTERACTION', true);

// Increase stack trace depth to understand code flow
sysMonitor.setStackTraceDepth(8);

// Track specific obfuscated classes
sysMonitor.addCustomHook({
    className: "com.example.app.a.b.c",  // Obfuscated class name
    methodName: "a",                     // Obfuscated method name
    parameterLogging: true,
    returnValueLogging: true
});
```

This scenario can help infer the actual functionality of obfuscated code by monitoring system API call patterns, particularly useful for reverse engineering analysis.

**Case 4: Analyzing String Processing and Encoding Chains**
```javascript
// Load system function monitoring module
var sysMonitor = require('./modules/system_api_monitor.js')(config, logger, utils);

// Focus only on string processing and encoding
sysMonitor.enableOnly(['STRING_PROCESSING', 'ENCODING']);

// Pay special attention to regex and encoding methods
sysMonitor.setMethodFilter({
    'java.lang.String': ['matches', 'replaceAll', 'split'],
    'java.util.regex.Pattern': ['compile', 'matcher'],
    'java.util.regex.Matcher': ['find', 'group'],
    'android.util.Base64': ['encode', 'decode', 'encodeToString'],
    'java.net.URLEncoder': ['encode'],
    'java.net.URLDecoder': ['decode']
});
```

This scenario can reveal the application's data processing flow, especially when it involves string transformations and multi-layer encoding. Monitoring log example:

```
[12:34:56][INFO] (SYSTEM) Function call: String.replaceAll
[12:34:56][INFO] (SYSTEM) Call location: com.example.app.StringProcessor.clean
[12:34:56][DEBUG] (SYSTEM) Parameters: {"regex":"[^a-zA-Z0-9]","replacement":""}
[12:34:56][DEBUG] (SYSTEM) Return value: "abc123XYZ"

[12:34:56][INFO] (SYSTEM) Function call: String.toLowerCase
[12:34:56][INFO] (SYSTEM) Call location: com.example.app.StringProcessor.normalize
[12:34:56][DEBUG] (SYSTEM) Return value: "abc123xyz"

[12:34:56][INFO] (SYSTEM) Function call: URLEncoder.encode
[12:34:56][INFO] (SYSTEM) Call location: com.example.app.StringProcessor.prepare
[12:34:56][DEBUG] (SYSTEM) Parameters: {"s":"abc123xyz","charset":"UTF-8"}
[12:34:56][DEBUG] (SYSTEM) Return value: "abc123xyz"
```

These real-world use cases demonstrate the various applications of the system function monitoring module, from data flow analysis to security inspection to reverse engineering assistance, providing comprehensive monitoring capabilities.

## Example Script: examples/usage_example.js

Example script demonstrates how to use this framework for specific application scenarios.

### Example Features

- Monitors all encryption-related methods of a specific class
- Filters network requests to specific domains
- Extracts keys from SharedPreferences
- Bypasses specific signature checks
- Extracts JWT tokens and parses their content

### Usage

```bash
# Run the example script directly
frida -U -f com.example.app -l examples/usage_example.js --no-pause
```

### Example Code Snippet

**Monitors all encryption methods of a specific class**:
```javascript
Java.perform(function() {
    try {
        // Monitor custom encryption utility class
        var CustomEncryptionUtil = Java.use("com.example.app.security.CustomEncryptionUtil");
        
        // Get all methods
        var methods = CustomEncryptionUtil.class.getDeclaredMethods();
        methods.forEach(function(method) {
            var methodName = method.getName();
            
            // Filter encryption-related methods
            if (methodName.indexOf("encrypt") !== -1 || 
                methodName.indexOf("decrypt") !== -1 || 
                methodName.indexOf("hash") !== -1) {
                
                // Monitor all overloads
                CustomEncryptionUtil[methodName].overloads.forEach(function(overload) {
                    overload.implementation = function() {
                        console.log("[*] Invoking " + methodName);
                        
                        // Print parameters
                        for (var i = 0; i < arguments.length; i++) {
                            console.log("    参数" + i + ": " + arguments[i]);
                        }
                        
                        // Call original method
                        var ret = this[methodName].apply(this, arguments);
                        
                        // Print return value
                        console.log("    返回: " + ret);
                        return ret;
                    };
                });
            }
        });
    } catch (e) {
        console.log("[-] 监控失败: " + e);
    }
});
```

**Extracts JWT tokens**:
```javascript
// Find JWT token in requests
var patterns = [
    /Bearer\s+([A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)/,  // Authorization header
    /"token"\s*:\s*"([A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)"/  // token field in JSON
];

// Hook OkHttp's request builder
var Request$Builder = Java.use("okhttp3.Request$Builder");
Request$Builder.build.implementation = function() {
    var request = this.build();
    var headers = request.headers();
    
    // Check Authorization header
    var authHeader = headers.get("Authorization");
    if (authHeader) {
        for (var i = 0; i < patterns.length; i++) {
            var matches = patterns[i].exec(authHeader);
            if (matches && matches.length > 1) {
                console.log("[*] 发现JWT Token: " + matches[1]);
                
                // Decode JWT parts
                var parts = matches[1].split(".");
                if (parts.length === 3) {
                    try {
                        var header = JSON.parse(decodeJWT(parts[0]));
                        var payload = JSON.parse(decodeJWT(parts[1]));
                        console.log("    头部: " + JSON.stringify(header));
                        console.log("    负载: " + JSON.stringify(payload));
                    } catch (e) {
                        console.log("    JWT解析错误: " + e);
                    }
                }
            }
        }
    }
    
    return request;
};
```

## Advanced Usage

### Custom Log Level

Modify the configuration in `frida_master.js`:

```javascript
var config = {
    logLevel: 'debug',  // Changed to 'debug' for more detailed information
    // Other configurations...
};
```

### Disable Specific Modules

If only certain features are needed, modules can be commented out in the `loadModules()` function in `frida_master.js`:

```javascript
function loadModules() {
    // Load crypto module
    require('./modules/crypto_monitor.js')(config, logger, utils);
    
    // Load network module
    require('./modules/network_monitor.js')(config, logger, utils);
    
    // Comment out unnecessary modules
    // require('./modules/anti_debug.js')(config, logger, utils);
    // require('./modules/sensitive_api.js')(config, logger, utils);
    // require('./modules/auto_extractor.js')(config, logger, utils);
}
```

### Custom Filters

Various filters can be configured to reduce log output and focus on specific content:

```javascript
// Add network filter
var networkModule = require('./modules/network_monitor.js')(config, logger, utils);
networkModule.addUrlFilter("api.example.com");
networkModule.addContentTypeFilter("application/json");

// Add crypto filter
var cryptoModule = require('./modules/crypto_monitor.js')(config, logger, utils);
cryptoModule.setAlgorithmFilter(["AES", "RSA"]); // Only monitor these algorithms
```

### Save Console Output

You can save Frida's output to a file:

```bash
frida -U -f com.example.app -l frida_master.js --no-pause > frida_output.txt
```

### Combining with Other Tools

You can use extracted data with other tools:

```bash
# Pull extracted keys from device to computer
adb pull /sdcard/frida_extracted_keys.json

# Pull log file from device to computer
adb pull /sdcard/frida_log.txt
```

## Common Questions and Answers

### Q: What if the application crashes?

Some applications may be sensitive to Hooks, so you can try:
1. Disable anti-debug bypass: Set `bypassAllDetection: false` in config
   ```javascript
   var config = {
       bypassAllDetection: false,  // Disable all bypass features
       // Other configurations...
   };
   ```
2. Reduce the number of Hooks: Only load necessary modules
3. Use -f forced startup mode (non-attach mode)

### Q: How to filter out a large amount of log output?

1. Adjust log level:
   ```javascript
   var config = {
       logLevel: 'warn',  // Only show warnings and errors
       // Other configurations...
   };
   ```
2. Use grep to filter:
   ```bash
   frida -U -f com.example.app -l frida_master.js --no-pause | grep CRYPTO
   ```

### Q: Why are some encryption operations not captured?

Possible reasons:
1. The application uses Native layer encryption, which can be hooked using `hook_native_function.js` in the backup directory
2. The application uses custom encryption libraries, requiring specific hooks
3. The application uses code obfuscation, class names and method names may change

### Q: How to extend the framework functionality?

Create new module files, following the same structure:
```javascript
module.exports = function(config, logger, utils) {
    var tag = "MY_MODULE";
    logger.info(tag, "模块初始化");
    
    // Implement functionality...
    
    return {
        // Export APIs...
    };
};
```

Then load it in `frida_master.js`'s `loadModules()` function.

## License

This project is licensed under the MIT License.

---

**Disclaimer**: This framework is only for security research and authorized testing purposes. Please ensure you have legal permission to test the target application. For any misuse, the author is not responsible. 

## Module Startup and Usage Guide

This framework supports multiple usage methods, including full framework startup and individual module startup. Below are detailed instructions for various startup and usage methods.

### Basic Command Format

```bash
# Inject into a newly launched application
frida -U -f com.example.app -l script_file_path --no-pause

# Attach to a running application
frida -U -n "Application Name" -l script_file_path
```

### Full Framework Startup Method

```bash
# Inject into a newly launched application, start the full-featured framework
frida -U -f com.example.app -l frida_master.js --no-pause

# Attach to a running application, start the full-featured framework
frida -U -n "Application Name" -l frida_master.js
```

### Individual Module Startup Methods

#### 1. Crypto Monitoring Module

```bash
# Create a temporary JS file, e.g., run_crypto.js
echo 'Java.perform(function() { require("./modules/crypto_monitor.js")({logLevel: "info"}, console, null); });' > run_crypto.js

# Use this file to start Frida
frida -U -f com.example.app -l run_crypto.js --no-pause
```

**Or create a single module startup file with the following content:**

```javascript
// crypto_starter.js
Java.perform(function() {
    // Create basic logger
    var logger = {
        debug: function(tag, message) { console.log(`[DEBUG][${tag}] ${message}`); },
        info: function(tag, message) { console.log(`[INFO][${tag}] ${message}`); },
        warn: function(tag, message) { console.log(`[WARN][${tag}] ${message}`); },
        error: function(tag, message) { console.log(`[ERROR][${tag}] ${message}`); }
    };
    
    // Create basic utils
    var utils = {
        hexdump: function(array) {
            return hexdump(array);
        },
        bytesToString: function(bytes) {
            return String.fromCharCode.apply(null, bytes);
        }
    };
    
    // Configuration
    var config = {
        logLevel: 'info',
        fileLogging: false,
        autoExtractKeys: true
    };
    
    // Load crypto monitoring module
    var cryptoModule = require('./modules/crypto_monitor.js')(config, logger, utils);
    
    console.log("[+] Crypto monitoring module started");
});

// Trigger loading
setTimeout(function() {
    console.log("[*] Preparing to start crypto monitoring...");
    Java.perform(function() {});
}, 100);
```

Then use this file to start:
```bash
frida -U -f com.example.app -l crypto_starter.js --no-pause
```

#### 2. Network Monitoring Module

```javascript
// network_starter.js
Java.perform(function() {
    // Create basic logger and utils (same as above)
    
    // Configuration
    var config = {
        logLevel: 'info',
        fileLogging: false
    };
    
    // Load network monitoring module
    var networkModule = require('./modules/network_monitor.js')(config, logger, utils);
    
    // Optional: Set URL filter to monitor specific domains only
    networkModule.addUrlFilter("api.example.com");
    
    console.log("[+] Network monitoring module started");
});

// Trigger loading
setTimeout(function() {
    Java.perform(function() {});
}, 100);
```

Startup command:
```bash
frida -U -f com.example.app -l network_starter.js --no-pause
```

#### 3. Anti-Debug Bypass Module

```javascript
// antidebug_starter.js
Java.perform(function() {
    // Create basic logger and utils (same as above)
    
    // Configuration
    var config = {
        logLevel: 'info',
        fileLogging: false,
        bypassAllDetection: true
    };
    
    // Load anti-debug bypass module
    var antiDebugModule = require('./modules/anti_debug.js')(config, logger, utils);
    
    console.log("[+] Anti-debug bypass module started");
});

// Trigger loading
setTimeout(function() {
    Java.perform(function() {});
}, 100);
```

Startup command:
```bash
frida -U -f com.example.app -l antidebug_starter.js --no-pause
```

#### 4. Sensitive API Monitoring Module

```javascript
// sensitive_api_starter.js
Java.perform(function() {
    // Create basic logger and utils (same as above)
    
    // Configuration
    var config = {
        logLevel: 'info',
        fileLogging: false
    };
    
    // Load sensitive API monitoring module
    var sensitiveApiModule = require('./modules/sensitive_api.js')(config, logger, utils);
    
    // Optional: Add custom sensitive API
    sensitiveApiModule.addCustomApi("com.example.app.UserManager", "getUserData");
    
    console.log("[+] Sensitive API monitoring module started");
});

// Trigger loading
setTimeout(function() {
    Java.perform(function() {});
}, 100);
```

Startup command:
```bash
frida -U -f com.example.app -l sensitive_api_starter.js --no-pause
```

#### 5. Automatic Key Extraction Module

```javascript
// extractor_starter.js
Java.perform(function() {
    // Create basic logger and utils (same as above)
    
    // Configuration
    var config = {
        logLevel: 'info',
        fileLogging: true,
        autoExtractKeys: true
    };
    
    // Load automatic key extraction module
    var extractorModule = require('./modules/auto_extractor.js')(config, logger, utils);
    
    // Optional: Set key extraction callback
    extractorModule.addKeyExtractedCallback(function(keyInfo) {
        console.log(`[*] New key extracted: ${keyInfo.type} - ${keyInfo.value}`);
    });
    
    console.log("[+] Automatic key extraction module started");
});

// Trigger loading
setTimeout(function() {
    Java.perform(function() {});
}, 100);
```

Startup command:
```bash
frida -U -f com.example.app -l extractor_starter.js --no-pause
```

#### 6. DEX Dumper Module

```javascript
// dex_dumper_starter.js
Java.perform(function() {
    // Create basic logger and utils (same as above)
    
    // Configuration
    var config = {
        logLevel: 'info',
        fileLogging: true
    };
    
    // Load DEX dumper module
    var dexDumper = require('./modules/dex_dumper.js')(config, logger, utils);
    
    // Optional: Set output directory
    dexDumper.setOutputDirectory('/sdcard/frida_dex_dumps/');
    
    // Optional: Set DEX size limits
    dexDumper.setDexSizeLimit(4096, 50 * 1024 * 1024);
    
    // Show statistics after 30 seconds
    setTimeout(function() {
        dexDumper.showStats();
    }, 30000);
    
    console.log("[+] DEX dumper module started");
});

// Trigger loading
setTimeout(function() {
    Java.perform(function() {});
}, 100);
```

Startup command:
```bash
frida -U -f com.example.app -l dex_dumper_starter.js --no-pause
```

### Using Example Scripts

The framework provides several pre-configured examples in the `examples/` directory:

#### DEX Dumper Example (English Version)

```bash
# Run the pre-configured DEX dumper example
frida -U -f com.example.app -l examples/dex_dumper_guide_en.js --no-pause
```

Different unpacking methods for various scenarios (uncomment the corresponding function in the script):
- `basicUnpacking()`: Basic unpacking functionality
- `memoryOptimizedUnpacking()`: Memory-optimized version, suitable for low-memory devices
- `huaweiHmsUnpacking()`: Optimized for Huawei HMS applications
- `bytedanceUnpacking()`: Optimized for ByteDance applications
- `advancedUnpacking()`: Advanced unpacking, combined with anti-debug bypass

#### DEX Dumper Example (Chinese Version)

```bash
# Run the Chinese version of the DEX dumper example
frida -U -f com.example.app -l examples/dex_dumper_guide.js --no-pause
```

### Generic Startup File Creation Method

If you need to create a custom startup file, you can refer to the following generic template:

```javascript
// custom_starter.js
Java.perform(function() {
    // Create logger
    var logger = {
        debug: function(tag, message) { console.log(`[DEBUG][${tag}] ${message}`); },
        info: function(tag, message) { console.log(`[INFO][${tag}] ${message}`); },
        warn: function(tag, message) { console.log(`[WARN][${tag}] ${message}`); },
        error: function(tag, message) { console.log(`[ERROR][${tag}] ${message}`); }
    };
    
    // Create utility functions
    var utils = {
        hexdump: function(array) {
            return hexdump(array);
        },
        bytesToString: function(bytes) {
            return String.fromCharCode.apply(null, bytes);
        },
        stringToBytes: function(str) {
            var bytes = [];
            for (var i = 0; i < str.length; i++) {
                bytes.push(str.charCodeAt(i));
            }
            return bytes;
        },
        getStackTrace: function() {
            return Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join('\n');
        }
    };
    
    // Basic configuration
    var config = {
        logLevel: 'info',
        fileLogging: false
    };
    
    // Load required modules
    // Uncomment the modules you want to start
    //require('./modules/crypto_monitor.js')(config, logger, utils);
    //require('./modules/network_monitor.js')(config, logger, utils);
    //require('./modules/anti_debug.js')(config, logger, utils);
    //require('./modules/sensitive_api.js')(config, logger, utils);
    //require('./modules/auto_extractor.js')(config, logger, utils);
    //require('./modules/dex_dumper.js')(config, logger, utils);
    
    console.log("[+] Custom module combination started");
});

// Trigger loading
setTimeout(function() {
    Java.perform(function() {});
}, 100);
```

After creation, use the following command to start:
```bash
frida -U -f com.example.app -l custom_starter.js --no-pause
```

### Command-Line Parameter Description

Commonly used Frida command-line parameters:

- `-U`: Connect to USB device
- `-f package_name`: Specify the package name of the application to launch
- `-n "Application Name"`: Connect to a running process by application name
- `-p Process ID`: Connect to a running process by process ID
- `-l script_path`: Specify the JavaScript script file to inject
- `--no-pause`: Run the application immediately after injection without pausing
- `-o output_file`: Save console output to a file
- `--runtime=v8`: Use the V8 JavaScript engine (recommended)
- `--debug`: Enable debug output

### Advanced Usage Tips

1. **Silent Logging**: Redirect output to a file
```bash
frida -U -f com.example.app -l frida_master.js --no-pause > log.txt 2>&1
```

2. **Persistent Connection**: Use the -R parameter to reattach after application restart
```bash
frida -U -f com.example.app -l frida_master.js --no-pause -R
```

3. **Remote Debugging**: Connect to a device over the network
```bash
# Run frida-server on the device
adb shell "/data/local/tmp/frida-server &"

# Connect from your computer
frida -H device_IP_address -f com.example.app -l frida_master.js --no-pause
```

4. **Combining Multiple Scripts**: Load multiple scripts simultaneously
```bash
frida -U -f com.example.app -l script1.js -l script2.js --no-pause
```