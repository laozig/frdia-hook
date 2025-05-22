# Frida全功能Hook框架

[English](README.md) | [简体中文](README-CN.md)

一个功能强大、模块化的Frida脚本框架，用于Android应用分析、渗透测试和安全研究。框架提供全面的功能，包括加密监控、网络监控、反调试绕过、敏感API监控和自动提取密钥。

## 目录结构

```
frdia/
│
├── frida_master.js          # 主入口文件，配置和加载所有模块
├── frida_master.js.bak      # 主文件备份
│
├── modules/                 # 功能模块目录
│   ├── crypto_monitor.js    # 加密监控模块
│   ├── network_monitor.js   # 网络监控模块
│   ├── anti_debug.js        # 反调试绕过模块
│   ├── sensitive_api.js     # 敏感API监控模块
│   ├── auto_extractor.js    # 自动提取密钥模块
│   ├── system_api_monitor.js # 系统函数监控模块
│   └── dex_dumper.js        # DEX脱壳模块
│
├── examples/                # 示例代码目录
│   └── usage_example.js     # 使用示例脚本
│
└── backup/                  # 备份脚本目录(单功能脚本)
    ├── hook_java_method.js  # Java方法Hook脚本
    ├── hook_native_function.js # 原生函数Hook脚本
    ├── bypass_ssl_pinning.js # SSL证书固定绕过
    ├── dump_stack.js        # 堆栈跟踪脚本
    └── ...                  # 其他单一功能脚本
```

## 环境要求

- Frida >= 15.0.0
- Android设备(真机或模拟器)
- Python 3.x (如使用Frida-tools)

## 快速开始

### 基本使用方法

1. 将代码克隆到本地：

```bash
git clone https://github.com/yourusername/frdia.git
cd frdia
```

2. 使用Frida注入脚本：

```bash
# 指定包名注入(推荐)
frida -U -f com.example.app -l frida_master.js --no-pause

# 或附加到已运行的进程
frida -U -n "应用名称" -l frida_master.js

# 使用进程ID附加
frida -U -p <PID> -l frida_master.js
```

### 日志输出

- 控制台实时输出监控信息
- 日志文件保存在：`/sdcard/frida_log.txt`
- 提取的密钥保存在：`/sdcard/frida_extracted_keys.json`

## 主框架文件：frida_master.js

主入口文件负责配置框架和加载各功能模块。

### 配置参数

在`frida_master.js`中，可以修改以下配置：

```javascript
var config = {
    logLevel: 'info',           // 日志级别: debug, info, warn, error
    fileLogging: true,          // 是否保存日志到文件
    logFilePath: '/sdcard/frida_log.txt',  // 日志文件路径
    autoExtractKeys: true,      // 自动提取加密密钥
    bypassAllDetection: true,   // 绕过所有检测机制
    colorOutput: true,          // 控制台彩色输出
    stackTrace: false           // 打印调用栈
};
```

### 主要功能

- **日志系统**：提供四个日志级别(debug, info, warn, error)和彩色输出
- **工具函数**：提供hex转储、字节数组转换等实用功能 
- **模块加载**：按需加载各功能模块
- **环境检查**：检查运行环境并创建日志文件

### 日志系统

框架提供四个日志级别：
- **debug**: 最详细的调试信息
- **info**: 一般信息(默认)
- **warn**: 警告信息
- **error**: 错误信息

示例：
```javascript
logger.debug("TAG", "调试信息");
logger.info("TAG", "一般信息");
logger.warn("TAG", "警告信息");
logger.error("TAG", "错误信息");
```

### 工具函数

主框架提供了常用工具函数：
- `utils.hexdump()`: 生成二进制数据的十六进制表示
- `utils.bytesToString()`: 字节数组转字符串
- `utils.stringToBytes()`: 字符串转字节数组
- `utils.getStackTrace()`: 获取当前调用栈

## 功能模块详细说明

### 1. 加密监控模块：modules/crypto_monitor.js

#### 功能概述

监控和记录常见加密算法的使用，自动提取密钥、IV、明文、密文。

#### 详细参数说明

加密监控模块支持以下参数配置，可在加载模块时通过API传入：

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `enableKeyExtraction` | Boolean | true | Whether to extract encryption keys |
| `logPlaintext` | Boolean | true | Whether to log plaintext data |
| `logCiphertext` | Boolean | true | Whether to log ciphertext data |
| `maxDataSize` | Integer | 1024 | Maximum bytes of data to log |
| `algorithmFilter` | String[] | [] | Only monitor specified algorithms, empty array means monitor all |

#### 参数配置方法

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

#### 支持的加密API

- **Java加密标准库**：
  - `javax.crypto.Cipher` (AES/DES等对称加密)
  - `java.security.MessageDigest` (MD5/SHA等哈希算法)
  - `android.util.Base64` (Base64编解码)
  - RSA密钥生成和加解密

- **第三方加密库**：
  - BouncyCastle
  - Apache Commons Codec

#### 最佳使用方法

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

#### 查看监控结果

所有加密操作会在控制台和日志文件中显示，格式如下：

```
[12:34:56][INFO] (CRYPTO) ====== 发现加密密钥 ======
[12:34:56][INFO] (CRYPTO) 算法: AES
[12:34:56][INFO] (CRYPTO) 密钥: [字节数组]
[12:34:56][INFO] (CRYPTO) 密钥(HEX): A1B2C3D4E5F6...
[12:34:56][INFO] (CRYPTO) 密钥(B64): a1b2c3d4e5f6...
[12:34:56][INFO] (CRYPTO) IV: [字节数组]
[12:34:56][INFO] (CRYPTO) IV(HEX): 0102030405060708...
[12:34:56][INFO] (CRYPTO) IV(B64): AAECAwQFBgcICQ==
[12:34:56][INFO] (CRYPTO) 明文样本: 需要加密的数据
[12:34:56][INFO] (CRYPTO) 密文样本: [加密后数据]
[12:34:56][INFO] (CRYPTO) ==========================
```

#### 优点与局限性

**优点：**
- Comprehensive monitoring of all encryption/decryption operations
- Automatic extraction of keys, IVs and sensitive information
- Support for mainstream encryption libraries and custom implementations
- Highly configurable, can adjust monitoring granularity as needed
- Real-time view of encryption parameters without reverse engineering

**局限性：**
- Cannot directly monitor Native layer encryption (needs to be combined with native_function.js)
- Heavy monitoring may impact application performance
- May capture incomplete keys for rapidly changing memory keys
- Some heavily obfuscated code might require manual adjustment of hook points
- Large volume of encryption operations will generate significant logs

### 2. 反调试绕过模块：modules/anti_debug.js

#### 功能概述

自动绕过各种反调试、反Root、反模拟器、反注入、反抓包等检测机制。

#### 详细参数说明

反调试绕过模块支持以下参数配置，可在加载模块时通过API设置：

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

#### 参数配置方法

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

#### 绕过检测类型

- **Java层反调试绕过**：
  - `Debug.isDebuggerConnected()`
  - `ApplicationInfo.FLAG_DEBUGGABLE`
  - `System.exit()` 阻止应用强制退出
  - `Process.killProcess()` 阻止进程终止

- **Root检测绕过**：
  - 敏感文件检测(`/system/bin/su`等)
  - Runtime.exec("su")检测
  - Shell.exec检测

- **模拟器检测绕过**：
  - Build属性检测(修改BRAND,MODEL等)
  - TelephonyManager相关检测(IMEI等)
  - 传感器检测

- **Frida/Xposed检测绕过**：
  - 关键字符串检测
  - 敏感文件检测
  - /proc/self/maps检测
  - 反射调用检测

- **SSL Pinning绕过**：
  - X509TrustManager绕过
  - OkHttp证书固定绕过
  - TrustManagerImpl绕过

- **签名校验绕过**：
  - PackageManager.getPackageInfo绕过
  - Signature.equals绕过

- **Native层检测绕过**：
  - ptrace反调试绕过
  - /proc/maps检测绕过
  - 原生层Root检测绕过

#### 最佳使用方法

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

#### 优点与局限性

**优点：**
- Comprehensive coverage of common Android anti-debugging/anti-root/anti-emulator detection mechanisms
- Modular design, can enable/disable specific bypass features as needed
- Automatically handles Native and Java layer detections
- Supports device info spoofing to hide real environment characteristics
- Built-in SSL certificate pinning bypass
- Can dynamically add custom bypass rules for specific applications
- Records bypassed detection points for protection mechanism analysis

**局限性：**
- May require additional configuration for highly customized protection schemes
- Some advanced anti-debugging techniques may require Native modules
- Bypassing many detection points could cause performance degradation
- May not bypass hardware-based detections (like SafetyNet attestation)
- Not suitable for apps with custom VM protection
- Excessive bypassing may cause application functionality issues in extreme cases
- Latest anti-debugging techniques may require module updates

### 3. 网络监控模块：modules/network_monitor.js

#### 功能概述

监控和记录HTTP/HTTPS请求和响应，WebSocket通信，Socket通信等网络活动。

#### 详细参数说明

网络监控模块支持以下参数配置，可在加载模块时通过API设置：

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

#### 参数配置方法

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

#### 支持的网络API

- **HTTP客户端**：
  - OkHttp3
  - HttpURLConnection
  - Volley

- **Web组件**：
  - WebView
  - WebSocket

- **底层通信**：
  - Socket

#### 最佳使用方法

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

#### 优点与局限性

**优点：**
- Comprehensive monitoring of all application network communications, including HTTPS encrypted traffic
- Rich filtering functionality, can customize monitoring for specific needs
- Automatically extracts and parses common authentication tokens (such as JWT)
- Supports mainstream HTTP client libraries and WebSocket implementations
- Can simultaneously monitor multiple types of network communication in the application
- Automatically bypasses SSL certificate pinning without additional configuration

**局限性：**
- Large numbers of network requests will generate large logs, potentially affecting performance
- Complex binary protocols require additional parsers to understand content
- Some highly customized network libraries may require additional hook points
- Cannot directly monitor Native layer network requests (needs to be combined with native_function.js)
- May not support some non-standard WebSocket implementations or custom protocols
- Monitoring all response bodies may increase memory usage

### 4. 敏感API监控模块：modules/sensitive_api.js

#### 功能概述

监控应用对敏感API的调用，如文件访问、剪贴板操作、定位服务、相机等。

#### 详细参数说明

敏感API监控模块支持以下参数配置：

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

#### 支持的API类别

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

#### 参数配置方法

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

#### 最佳使用方法

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

#### 优点与局限性

**优点：**
- Comprehensive coverage of Android sensitive APIs, clearly categorized for auditing
- Modular design, can enable/disable specific categories as needed
- Supports logging parameters and return values for in-depth analysis
- Can log call stack to track call origins
- Flexible filtering mechanisms for focusing on specific file types or URIs
- Can dynamically add custom monitoring points for specific applications
- Low-overhead configuration options suitable for long-term monitoring

**局限性：**
- Monitoring many APIs will generate large logs, potentially affecting performance
- Some sensitive APIs may be implemented at the Native layer, requiring native_function.js
- For highly obfuscated apps, may need manual adjustment of class/method names
- Cannot monitor APIs called via reflection (unless specially handled)
- Excessive parameter and return value logging may increase memory usage
- Some API parameters or return values may be too complex for direct logging
- Some system-level APIs may differ between Android versions, requiring adaptation

### 5. 自动提取密钥模块：modules/auto_extractor.js

#### 功能概述

自动识别、提取和保存应用中的加密密钥、令牌、API密钥和配置信息。

#### 详细参数说明

自动提取密钥模块支持以下参数配置：

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

#### 提取源

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

#### 参数配置方法

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

#### 密钥识别规则

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

#### 最佳使用方法

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

#### 优点与局限性

**优点：**
- Fully automatic extraction of various keys and sensitive information from applications
- Comprehensive analysis from multiple sources increases detection rate
- Intelligent identification of common key formats and characteristics
- Supports custom extraction rules and patterns
- Structured storage of extraction results for subsequent analysis
- Automatic deduplication and classification improves extraction quality
- Can view extraction progress in real-time without waiting for application completion

**局限性：**
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

## 备份脚本目录 (backup/)

备份目录包含了拆分的单一功能脚本文件，可以根据需要单独使用，无需加载整个框架。

### Hook类脚本

**文件列表**:
- **hook_java_method.js**: 通用Java方法Hook脚本
  - 功能: 拦截任意Java方法调用
  - 用法: `frida -U -f com.example.app -l backup/hook_java_method.js`
  
- **hook_native_function.js**: 原生函数Hook脚本
  - 功能: 拦截原生库函数调用
  - 用法: `frida -U -f com.example.app -l backup/hook_native_function.js`
  
- **hook_constructor.js**: 构造函数Hook脚本
  - 功能: 拦截类的实例化
  - 用法: `frida -U -f com.example.app -l backup/hook_constructor.js`

- **hook_all_methods.js**: 类所有方法Hook脚本
  - 功能: 监控类的所有方法调用
  - 用法: `frida -U -f com.example.app -l backup/hook_all_methods.js`

### 反调试相关脚本

**文件列表**:
- **hook_anti_debug.js**: 简化版反调试绕过
  - 功能: 绕过基本的调试检测
  - 用法: `frida -U -f com.example.app -l backup/hook_anti_debug.js`
  
- **bypass_ssl_pinning.js**: SSL证书固定绕过
  - 功能: 绕过常见的证书固定实现
  - 用法: `frida -U -f com.example.app -l backup/bypass_ssl_pinning.js`

- **hook_ptrace.js**: ptrace反调试绕过
  - 功能: 绕过Native层ptrace检测
  - 用法: `frida -U -f com.example.app -l backup/hook_ptrace.js`

- **hook_frida_detection.js**: Frida检测绕过
  - 功能: 绕过常见的Frida检测机制
  - 用法: `frida -U -f com.example.app -l backup/hook_frida_detection.js`

- **hook_debug_detect_flags.js**: 调试标记检测绕过
  - 功能: 绕过FLAG_DEBUGGABLE等检测
  - 用法: `frida -U -f com.example.app -l backup/hook_debug_detect_flags.js`

### 信息提取脚本

**文件列表**:
- **dump_stack.js**: 堆栈跟踪脚本
  - 功能: 打印当前执行堆栈
  - 用法: `frida -U -f com.example.app -l backup/dump_stack.js`
  
- **hook_okhttp_request.js**: OkHttp请求提取
  - 功能: 监控OkHttp网络请求
  - 用法: `frida -U -f com.example.app -l backup/hook_okhttp_request.js`

- **hook_okhttp_response.js**: OkHttp响应提取
  - 功能: 监控OkHttp响应
  - 用法: `frida -U -f com.example.app -l backup/hook_okhttp_response.js`

- **hook_base64_decode.js**: Base64解码监控
  - 功能: 监控Base64编解码操作
  - 用法: `frida -U -f com.example.app -l backup/hook_base64_decode.js`

- **hook_cipher.js**: 加密算法监控
  - 功能: 监控Cipher加密解密
  - 用法: `frida -U -f com.example.app -l backup/hook_cipher.js`

- **hook_message_digest.js**: 消息摘要监控
  - 功能: 监控哈希计算
  - 用法: `frida -U -f com.example.app -l backup/hook_message_digest.js`

### 其他实用脚本

**文件列表**:
- **hook_system_exit.js**: 阻止应用退出
  - 功能: 拦截System.exit调用
  - 用法: `frida -U -f com.example.app -l backup/hook_system_exit.js`

- **hook_build_model.js**: 修改设备型号
  - 功能: 修改Build.MODEL返回值
  - 用法: `frida -U -f com.example.app -l backup/hook_build_model.js`
  
- **hook_webview_loadurl.js**: WebView URL监控
  - 功能: 监控WebView加载的URL
  - 用法: `frida -U -f com.example.app -l backup/hook_webview_loadurl.js`

- **hook_sharedpreferences.js**: 应用配置监控
  - 功能: 监控SharedPreferences读写
  - 用法: `frida -U -f com.example.app -l backup/hook_sharedpreferences.js`

- **hook_network_proxy.js**: 网络代理配置
  - 功能: 修改网络代理设置
  - 用法: `frida -U -f com.example.app -l backup/hook_network_proxy.js`

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

## 示例脚本: examples/usage_example.js

示例脚本演示如何针对特定应用场景使用本框架。

### 示例功能

- 监控特定类的所有加密相关方法
- 过滤特定域名的网络请求
- 提取SharedPreferences中的密钥
- 绕过特定的签名检测
- 提取JWT令牌并解析内容

### 使用方法

```bash
# 直接运行示例脚本
frida -U -f com.example.app -l examples/usage_example.js --no-pause
```

### 示例代码片段

**监控特定类的所有加密方法**:
```javascript
Java.perform(function() {
    try {
        // 监控自定义加密工具类
        var CustomEncryptionUtil = Java.use("com.example.app.security.CustomEncryptionUtil");
        
        // 获取所有方法
        var methods = CustomEncryptionUtil.class.getDeclaredMethods();
        methods.forEach(function(method) {
            var methodName = method.getName();
            
            // 过滤加密相关方法
            if (methodName.indexOf("encrypt") !== -1 || 
                methodName.indexOf("decrypt") !== -1 || 
                methodName.indexOf("hash") !== -1) {
                
                // 监控所有重载
                CustomEncryptionUtil[methodName].overloads.forEach(function(overload) {
                    overload.implementation = function() {
                        console.log("[*] 调用 " + methodName);
                        
                        // 打印参数
                        for (var i = 0; i < arguments.length; i++) {
                            console.log("    参数" + i + ": " + arguments[i]);
                        }
                        
                        // 调用原方法
                        var ret = this[methodName].apply(this, arguments);
                        
                        // 打印返回值
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

**提取JWT令牌**:
```javascript
// 查找请求中的JWT Token
var patterns = [
    /Bearer\s+([A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)/,  // Authorization 头
    /"token"\s*:\s*"([A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)"/  // JSON中的token字段
];

// Hook OkHttp的请求构建
var Request$Builder = Java.use("okhttp3.Request$Builder");
Request$Builder.build.implementation = function() {
    var request = this.build();
    var headers = request.headers();
    
    // 检查Authorization头
    var authHeader = headers.get("Authorization");
    if (authHeader) {
        for (var i = 0; i < patterns.length; i++) {
            var matches = patterns[i].exec(authHeader);
            if (matches && matches.length > 1) {
                console.log("[*] 发现JWT Token: " + matches[1]);
                
                // 解码JWT的各部分
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

## 高级使用方法

### 自定义日志级别

修改`frida_master.js`中的配置：

```javascript
var config = {
    logLevel: 'debug',  // 改为'debug'以显示更详细的信息
    // 其他配置...
};
```

### 禁用特定模块

如果只需要某些功能，可以在`frida_master.js`中的`loadModules()`函数中注释掉不需要的模块：

```javascript
function loadModules() {
    // 加载加密模块
    require('./modules/crypto_monitor.js')(config, logger, utils);
    
    // 加载网络模块
    require('./modules/network_monitor.js')(config, logger, utils);
    
    // 注释掉不需要的模块
    // require('./modules/anti_debug.js')(config, logger, utils);
    // require('./modules/sensitive_api.js')(config, logger, utils);
    // require('./modules/auto_extractor.js')(config, logger, utils);
}
```

### 自定义过滤器

可以配置各种过滤器来减少日志输出并专注于特定内容：

```javascript
// 添加网络过滤器
var networkModule = require('./modules/network_monitor.js')(config, logger, utils);
networkModule.addUrlFilter("api.example.com");
networkModule.addContentTypeFilter("application/json");

// 添加加密过滤器
var cryptoModule = require('./modules/crypto_monitor.js')(config, logger, utils);
cryptoModule.setAlgorithmFilter(["AES", "RSA"]); // 只监控这些算法
```

### 保存控制台输出

您可以将Frida的输出保存到文件：

```bash
frida -U -f com.example.app -l frida_master.js --no-pause > frida_output.txt
```

### 与其他工具结合

可以将提取到的数据与其他工具结合使用：

```bash
# 将提取的密钥从设备拉取到电脑
adb pull /sdcard/frida_extracted_keys.json

# 将日志文件拉取到电脑
adb pull /sdcard/frida_log.txt
```

## 常见问题解答

### Q: 应用崩溃怎么办？

某些应用可能对Hook敏感，可以尝试：
1. 禁用反调试绕过: 在config中设置`bypassAllDetection: false`
   ```javascript
   var config = {
       bypassAllDetection: false,  // 禁用所有绕过功能
       // 其他配置...
   };
   ```
2. 减少Hook数量: 只加载必要的模块
3. 使用-f强制启动模式(非附加模式)

### Q: 如何过滤大量的日志输出？

1. 调整日志级别:
   ```javascript
   var config = {
       logLevel: 'warn',  // 只显示警告和错误
       // 其他配置...
   };
   ```
2. 使用grep过滤:
   ```bash
   frida -U -f com.example.app -l frida_master.js --no-pause | grep CRYPTO
   ```

### Q: 为什么某些加密操作没被捕获？

可能的原因：
1. 应用使用了Native层加密，可以使用backup目录中的`hook_native_function.js`针对特定原生函数进行Hook
2. 应用使用了自定义加密库，需要特定Hook
3. 应用使用了代码混淆，类名和方法名可能改变

### Q: 如何扩展框架功能？

创建新的模块文件，遵循相同的结构：
```javascript
module.exports = function(config, logger, utils) {
    var tag = "MY_MODULE";
    logger.info(tag, "模块初始化");
    
    // 实现功能...
    
    return {
        // 导出API...
    };
};
```

然后在`frida_master.js`的`loadModules()`中加载它。

## 许可证

本项目采用 MIT 许可证。

---

**免责声明**: 本框架仅用于安全研究和授权测试目的。使用前请确保您有合法权限测试目标应用。对于任何滥用导致的问题，作者不承担责任。 