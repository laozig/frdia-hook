# Frida全功能Hook框架

一个功能强大的Frida脚本框架，专为Android应用分析和安全测试设计。本框架提供全面的功能模块，包括加密监控、网络监控、反调试绕过、敏感API监控和自动提取密钥。

## 目录结构

```
frdia/
│
├── frida_master.js          # 主入口文件
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

## 快速开始

### 使用方法

```bash
# 注入到指定应用
frida -U -f com.example.app -l frida_master.js --no-pause

# 或附加到运行中的进程
frida -U -n "应用名称" -l frida_master.js
```

### 日志输出
- 控制台实时输出
- 日志文件：`/sdcard/frida_log.txt`
- 提取的密钥：`/sdcard/frida_extracted_keys.json`

## 主框架文件说明

### frida_master.js

主入口文件，负责配置框架和加载各功能模块。

#### 配置参数

```javascript
var config = {
    logLevel: 'info',           // 日志级别: debug, info, warn, error
    fileLogging: true,          // 是否保存日志到文件
    logFilePath: '/sdcard/frida_log.txt',  // 日志路径
    autoExtractKeys: true,      // 自动提取密钥
    bypassAllDetection: true,   // 绕过检测
    colorOutput: true,          // 彩色输出
    stackTrace: false           // 打印调用栈
};
```

#### 主要功能
- 日志系统：提供四个日志级别(debug, info, warn, error)
- 工具函数：提供hex转储、字节数组转换等实用功能
- 模块加载：按需加载各功能模块
- 环境检查：检查运行环境并创建日志文件

## 功能模块详细介绍

### 1. 加密监控模块 (crypto_monitor.js)

监控和记录加密算法的使用，自动提取密钥、IV、明文和密文。

**文件路径**: `modules/crypto_monitor.js`

#### 详细参数说明

加密监控模块支持以下参数配置，可在加载模块时通过API传入：

| 参数名 | 类型 | 默认值 | 说明 |
|-------|------|-------|------|
| `enableKeyExtraction` | 布尔值 | true | 是否提取加密密钥 |
| `logPlaintext` | 布尔值 | true | 是否记录明文数据 |
| `logCiphertext` | 布尔值 | true | 是否记录密文数据 |
| `maxDataSize` | 整数 | 1024 | 记录数据的最大字节数 |
| `algorithmFilter` | 字符串数组 | [] | 仅监控指定的加密算法，空数组表示监控所有算法 |

#### 参数配置方法

```javascript
// 手动加载并配置加密监控模块
var cryptoModule = require('./modules/crypto_monitor.js')(config, logger, utils);

// 配置算法过滤器，仅监控特定算法
cryptoModule.setAlgorithmFilter(["AES/CBC/PKCS5Padding", "RSA/ECB/PKCS1Padding"]);

// 设置最大数据记录大小（字节）
cryptoModule.setMaxDataSize(2048);

// 启用或禁用特定功能
cryptoModule.enableKeyExtraction(true);  // 启用密钥提取
cryptoModule.enablePlaintextLogging(false);  // 禁用明文记录
```

#### 监控的加密API详解

1. **Javax Crypto APIs**
   - `javax.crypto.Cipher`: 监控所有初始化、加密和解密操作
   - `javax.crypto.spec.SecretKeySpec`: 监控密钥创建
   - `javax.crypto.spec.IvParameterSpec`: 监控初始化向量创建

2. **Java Security APIs**
   - `java.security.MessageDigest`: 监控MD5、SHA系列哈希计算
   - `java.security.Signature`: 监控数字签名操作
   - `java.security.KeyPairGenerator`: 监控密钥对生成

3. **Android特有API**
   - `android.util.Base64`: 监控Base64编解码
   - `android.content.SharedPreferences`: 监控加密相关配置读写

4. **第三方库支持**
   - BouncyCastle加密库API
   - Apache Commons Codec
   - 自定义加密库方法（可通过配置添加）

#### 最佳使用方法

**场景一：通用监控**
```javascript
// 默认配置，监控所有加密操作
require('./modules/crypto_monitor.js')(config, logger, utils);
```

**场景二：性能优化监控**
```javascript
// 减少日志量，提高性能
var cryptoModule = require('./modules/crypto_monitor.js')(config, logger, utils);
cryptoModule.setAlgorithmFilter(["AES", "RSA"]); // 只监控重要算法
cryptoModule.enablePlaintextLogging(false);  // 不记录明文数据
cryptoModule.enableCiphertextLogging(false); // 不记录密文数据
cryptoModule.setMaxDataSize(128); // 限制记录大小
```

**场景三：针对特定应用优化**
```javascript
// 针对使用AES加密的银行应用
var cryptoModule = require('./modules/crypto_monitor.js')(config, logger, utils);
cryptoModule.setAlgorithmFilter(["AES"]);
cryptoModule.addCustomHook("com.bankapp.security.CryptoUtil", "encrypt");
```

#### 输出格式详解

模块输出包括以下格式：

1. **加密操作记录**：
```
[12:34:56][INFO] (CRYPTO) 加密操作: AES/CBC/PKCS5Padding
[12:34:56][INFO] (CRYPTO) 来源: com.example.app.SecurityManager.encrypt:125
[12:34:56][INFO] (CRYPTO) 密钥(HEX): 0123456789ABCDEF0123456789ABCDEF
[12:34:56][INFO] (CRYPTO) IV(HEX): 0123456789ABCDEF0123456789ABCDEF
```

2. **解密操作记录**：
```
[12:34:56][INFO] (CRYPTO) 解密操作: AES/CBC/PKCS5Padding
[12:34:56][INFO] (CRYPTO) 来源: com.example.app.SecurityManager.decrypt:158
[12:34:56][INFO] (CRYPTO) 密钥(HEX): 0123456789ABCDEF0123456789ABCDEF
[12:34:56][INFO] (CRYPTO) 密文长度: 256字节
[12:34:56][INFO] (CRYPTO) 明文样本: {"username":"admin","token":"12345"}
```

3. **哈希计算记录**：
```
[12:34:56][INFO] (CRYPTO) 哈希计算: SHA-256
[12:34:56][INFO] (CRYPTO) 输入样本: password123
[12:34:56][INFO] (CRYPTO) 输出(HEX): ef92b778bafe771e89245b89ecbc08a44a4e166c06659911881f383d4473e94f
```

#### 优点与局限性

**优点：**
- 全面监控应用中的所有加密/解密操作
- 自动提取密钥、IV等敏感信息
- 支持主流加密库和自定义加密实现
- 可配置性高，可根据需求调整监控粒度
- 实时查看加密参数，无需反编译或猜测算法

**局限性：**
- 对于Native层加密无法直接监控（需结合native_function.js使用）
- 高强度监控可能影响应用性能
- 对于内存中频繁修改的密钥可能捕获不完整
- 部分高度混淆的代码可能需要手动调整Hook点
- 大量加密操作会产生大量日志，需合理配置过滤器

#### 实际应用案例

**案例1：提取API通信密钥**
某APP使用AES加密与服务器通信，通过监控Cipher.init()方法成功提取密钥：
```
[12:34:56][INFO] (CRYPTO) AES密钥提取成功
[12:34:56][INFO] (CRYPTO) 密钥(HEX): 8F7D4E34A1B2C3F8E4A5C6B7D8E9F0A1
[12:34:56][INFO] (CRYPTO) IV(HEX): 1A2B3C4D5E6F7A8B9C0D1E2F3A4B5C6D
```
使用提取的密钥成功解密所有网络流量。

**案例2：识别安全漏洞**
通过监控发现某APP在SharedPreferences中存储硬编码密钥：
```
[12:34:56][INFO] (CRYPTO) 静态密钥检测: SecretKeySpec
[12:34:56][INFO] (CRYPTO) 硬编码密钥(HEX): DEADBEEF01234567DEADBEEF01234567
[12:34:56][INFO] (CRYPTO) 密钥用途: 数据库加密
[12:34:56][INFO] (CRYPTO) 安全风险: 硬编码密钥可被提取
```

### 2. 反调试绕过模块 (anti_debug.js)

绕过各种反调试、反Root、反模拟器、反注入和SSL Pinning等检测机制。

**文件路径**: `modules/anti_debug.js`

#### 详细参数说明

反调试绕过模块支持以下参数配置，可在加载模块时通过API设置：

| 参数名 | 类型 | 默认值 | 说明 |
|-------|------|-------|------|
| `bypassAllDetection` | 布尔值 | true | 是否启用所有绕过功能 |
| `bypassRootDetection` | 布尔值 | true | 是否绕过Root检测 |
| `bypassEmulatorDetection` | 布尔值 | true | 是否绕过模拟器检测 |
| `bypassDebugDetection` | 布尔值 | true | 是否绕过调试检测 |
| `bypassFridaDetection` | 布尔值 | true | 是否绕过Frida检测 |
| `bypassXposedDetection` | 布尔值 | true | 是否绕过Xposed检测 |
| `bypassSslPinning` | 布尔值 | true | 是否绕过SSL证书固定 |
| `bypassSignatureVerification` | 布尔值 | true | 是否绕过签名验证 |
| `fakeDeviceInfo` | 对象 | null | 自定义设备信息，用于伪装设备 |
| `preventExit` | 布尔值 | true | 阻止应用强制退出 |
| `logBypassedDetections` | 布尔值 | true | 是否记录被绕过的检测 |
| `bypassNativeDetection` | 布尔值 | true | 是否绕过Native层检测 |

#### 参数配置方法

```javascript
// 手动加载并配置反调试绕过模块
var antiDebugModule = require('./modules/anti_debug.js')(config, logger, utils);

// 有选择地启用/禁用某些绕过功能
antiDebugModule.disableRootDetectionBypass();  // 禁用Root检测绕过
antiDebugModule.enableEmulatorDetectionBypass(true);  // 启用模拟器检测绕过

// 自定义设备信息，用于伪装设备
antiDebugModule.setFakeDeviceInfo({
    brand: "samsung",
    model: "SM-G973F",
    manufacturer: "Samsung",
    fingerprint: "samsung/beyond1ltexx/beyond1:10/QP1A.190711.020/G973FXXU3BSL1:user/release-keys",
    sdkInt: 29,
    androidVersion: "10"
});

// 设置绕过SSL证书固定的选项
antiDebugModule.setSslUnpinningOptions({
    enableOkHttp: true,
    enableConscrypt: true,
    enableOpenSSL: true,
    enableCustomTrustManager: true
});

// 添加自定义检测绕过（针对特定应用的反调试机制）
antiDebugModule.addCustomHook({
    className: "com.example.app.SecurityUtils",
    methodName: "checkDeviceIntegrity",
    returnValue: true
});
```

#### 绕过检测类型详解

1. **Java层反调试检测绕过**
   - `Debug.isDebuggerConnected()`: 返回false
   - `ActivityManager.getRunningAppProcesses()`: 过滤调试器进程
   - `Debug.isDebuggerConnected()`: 返回false
   - `ApplicationInfo.flags`: 移除FLAG_DEBUGGABLE标志
   - `InetAddress.isReachable()`: 绕过Frida服务器探测
   - `System.exit()`: 阻止应用强制退出
   - `Process.killProcess()`: 阻止进程终止

2. **Root检测绕过**
   - 文件检测: 拦截对`/system/bin/su`等文件的访问
   - 命令执行: 拦截`Runtime.exec("su")`等命令
   - 包检测: 过滤已知Root相关包
   - 属性检测: 修改`ro.secure`等系统属性
   - 签名检测: 绕过Superuser应用签名检测

3. **模拟器检测绕过**
   - 设备特征: 修改Build类各字段(MODEL, BRAND等)
   - 硬件ID: 修改IMEI, IMSI等硬件标识符
   - 传感器: 模拟真实设备传感器数据
   - 电话功能: 修改TelephonyManager返回值
   - CPU特征: 伪装CPU信息文件

4. **Frida/Xposed检测绕过**
   - 进程扫描: 隐藏Frida相关进程
   - 文件检测: 拦截对frida-agent等文件的检测
   - 内存扫描: 修改/proc/self/maps扫描结果
   - 端口检测: 隐藏Frida默认端口
   - 特征检测: 移除Frida/Xposed内存特征

5. **SSL Pinning绕过**
   - OkHttp: 绕过OkHttp的证书固定
   - X509TrustManager: 替换信任管理器
   - Conscrypt: 绕过Conscrypt库实现
   - TrustManagerImpl: 修改系统信任管理器
   - 自定义验证: 处理自定义证书验证逻辑

6. **签名校验绕过**
   - PackageManager.getPackageInfo: 返回原始签名
   - Signature.verify: 强制返回验证通过
   - 自定义验证: 绕过应用自定义签名校验

7. **Native层检测绕过**
   - ptrace: 绕过ptrace反调试
   - /proc/maps: 过滤内存映射信息
   - native库检测: 绕过库特征检测
   - 系统属性: 修改Native层系统属性读取
   - JNI函数: 绕过JNI层检测函数

#### 最佳使用方法

**场景一：标准应用分析**
```javascript
// 使用默认配置，启用所有绕过功能
require('./modules/anti_debug.js')(config, logger, utils);
```

**场景二：银行/金融应用分析**
```javascript
var antiDebugModule = require('./modules/anti_debug.js')(config, logger, utils);

// 为金融应用优化绕过设置
antiDebugModule.enableAdvancedDetectionBypass(true);  // 启用高级检测绕过
antiDebugModule.setSslUnpinningOptions({   // 自定义SSL绕过选项
    enableOkHttp: true,
    enableCustomTrustManager: true,
    enableNativeTLS: true,
    trustAllCertificates: true
});

// 伪装成普通设备，避免银行App的额外检测
antiDebugModule.setFakeDeviceInfo({
    brand: "samsung",
    model: "SM-G973F",
    bootloaderUnlocked: false,
    developerMode: false
});
```

**场景三：游戏防护绕过**
```javascript
var antiDebugModule = require('./modules/anti_debug.js')(config, logger, utils);

// 为游戏保护机制配置
antiDebugModule.enableNativeDetectionBypass(true);  // 增强Native层绕过
antiDebugModule.enableTimingDetectionBypass(true);  // 绕过时序检测
antiDebugModule.disableLogEvents(true);  // 避免大量检测事件记录，减少干扰
```

**场景四：特定应用优化**
```javascript
var antiDebugModule = require('./modules/anti_debug.js')(config, logger, utils);

// 只启用需要的功能，提高性能
antiDebugModule.disableAllBypasses();  // 先禁用所有绕过
antiDebugModule.enableDebugDetectionBypass(true);  // 只启用调试检测绕过
antiDebugModule.enableFridaDetectionBypass(true);  // 启用Frida检测绕过

// 添加自定义绕过
antiDebugModule.addCustomJavaHook("com.example.app.SecurityCheck", "isDeviceCompromised", false);
```

#### 设备信息自定义

可以修改以下设备信息来绕过特定检测：

```javascript
// 自定义完整设备信息
antiDebugModule.setFakeDeviceInfo({
    brand: "samsung",
    model: "SM-G973F",
    manufacturer: "Samsung", 
    device: "beyond1",
    product: "beyond1ltexx",
    fingerprint: "samsung/beyond1ltexx/beyond1:10/QP1A.190711.020/G973FXXU3BSL1:user/release-keys",
    hardware: "exynos9820",
    bootloader: "G973FXXU3BSL1",
    sdkInt: 29,
    release: "10",
    securityPatch: "2020-01-01",
    serialNumber: "RZVAE5TG4TA",
    buildType: "user",
    buildTags: "release-keys"
});

// 或单独修改某个属性
antiDebugModule.setDeviceProperty("model", "SM-G973F");
antiDebugModule.setDeviceProperty("manufacturer", "Samsung");
```

#### 优点与局限性

**优点：**
- 全面覆盖Android常见反调试/反Root/反模拟器检测机制
- 模块化设计，可按需启用/禁用特定绕过功能
- 自动处理Native层和Java层检测
- 支持伪装设备信息，隐藏真实环境特征
- 内置SSL证书固定绕过，无需额外配置
- 可动态添加自定义绕过规则，适应特定应用
- 记录被绕过的检测点，便于分析应用保护机制

**局限性：**
- 对于高度定制化的保护方案可能需要额外配置
- 某些高级反调试技术可能需要结合Native模块使用
- 绕过大量检测点可能导致性能下降
- 可能无法绕过基于硬件特性的检测（如SafetyNet完整性检查）
- 不适用于带有自定义加密VM保护的应用
- 某些极端情况下，过度绕过可能导致应用功能异常
- 最新版本的反调试技术可能需要更新模块才能绕过

#### 实际应用案例

**案例1：绕过银行应用的多层检测**
某银行APP启动时执行多达15种安全性检查：
```
[12:34:56][INFO] (ANTI) 绕过 Root检测: Shell.exec("su")
[12:34:56][INFO] (ANTI) 绕过 Root检测: File.exists(/system/xbin/su)
[12:34:56][INFO] (ANTI) 绕过 调试检测: Debug.isDebuggerConnected()
[12:34:56][INFO] (ANTI) 绕过 模拟器检测: Build.FINGERPRINT.contains("generic")
[12:34:56][INFO] (ANTI) 绕过 框架检测: String.contains("frida")
[12:34:56][INFO] (ANTI) 绕过 SSL证书固定: OkHttpClient$Builder.certificatePinner()
...
```
成功绕过所有检测，实现对应用完整分析。

**案例2：阻止反调试退出**
某应用检测到Frida后尝试强制退出：
```
[12:34:56][INFO] (ANTI) 绕过 强制退出: System.exit(0)
[12:34:56][DEBUG] (ANTI) 调用来源: com.example.app.SecurityChecker.onFridaDetected()
```
成功拦截退出调用，应用继续运行。

**案例3：动态绕过自定义检测**
某应用使用自定义反调试库：
```
[12:34:56][WARN] (ANTI) 未知检测点: com.app.security.CustomDetector.checkIntegrity()
[12:34:56][INFO] (ANTI) 添加动态Hook: com.app.security.CustomDetector.checkIntegrity()
[12:34:57][INFO] (ANTI) 绕过 自定义检测: com.app.security.CustomDetector.checkIntegrity()
```
自动学习并绕过未知检测方法。

#### 高级自定义配置

对于复杂应用，可以创建自定义配置文件：

```javascript
// 创建custom_anti_debug.js
var antiConfig = {
    // 定义自定义检测函数
    customDetectionMethods: [
        {className: "com.example.security.DeviceSecurity", methodName: "checkRooted", returnValue: false},
        {className: "com.example.security.DeviceSecurity", methodName: "isEmulator", returnValue: false},
        {className: "com.example.security.DeviceSecurity", methodName: "isDebuggable", returnValue: false}
    ],
    
    // 定义需要修改的系统属性
    systemProperties: {
        "ro.secure": "1",
        "ro.debuggable": "0",
        "ro.boot.verifiedbootstate": "green",
        "ro.boot.veritymode": "enforcing",
        "ro.boot.flash.locked": "1"
    },
    
    // 定义设备信息
    deviceInfo: {
        brand: "samsung",
        model: "SM-G973F",
        manufacturer: "Samsung"
    },
    
    // 自定义Native绕过
    nativeBypass: {
        enablePtraceBypass: true,
        enableMapsFiltering: true,
        enableFridaServerDetection: true
    }
};

// 将配置传递给模块
var antiDebugModule = require('./modules/anti_debug.js')(config, logger, utils);
antiDebugModule.loadCustomConfig(antiConfig);
```

### 3. 网络监控模块 (network_monitor.js)

监控和记录HTTP/HTTPS请求和响应，WebSocket通信，Socket通信等。

**文件路径**: `modules/network_monitor.js`

#### 详细参数说明

网络监控模块支持以下参数配置，可在加载模块时通过API设置：

| 参数名 | 类型 | 默认值 | 说明 |
|-------|------|-------|------|
| `logRequestBody` | 布尔值 | true | 是否记录请求体内容 |
| `logResponseBody` | 布尔值 | true | 是否记录响应体内容 |
| `maxBodySize` | 整数 | 5120 | 请求/响应体记录的最大字节数 |
| `enableSslUnpinning` | 布尔值 | true | 是否自动绕过SSL证书固定 |
| `urlFilters` | 字符串数组 | [] | URL过滤器，空数组表示监控所有URL |
| `headerFilters` | 对象 | {} | 请求头过滤器，用于筛选特定请求头的请求 |
| `contentTypeFilters` | 字符串数组 | [] | 内容类型过滤器，空数组表示监控所有内容类型 |
| `excludeUrlPatterns` | 正则表达式数组 | [] | 排除特定URL模式的请求 |
| `logBinaryResponses` | 布尔值 | false | 是否记录二进制响应数据 |

#### 参数配置方法

```javascript
// 手动加载并配置网络监控模块
var networkModule = require('./modules/network_monitor.js')(config, logger, utils);

// 设置URL过滤器，只监控特定域名
networkModule.addUrlFilter("api.example.com");
networkModule.addUrlFilter("login.example.com");

// 排除特定URL
networkModule.addExcludeUrlPattern(/\.jpg$|\.png$|\.gif$/);  // 排除图片请求

// 根据内容类型过滤
networkModule.addContentTypeFilter("application/json");
networkModule.addContentTypeFilter("application/x-www-form-urlencoded");

// 设置请求/响应体大小限制
networkModule.setMaxBodySize(10240);  // 设置为10KB

// 配置请求头过滤器
networkModule.addHeaderFilter("Authorization");  // 只监控带有Authorization头的请求

// 启用/禁用特定功能
networkModule.enableResponseBodyLogging(false);  // 不记录响应体
networkModule.enableBinaryResponseLogging(true); // 记录二进制响应
```

#### 监控的网络API详解

1. **HTTP客户端监控**
   - **OkHttp3**：完整监控OkHttp3请求和响应，包括拦截器链
   - **HttpURLConnection**：监控标准Java HTTP连接
   - **Volley**：监控Google Volley网络库请求
   - **Retrofit**：通过OkHttp层间接监控Retrofit调用

2. **WebView相关**
   - **WebView.loadUrl**：监控WebView加载的URL
   - **WebViewClient**：监控页面加载和资源请求
   - **JavascriptInterface**：监控JS接口调用

3. **WebSocket监控**
   - **OkHttp WebSocket**：监控WebSocket连接和消息
   - **标准WebSocket**：监控标准WebSocket实现
   - **自定义WebSocket库**：通过Hook底层Socket实现监控

4. **Socket监控**
   - **标准Socket**：监控原始Socket连接
   - **SSLSocket**：监控SSL/TLS连接
   - **DatagramSocket**：监控UDP数据包

#### 最佳使用方法

**场景一：通用监控**
```javascript
// 默认配置，监控所有网络活动
require('./modules/network_monitor.js')(config, logger, utils);
```

**场景二：API调试优化**
```javascript
var networkModule = require('./modules/network_monitor.js')(config, logger, utils);

// 只关注特定API端点
networkModule.addUrlFilter("api.example.com/v1");

// 只监控JSON内容
networkModule.addContentTypeFilter("application/json");

// 排除心跳检测请求
networkModule.addExcludeUrlPattern(/\/heartbeat$/);

// 增加响应体大小限制，适合大型API响应
networkModule.setMaxBodySize(20480);
```

**场景三：性能优化监控**
```javascript
var networkModule = require('./modules/network_monitor.js')(config, logger, utils);

// 只记录请求，不记录响应体（减少内存占用）
networkModule.enableResponseBodyLogging(false);

// 排除静态资源，减少日志量
networkModule.addExcludeUrlPattern(/\.(jpg|png|gif|css|js)$/);

// 减小记录大小
networkModule.setMaxBodySize(1024);
```

**场景四：安全审计**
```javascript
var networkModule = require('./modules/network_monitor.js')(config, logger, utils);

// 只关注带有认证信息的请求
networkModule.addHeaderFilter("Authorization");
networkModule.addHeaderFilter("Cookie");

// 监控特定敏感操作
networkModule.addUrlFilter("/api/login");
networkModule.addUrlFilter("/api/payment");
networkModule.addUrlFilter("/api/user");
```

#### 输出格式详解

模块输出包括以下格式：

1. **HTTP请求记录**：
```
[12:34:56][INFO] (NETWORK) 请求 [ID-123]: POST https://api.example.com/v1/login
[12:34:56][DEBUG] (NETWORK) 请求头: {
  "Content-Type": "application/json",
  "Authorization": "Bearer eyJhbGciOi...",
  "User-Agent": "OkHttp3/4.9.0"
}
[12:34:56][DEBUG] (NETWORK) 请求体: {"username":"user","password":"****"}
```

2. **HTTP响应记录**：
```
[12:34:57][INFO] (NETWORK) 响应 [ID-123]: 200 OK (531ms)
[12:34:57][DEBUG] (NETWORK) 响应头: {
  "Content-Type": "application/json",
  "Server": "nginx/1.18.0",
  "Content-Length": "428"
}
[12:34:57][DEBUG] (NETWORK) 响应体: {"status":"success","token":"eyJhbGciO...","expires_in":3600}
```

3. **WebSocket通信记录**：
```
[12:35:01][INFO] (NETWORK) WebSocket连接 [WS-45]: wss://realtime.example.com
[12:35:02][INFO] (NETWORK) WebSocket发送 [WS-45]: {"type":"subscribe","channel":"updates"}
[12:35:03][INFO] (NETWORK) WebSocket接收 [WS-45]: {"type":"message","data":{"event":"update","content":"..."}}
```

4. **Socket通信记录**：
```
[12:36:05][INFO] (NETWORK) Socket连接 [SOC-12]: 192.168.1.100:443
[12:36:05][DEBUG] (NETWORK) Socket发送 [SOC-12]: <二进制数据, 256字节>
[12:36:06][DEBUG] (NETWORK) Socket接收 [SOC-12]: <二进制数据, 1024字节>
```

#### 优点与局限性

**优点：**
- 全面监控应用所有网络通信，包括HTTPS加密流量
- 提供丰富的过滤功能，可针对特定需求自定义监控
- 自动提取和解析常见身份验证令牌（如JWT）
- 支持主流HTTP客户端库和WebSocket实现
- 可同时监控应用内的多种网络通信方式
- 自动绕过SSL证书固定，无需额外配置

**局限性：**
- 大量网络请求会生成大量日志，可能影响性能
- 复杂的二进制协议需要额外解析器才能理解内容
- 某些高度自定义的网络库可能需要额外的Hook点
- 无法直接监控Native层实现的网络请求（需结合native_function.js使用）
- 可能不支持某些非标准的WebSocket实现或自定义协议
- 监控所有响应体可能导致内存占用增加

#### 实际应用案例

**案例1：发现未加密敏感数据**
某APP登录请求监控结果：
```
[12:34:56][INFO] (NETWORK) 请求: POST https://api.example.com/login
[12:34:56][DEBUG] (NETWORK) 请求体: {"username":"admin","password":"plaintext_password"}
```
发现密码以明文方式传输，存在安全风险。

**案例2：识别API认证漏洞**
通过监控发现某APP使用固定API密钥进行认证：
```
[12:34:56][INFO] (NETWORK) 请求: GET https://api.example.com/user/data
[12:34:56][DEBUG] (NETWORK) 请求头: {
  "API-Key": "1a2b3c4d5e6f7g8h9i0",
  "Content-Type": "application/json"
}
```
所有用户共用同一个API密钥，缺少用户级别权限控制。

**案例3：WebSocket认证绕过**
通过监控WebSocket通信，发现可直接发送未授权操作：
```
[12:34:56][INFO] (NETWORK) WebSocket连接: wss://api.example.com/ws
[12:34:56][INFO] (NETWORK) WebSocket发送: {"action":"get_data","user_id":"12345"}
[12:34:56][INFO] (NETWORK) WebSocket接收: {"status":"success","data":{"credit_card":"1234-5678-9012-3456"}}
```
WebSocket连接没有验证用户权限，可以请求任意用户数据。

#### 自定义监控扩展

可以通过以下方式扩展网络监控模块：

```javascript
// 添加自定义HTTP客户端监控
networkModule.addCustomHttpClientHook({
    className: "com.example.app.CustomHttpClient",
    methodSend: "sendRequest",
    methodReceive: "parseResponse"
});

// 添加自定义WebSocket监控
networkModule.addCustomWebSocketHook({
    className: "com.example.app.CustomWebSocketClient",
    connectMethod: "connect",
    sendMethod: "send",
    receiveMethod: "onMessage"
});

// 自定义请求/响应解析逻辑
networkModule.setRequestParser(function(requestObj) {
    // 自定义请求解析逻辑
    return {url: ..., headers: ..., body: ...};
});
```

### 4. 敏感API监控模块 (sensitive_api.js)

监控应用对敏感API的调用。

**文件路径**: `modules/sensitive_api.js`

#### 详细参数说明

敏感API监控模块支持以下参数配置：

| 参数名 | 类型 | 默认值 | 说明 |
|-------|------|-------|------|
| `enableAllCategories` | 布尔值 | true | 是否监控所有类别API |
| `categoriesEnabled` | 对象 | {} | 各类别API监控的启用状态 |
| `logParameters` | 布尔值 | true | 是否记录API调用参数 |
| `logReturnValues` | 布尔值 | true | 是否记录API返回值 |
| `maxParameterSize` | 整数 | 1024 | 记录参数值的最大字节数 |
| `logStackTrace` | 布尔值 | false | 是否记录调用堆栈 |
| `fileExtensionFilter` | 字符串数组 | [] | 文件操作监控的扩展名过滤器 |
| `contentProviderFilter` | 字符串数组 | [] | ContentProvider URI过滤器 |
| `customHooks` | 对象数组 | [] | 自定义API监控配置 |
| `excludeMethods` | 字符串数组 | [] | 排除特定方法的监控 |

#### 支持的API类别

模块将监控的API分为以下几个类别，每个类别可单独启用或禁用：

1. **FILE_SYSTEM**: 文件系统操作
2. **SHARED_PREFS**: SharedPreferences操作
3. **DATABASE**: 数据库操作
4. **CLIPBOARD**: 剪贴板操作
5. **LOCATION**: 位置服务
6. **CAMERA**: 相机操作
7. **MICROPHONE**: 麦克风操作
8. **CONTACTS**: 联系人访问
9. **SMS**: 短信操作
10. **PHONE**: 电话操作
11. **DEVICE_INFO**: 设备信息获取
12. **ACCOUNT**: 账户操作
13. **PACKAGE_MANAGER**: 包管理器操作
14. **CRYPTO**: 加密相关操作
15. **NETWORK_INFO**: 网络信息获取
16. **CONTENT_PROVIDER**: ContentProvider访问
17. **WEBVIEW**: WebView相关操作
18. **IPC**: 进程间通信

#### 参数配置方法

```javascript
// 手动加载并配置敏感API监控模块
var apiModule = require('./modules/sensitive_api.js')(config, logger, utils);

// 启用/禁用特定类别的API监控
apiModule.enableCategory('FILE_SYSTEM', true);    // 启用文件系统监控
apiModule.enableCategory('LOCATION', true);       // 启用位置服务监控
apiModule.enableCategory('DEVICE_INFO', false);   // 禁用设备信息监控

// 仅启用指定类别，其他全部禁用
apiModule.enableOnly(['FILE_SYSTEM', 'SHARED_PREFS', 'CLIPBOARD']);

// 调整日志记录选项
apiModule.setLogParameters(true);      // 记录调用参数
apiModule.setLogReturnValues(true);    // 记录返回值
apiModule.setLogStackTrace(true);      // 记录调用栈

// 设置文件扩展名过滤器
apiModule.setFileExtensionFilter(['.xml', '.db', '.json']);

// 添加自定义API监控
apiModule.addCustomHook({
    className: "com.example.app.DataManager",
    methodName: "readSensitiveData",
    parameterLogging: true,
    returnValueLogging: true,
    category: "CUSTOM"
});
```

#### 监控的敏感API详解

1. **文件系统操作**
   - `java.io.File`: 所有文件创建、删除、读写操作
   - `java.io.FileInputStream/FileOutputStream`: 文件流操作
   - `android.content.Context.openFileInput/openFileOutput`: 应用文件读写
   - `java.io.RandomAccessFile`: 随机访问文件
   - `android.app.DownloadManager`: 文件下载管理

2. **数据存储操作**
   - `android.content.SharedPreferences`: 所有配置读写操作
   - `android.database.sqlite.SQLiteDatabase`: 数据库读写操作
   - `android.content.ContentValues`: 内容值创建和修改
   - `android.database.Cursor`: 查询结果访问

3. **系统服务访问**
   - `android.content.ClipboardManager`: 剪贴板内容读写
   - `android.location.LocationManager`: 位置获取和监听
   - `android.hardware.Camera`: 相机访问和控制
   - `android.media.MediaRecorder`: 录音和视频录制
   - `android.hardware.SensorManager`: 传感器访问

4. **个人数据访问**
   - `android.provider.ContactsContract`: 联系人访问
   - `android.provider.Telephony`: 短信访问
   - `android.telephony.TelephonyManager`: 电话和SIM卡信息
   - `android.accounts.AccountManager`: 账户信息访问

5. **设备信息获取**
   - `android.telephony.TelephonyManager.getDeviceId()`: IMEI获取
   - `android.telephony.TelephonyManager.getSubscriberId()`: IMSI获取
   - `android.provider.Settings.Secure.ANDROID_ID`: Android ID获取
   - `android.os.Build`: 设备信息获取

6. **应用交互**
   - `android.content.pm.PackageManager`: 包信息查询
   - `android.app.ActivityManager`: 活动和服务监控
   - `android.content.ContentResolver`: 内容提供者访问

#### 最佳使用方法

**场景一：通用监控**
```javascript
// 默认配置，监控所有敏感API
require('./modules/sensitive_api.js')(config, logger, utils);
```

**场景二：隐私审计**
```javascript
var apiModule = require('./modules/sensitive_api.js')(config, logger, utils);

// 只监控与隐私相关的API类别
apiModule.enableOnly([
    'LOCATION',
    'CAMERA',
    'MICROPHONE',
    'CONTACTS',
    'SMS',
    'PHONE',
    'DEVICE_INFO'
]);

// 启用调用栈记录，便于分析调用来源
apiModule.setLogStackTrace(true);
```

**场景三：数据安全审计**
```javascript
var apiModule = require('./modules/sensitive_api.js')(config, logger, utils);

// 重点监控数据存储和加密相关操作
apiModule.enableOnly([
    'FILE_SYSTEM',
    'SHARED_PREFS',
    'DATABASE',
    'CRYPTO'
]);

// 记录详细的参数和返回值信息
apiModule.setMaxParameterSize(4096);  // 增加记录的参数大小
```

**场景四：节约资源的配置**
```javascript
var apiModule = require('./modules/sensitive_api.js')(config, logger, utils);

// 只监控最关键的类别，节省资源
apiModule.disableAllCategories();
apiModule.enableCategory('FILE_SYSTEM', true);
apiModule.enableCategory('SHARED_PREFS', true);

// 减少日志量
apiModule.setLogParameters(false);
apiModule.setLogStackTrace(false);
```

#### 输出格式详解

模块输出包括以下格式：

1. **基本API调用记录**：
```
[12:34:56][INFO] (SENSITIVE) 检测到敏感API: FILE_SYSTEM.FileOutputStream
[12:34:56][INFO] (SENSITIVE) 调用位置: com.example.app.FileManager.saveData()
[12:34:56][DEBUG] (SENSITIVE) 参数: {
  "path": "/data/data/com.example.app/files/config.json"
}
```

2. **详细带参数和返回值的记录**：
```
[12:34:56][INFO] (SENSITIVE) 检测到敏感API: SHARED_PREFS.getString
[12:34:56][INFO] (SENSITIVE) 调用位置: com.example.app.PreferenceManager.getAuthToken()
[12:34:56][DEBUG] (SENSITIVE) 参数: {
  "key": "auth_token",
  "defaultValue": null
}
[12:34:56][DEBUG] (SENSITIVE) 返回值: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
```

3. **带堆栈跟踪的记录**：
```
[12:34:56][INFO] (SENSITIVE) 检测到敏感API: LOCATION.getLastKnownLocation
[12:34:56][DEBUG] (SENSITIVE) 参数: {
  "provider": "gps"
}
[12:34:56][DEBUG] (SENSITIVE) 堆栈:
  at com.example.app.LocationTracker.getCurrentLocation(LocationTracker.java:125)
  at com.example.app.UserActivity.onResume(UserActivity.java:78)
  at android.app.Activity.performResume(Activity.java:7304)
```

#### 优点与局限性

**优点：**
- 全面覆盖Android敏感API，分类清晰，便于审计
- 模块化设计，可按需启用或禁用特定类别监控
- 支持记录参数和返回值，便于深入分析
- 可记录调用栈，便于追踪调用来源
- 灵活的过滤机制，可聚焦于特定文件类型或URI
- 可动态添加自定义监控点，适应特定应用
- 低性能开销的配置选项，适合长时间监控

**局限性：**
- 监控大量API会产生大量日志，可能影响性能
- 部分敏感API可能在Native层实现，需结合native_function.js使用
- 针对高度混淆的应用，可能需要手动调整类名方法名
- 无法监控通过反射动态调用的API（除非特殊处理）
- 过多记录参数和返回值可能导致内存占用增加
- 某些API的参数或返回值可能过于复杂，不便于直接记录
- 部分系统级API在不同Android版本间有差异，可能需要适配

#### 实际应用案例

**案例1：检测不安全的数据存储**
```
[12:34:56][INFO] (SENSITIVE) 检测到敏感API: SHARED_PREFS.putString
[12:34:56][DEBUG] (SENSITIVE) 参数: {
  "key": "password",
  "value": "123456"
}
[12:34:56][INFO] (SENSITIVE) 调用位置: com.example.app.LoginActivity.saveCredentials()
```
发现应用以明文方式存储密码，存在安全风险。

**案例2：未授权位置获取**
```
[12:34:56][INFO] (SENSITIVE) 检测到敏感API: LOCATION.getLastKnownLocation
[12:34:56][DEBUG] (SENSITIVE) 参数: {
  "provider": "network"
}
[12:34:56][DEBUG] (SENSITIVE) 返回值: {
  "latitude": 37.422,
  "longitude": -122.084,
  "accuracy": 50.0
}
[12:34:56][INFO] (SENSITIVE) 调用位置: com.example.app.TrackingService.onStart()
```
发现后台服务在启动时获取位置信息，可能存在隐私问题。

**案例3：设备识别信息收集**
```
[12:34:56][INFO] (SENSITIVE) 检测到敏感API: DEVICE_INFO.getAndroidId
[12:34:56][DEBUG] (SENSITIVE) 返回值: "a1b2c3d4e5f6g7h8"
[12:34:56][INFO] (SENSITIVE) 调用位置: com.example.app.analytics.DeviceInfoCollector.collectId()
```
发现应用收集设备标识符，可能用于跟踪用户。

#### 定制化监控示例

针对特定应用可以进一步定制监控：

```javascript
// 为特定应用定制监控配置
var apiConfig = {
    // 自定义重要文件路径模式
    importantFilePaths: [
        "/data/data/com.example.app/files/config",
        "/data/data/com.example.app/shared_prefs/auth",
        "/data/data/com.example.app/databases/"
    ],
    
    // 关注的SharedPreferences键值
    sensitivePrefsKeys: [
        "token", "auth", "password", "key", "secret"
    ],
    
    // 自定义监控方法
    customMethods: [
        {
            className: "com.example.app.SecurityManager",
            methodName: "decrypt",
            paramLogging: true,
            returnLogging: true
        },
        {
            className: "com.example.app.network.ApiClient",
            methodName: "authenticate",
            paramLogging: true
        }
    ]
};

// 加载模块时传入自定义配置
var apiModule = require('./modules/sensitive_api.js')(config, logger, utils);
apiModule.loadCustomConfig(apiConfig);
```

### 5. 自动提取密钥模块 (auto_extractor.js)

自动识别和提取应用中的密钥、令牌和配置信息。

**文件路径**: `modules/auto_extractor.js`

#### 详细参数说明

自动提取密钥模块支持以下参数配置：

| 参数名 | 类型 | 默认值 | 说明 |
|-------|------|-------|------|
| `autoExtractKeys` | 布尔值 | true | 是否启用自动提取功能 |
| `outputFilePath` | 字符串 | '/sdcard/frida_extracted_keys.json' | 提取数据输出文件路径 |
| `extractionSources` | 对象 | {} | 各提取源的启用状态 |
| `keyPatterns` | 对象数组 | [] | 密钥识别的正则表达式模式 |
| `sensitiveKeywords` | 字符串数组 | [] | 敏感关键词，用于识别可能的密钥 |
| `minKeyLength` | 整数 | 16 | 最小密钥长度 |
| `maxEntries` | 整数 | 1000 | 最多存储的密钥条目数 |
| `saveInterval` | 整数 | 5000 | 自动保存间隔(毫秒) |
| `removeDuplicates` | 布尔值 | true | 是否移除重复密钥 |
| `customExtractionRules` | 对象数组 | [] | 自定义提取规则 |
| `classPatterns` | 字符串数组 | [] | 类名模式，用于静态字段提取 |

#### 提取源详解

模块支持从以下来源提取密钥：

1. **静态字段提取**：
   - 分析应用中常见配置类的静态字段
   - 例如：`Config.API_KEY`、`Constants.SECRET_KEY`等
   - 特别关注带有敏感关键词的字段名称

2. **配置文件提取**：
   - 监控文件读取操作，提取配置文件内容
   - 支持的格式：JSON, XML, Properties, YAML
   - 主要关注`.properties`、`.json`、`.xml`等文件

3. **网络请求提取**：
   - 分析HTTP请求头中的认证信息
   - 提取响应中的令牌和密钥
   - 特别关注`Authorization`、`X-API-Key`等请求头

4. **SharedPreferences提取**：
   - 监控SharedPreferences读写操作
   - 提取敏感配置项，如令牌、密钥等
   - 关注键名包含"key"、"token"、"secret"等关键词的项

5. **内存密钥提取**：
   - 监控密钥生成和加密初始化操作
   - 从`javax.crypto.spec.SecretKeySpec`捕获密钥
   - 从`IvParameterSpec`捕获初始化向量

6. **代码内硬编码提取**：
   - 分析代码中的字符串常量
   - 识别符合特定格式的硬编码密钥
   - 例如Base64编码字符串、十六进制字符串等

#### 参数配置方法

```javascript
// 手动加载并配置自动提取密钥模块
var extractorModule = require('./modules/auto_extractor.js')(config, logger, utils);

// 配置提取选项
extractorModule.setOutputFilePath('/sdcard/custom_keys.json');  // 自定义输出路径
extractorModule.setSaveInterval(10000);  // 设置保存间隔为10秒

// 启用或禁用特定提取源
extractorModule.enableExtractionSource('STATIC_FIELDS', true);
extractorModule.enableExtractionSource('NETWORK', true);
extractorModule.enableExtractionSource('SHARED_PREFS', false);  // 禁用SharedPreferences提取

// 添加自定义密钥识别模式
extractorModule.addKeyPattern('API_KEY', /[Aa][Pp][Ii][_-]?[Kk][Ee][Yy][=:]\s*["']?([A-Za-z0-9_\-]{16,})["']?/);
extractorModule.addKeyPattern('JWT', /eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/);

// 添加敏感关键词
extractorModule.addSensitiveKeywords(['apikey', 'secret', 'password', 'token', 'auth', 'credential']);

// 添加自定义提取规则
extractorModule.addCustomExtractionRule({
    className: "com.example.app.ApiClient",
    methodName: "authenticate",
    parameterIndex: 1,  // 提取第二个参数作为API密钥
    type: "API_KEY"
});

// 设置类名模式，用于静态字段扫描
extractorModule.setClassPatterns([
    "com.example.app.Config",
    "com.example.app.Constants",
    "com.example.app.util.Security"
]);
```

#### 密钥识别规则详解

模块使用以下规则识别可能的密钥：

1. **名称匹配**：
   - 包含关键词：key, token, secret, password, auth, api, credential等
   - 例如：`API_KEY`、`auth_token`、`secret_key`等

2. **格式匹配**：
   - **Base64格式**：`^[A-Za-z0-9+/=]{24,}$`
   - **十六进制格式**：`^[A-Fa-f0-9]{16,}$`
   - **JWT格式**：`^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$`
   - **OAuth格式**：`^[a-zA-Z0-9]{32,}$`
   - **API密钥格式**：各种常见API密钥格式的正则表达式

3. **上下文匹配**：
   - 出现在认证相关方法的参数或返回值中
   - 出现在请求头中特定字段(`Authorization`, `API-Key`等)
   - 存储在名称含有敏感关键词的配置项中

4. **内容特征**：
   - 足够长度(默认16字符以上)
   - 高熵值(随机性高的字符串)
   - 符合特定平台密钥格式(如AWS、Firebase等)

#### 最佳使用方法

**场景一：通用监控**
```javascript
// 使用默认配置，监控所有提取源
require('./modules/auto_extractor.js')(config, logger, utils);
```

**场景二：网络API密钥提取**
```javascript
var extractorModule = require('./modules/auto_extractor.js')(config, logger, utils);

// 专注于提取网络API密钥
extractorModule.disableAllSources();
extractorModule.enableExtractionSource('NETWORK', true);

// 添加常见API密钥格式
extractorModule.addKeyPattern('Twitter', /[tT][wW][iI][tT][tT][eE][rR].*["']([0-9a-zA-Z]{35,44})["']/);
extractorModule.addKeyPattern('Facebook', /[fF][aA][cC][eE][bB][oO][oO][kK].*["']([0-9a-f]{32})["']/);
extractorModule.addKeyPattern('GitHub', /[gG][iI][tT][hH][uU][bB].*["']([0-9a-zA-Z]{35,40})["']/);
extractorModule.addKeyPattern('Google', /[gG][oO][oO][gG][lL][eE].*["']([A-Za-z0-9_-]{39})["']/);

// 增加HTTP请求头监控
extractorModule.addHeadersToMonitor([
    'x-api-key', 
    'authorization', 
    'client-secret',
    'client-id'
]);
```

**场景三：加密密钥提取**
```javascript
var extractorModule = require('./modules/auto_extractor.js')(config, logger, utils);

// 专注于提取加密密钥
extractorModule.disableAllSources();
extractorModule.enableExtractionSource('CRYPTO_KEYS', true);
extractorModule.enableExtractionSource('STATIC_FIELDS', true);

// 配置提取选项
extractorModule.setMinKeyLength(8);  // AES密钥可能只有16字节
extractorModule.addClassPatterns(["com.example.app.crypto", "com.example.security"]);  // 关注特定包名
```

**场景四：配置优化**
```javascript
var extractorModule = require('./modules/auto_extractor.js')(config, logger, utils);

// 优化配置，减少重复和误报
extractorModule.setMinKeyLength(24);  // 增加最小密钥长度，减少误报
extractorModule.setSaveInterval(30000);  // 延长保存间隔，减少I/O操作
extractorModule.setMaxEntries(100);  // 限制条目数，节省内存

// 减少提取来源，提高性能
extractorModule.disableAllSources();
extractorModule.enableExtractionSource('SHARED_PREFS', true);
extractorModule.enableExtractionSource('NETWORK', true);
```

#### 提取结果格式

提取的密钥以JSON格式保存，结构如下：

```json
{
  "metadata": {
    "timestamp": "2023-05-22T12:34:56.789Z",
    "app_package": "com.example.app",
    "count": 5
  },
  "keys": {
    "静态字段_com.example.Config.API_KEY": {
      "id": "静态字段_com.example.Config.API_KEY",
      "type": "API_KEY",
      "name": "API_KEY",
      "value": "a1b2c3d4e5f6g7h8i9j0",
      "source": "类静态字段",
      "class": "com.example.Config",
      "timestamp": "2023-05-22T12:34:56.789Z",
      "detectionMethod": "静态字段扫描",
      "confidence": "高",
      "usageCount": 1
    },
    "网络请求头_Authorization": {
      "id": "网络请求头_Authorization",
      "type": "JWT",
      "name": "Authorization",
      "value": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
      "source": "HTTP请求",
      "url": "https://api.example.com/auth",
      "timestamp": "2023-05-22T12:35:10.123Z",
      "detectionMethod": "网络请求监控",
      "confidence": "高",
      "usageCount": 3
    },
    "加密_AES_密钥": {
      "id": "加密_AES_密钥",
      "type": "SYMMETRIC_KEY",
      "name": "AES密钥",
      "value": "DEADBEEF01234567DEADBEEF01234567",
      "valueFormat": "hex",
      "source": "加密API",
      "algorithm": "AES/CBC/PKCS5Padding",
      "timestamp": "2023-05-22T12:36:05.678Z",
      "detectionMethod": "加密API监控",
      "confidence": "高",
      "usageCount": 5
    }
  }
}
```

#### 密钥分类与识别

模块将提取的密钥分类为以下几种类型：

1. **API_KEY**: API访问密钥
2. **AUTH_TOKEN**: 认证令牌
3. **JWT**: JSON Web Token
4. **OAUTH_TOKEN**: OAuth认证令牌
5. **SYMMETRIC_KEY**: 对称加密密钥(如AES)
6. **ASYMMETRIC_KEY**: 非对称加密密钥(如RSA)
7. **PASSWORD**: 密码
8. **HASH**: 哈希值
9. **SALT**: 加密盐值
10. **IV**: 初始化向量
11. **CONFIG**: 配置值
12. **CUSTOM**: 自定义类型

#### 优点与局限性

**优点：**
- 全自动提取应用中的各类密钥和敏感信息
- 多种来源综合分析，提高检出率
- 智能识别常见密钥格式和特征
- 支持自定义提取规则和模式
- 结构化存储提取结果，便于后续分析
- 自动去重和分类，提高提取质量
- 可实时查看提取进度，无需等待应用运行完成

**局限性：**
- 可能产生误报，将普通字符串误判为密钥
- 高强度加密或混淆的密钥可能难以识别
- 过多提取规则可能影响应用性能
- 频繁写入文件可能导致IO压力
- 无法提取仅在Native层使用的密钥
- 对于自定义格式的密钥需要手动配置规则
- 大量密钥提取可能导致内存占用增加

#### 实际应用案例

**案例1：提取Firebase配置密钥**
```
[12:34:56][INFO] (EXTRACTOR) 提取到静态字段: com.example.app.FirebaseConfig.API_KEY
[12:34:56][INFO] (EXTRACTOR) 类型: API_KEY
[12:34:56][INFO] (EXTRACTOR) 值: AIzaSyA1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6
[12:34:56][INFO] (EXTRACTOR) 置信度: 高
```
提取的Firebase API密钥可用于访问应用的Firebase服务。

**案例2：捕获加密密钥**
```
[12:34:56][INFO] (EXTRACTOR) 提取到AES密钥
[12:34:56][INFO] (EXTRACTOR) 类型: SYMMETRIC_KEY
[12:34:56][INFO] (EXTRACTOR) 值(HEX): 0123456789ABCDEF0123456789ABCDEF
[12:34:56][INFO] (EXTRACTOR) 算法: AES/CBC/PKCS5Padding
[12:34:56][INFO] (EXTRACTOR) 来源: javax.crypto.spec.SecretKeySpec
```
使用提取的AES密钥可以解密应用内的敏感数据。

**案例3：提取OAuth令牌**
```
[12:34:56][INFO] (EXTRACTOR) 提取到OAuth令牌
[12:34:56][INFO] (EXTRACTOR) 类型: OAUTH_TOKEN
[12:34:56][INFO] (EXTRACTOR) 值: ya29.a0AfB_byDNMgnI53Kj...
[12:34:56][INFO] (EXTRACTOR) 来源: HTTP请求头Authorization
[12:34:56][INFO] (EXTRACTOR) URL: https://www.googleapis.com/oauth2/v4/token
```
捕获的OAuth令牌可用于访问对应的API服务。

#### 高级用法: 密钥验证和利用

可以配合其他模块验证和利用提取的密钥：

```javascript
// 创建自定义提取后处理器
var extractorModule = require('./modules/auto_extractor.js')(config, logger, utils);

// 添加密钥提取回调处理
extractorModule.addKeyExtractedCallback(function(keyInfo) {
    // 在新提取密钥时执行自定义逻辑
    logger.info("KEY_HANDLER", "发现新密钥: " + keyInfo.type + " - " + keyInfo.name);
    
    // API密钥自动验证
    if (keyInfo.type === "API_KEY") {
        verifyApiKey(keyInfo.value);
    }
    
    // JWT令牌解析
    if (keyInfo.type === "JWT") {
        parseJwtToken(keyInfo.value);
    }
    
    // 加密密钥自动测试
    if (keyInfo.type === "SYMMETRIC_KEY") {
        testDecryption(keyInfo.value, keyInfo.algorithm);
    }
});

// 密钥验证示例函数
function verifyApiKey(apiKey) {
    // 实现API密钥验证逻辑
}

function parseJwtToken(token) {
    // 解析JWT令牌结构
    var parts = token.split('.');
    if (parts.length === 3) {
        try {
            // Base64解码令牌部分
            var header = JSON.parse(decodeBase64(parts[0]));
            var payload = JSON.parse(decodeBase64(parts[1]));
            logger.info("JWT_PARSER", "解析JWT: " + JSON.stringify({header: header, payload: payload}));
        } catch (e) {
            logger.error("JWT_PARSER", "解析失败: " + e);
        }
    }
}

function testDecryption(key, algorithm) {
    // 尝试使用密钥解密已捕获的加密数据
}
```

### 6. DEX脱壳模块 (dex_dumper.js)

提取内存中的DEX文件，支持多种加固保护的脱壳操作。现已支持大部分主流加固方案，包括企业级加固保护。

**文件路径**: `modules/dex_dumper.js`

#### 详细参数说明

DEX脱壳模块支持以下参数配置：

| 参数名 | 类型 | 默认值 | 说明 |
|-------|------|-------|------|
| `outputDir` | 字符串 | '/sdcard/frida_dumps/' | DEX文件输出目录 |
| `filterSystemClasses` | 布尔值 | true | 是否过滤系统类 |
| `autoLoadClasses` | 布尔值 | true | 是否自动加载所有类 |
| `dumpClassLoaders` | 布尔值 | true | 是否转储所有ClassLoader中的DEX |
| `dumpMemory` | 布尔值 | true | 是否扫描内存中的DEX |
| `dumpOnClassLoad` | 布尔值 | true | 是否在类加载时提取DEX |
| `minDexSize` | 整数 | 4096 | 最小DEX文件大小(字节) |
| `maxDexSize` | 整数 | 20 * 1024 * 1024 | 最大DEX文件大小(20MB) |
| `memScanIntervalMs` | 整数 | 5000 | 内存扫描间隔(毫秒) |
| `supportedProtections` | 字符串数组 | ['梆梆', '爱加密', '360加固', '腾讯乐固', '阿里聚安全', '百度加固', '娜迦', '盛大加固', '网秦加固', '几维安全', '通付盾', '瑞星加固', 'APKProtect', '顶像科技', '珊瑚灵御', '金丝雀', '华为HMS加固', '华为安全', '海思加固', '新版爱加密', '携程加固', '微信小程序加固', '字节跳动加固', '猎豹加固', 'OPPO加固', 'vivo加固'] | 支持的加固保护类型 |

#### 参数配置方法

```javascript
// 手动加载并配置DEX脱壳模块
var dexDumper = require('./modules/dex_dumper.js')(config, logger, utils);

// 设置脱壳输出目录
dexDumper.setOutputDirectory('/sdcard/my_dumps/');

// 禁用系统类过滤，提取所有类
dexDumper.setFilterSystemClasses(false);

// 设置DEX大小限制 (最小1KB，最大30MB)
dexDumper.setDexSizeLimit(1024, 30 * 1024 * 1024);

// 添加对其他加固保护的支持
dexDumper.addProtectionSupport('某某加固');

// 在脱壳完成后显示统计信息
setTimeout(function() {
    dexDumper.showStats();
}, 20000);  // 20秒后显示统计
```

#### 脱壳原理详解

1. **ClassLoader跟踪**
   - 拦截BaseDexClassLoader/DexClassLoader/InMemoryDexClassLoader的创建
   - 通过反射访问ClassLoader内部结构，获取DEX文件
   - 从DexPathList和dexElements数组中提取真实DEX

2. **类加载监控**
   - 拦截Class.forName和ClassLoader.loadClass方法
   - 在类加载后立即从其ClassLoader中提取DEX
   - 记录唯一ClassLoader，避免重复提取

3. **内存扫描**
   - 扫描进程内存中的可读区域
   - 通过DEX文件特征(魔数"dex\n")识别DEX文件
   - 验证并提取完整的DEX文件

4. **加固特定处理**
   - 针对梆梆加固：hook特定类(如"com.secneo.apkwrapper.AW")
   - 针对爱加密：hook关键方法(如"s.h.e.a.a.d")
   - 针对360加固：hook "com.qihoo.util.StubApp"类
   - 针对腾讯乐固：hook "com.tencent.StubShell.TxAppEntry"类
   - 针对华为HMS加固：hook HMS SDK关键类和方法
   - 针对华为安全/加固：hook SecAppApplication类
   - 针对海思加固：hook HiSecureApplication和SecDexLoader类
   - 针对新版爱加密：hook SuperApplication和DXApplication类
   - 针对携程加固：hook Shield相关类
   - 针对微信小程序：hook微信应用与Tinker加载器
   - 针对字节跳动加固：hook ShadowHook和抖音应用类
   - 针对手机厂商加固：针对OPPO、vivo等厂商加固方案

#### 自动提取流程

1. **初始化阶段**：
   - 创建输出目录
   - 设置所有钩子
   - 延迟执行内存扫描，等待应用初始化

2. **运行时提取**：
   - 应用启动后，监控所有ClassLoader创建
   - 实时从新发现的ClassLoader提取DEX
   - 定期扫描内存区域，寻找未加载的DEX

3. **类加载优化**：
   - 提供自动加载所有应用类的功能
   - 强制触发类加载，使得加密的DEX被解密并加载到内存

4. **去重与验证**：
   - 通过哈希值避免重复提取相同的DEX
   - 验证DEX文件完整性，过滤无效文件

#### 最佳使用方法

**场景一：通用脱壳**
```javascript
// 使用默认配置
require('./modules/dex_dumper.js')(config, logger, utils);
```

**场景二：内存占用优化**
```javascript
var dexDumper = require('./modules/dex_dumper.js')(config, logger, utils);

// 禁用周期性内存扫描，减少内存占用
var customConfig = {
    dumpClassLoaders: true,
    dumpOnClassLoad: true,
    dumpMemory: false,  // 禁用内存扫描
    autoLoadClasses: false  // 不自动加载所有类
};

// 手动设置配置
Object.keys(customConfig).forEach(key => {
    if (typeof dexDumper[`set${key.charAt(0).toUpperCase() + key.slice(1)}`] === 'function') {
        dexDumper[`set${key.charAt(0).toUpperCase() + key.slice(1)}`](customConfig[key]);
    }
});
```

**场景三：针对特定加固的优化**
```javascript
var dexDumper = require('./modules/dex_dumper.js')(config, logger, utils);

// 如果只需处理360加固
var customConfig = {
    supportedProtections: ['360加固'],
    dumpClassLoaders: true,
    dumpOnClassLoad: true,
    dumpMemory: true,
    autoLoadClasses: true
};

// 延迟执行，等待加固代码先初始化
setTimeout(function() {
    // 20秒后显示统计信息
    dexDumper.showStats();
}, 20000);
```

#### 输出格式详解

1. **文件命名格式**：
   - 从ClassLoader提取的DEX: `classes_XX.dex` (XX为序号)
   - 从内存中提取的DEX: `memory_XX.dex`

2. **日志输出**：
```
[12:34:56][INFO] (DUMPER) DEX脱壳模块初始化
[12:34:56][INFO] (DUMPER) 输出目录: /sdcard/frida_dumps/
[12:34:56][INFO] (DUMPER) 支持的保护: 梆梆, 爱加密, 360加固, 腾讯乐固, 阿里聚安全, 百度加固, 娜迦, 盛大加固, 网秦加固, 几维安全, 通付盾, 瑞星加固, APKProtect, 顶像科技, 珊瑚灵御, 金丝雀, 华为HMS加固, 华为安全, 海思加固, 新版爱加密, 携程加固, 微信小程序加固, 字节跳动加固, 猎豹加固, OPPO加固, vivo加固
[12:34:56][INFO] (DUMPER) ClassLoader钩子设置成功
[12:34:56][INFO] (DUMPER) 类加载钩子设置成功
[12:34:57][DEBUG] (DUMPER) ClassLoader创建: /data/app/app-1.apk
[12:34:58][INFO] (DUMPER) 提取DEX文件: /sdcard/frida_dumps/classes_01.dex [大小: 4194304 字节, 从ClassLoader]
[12:34:59][INFO] (DUMPER) 提取DEX文件: /sdcard/frida_dumps/memory_02.dex [大小: 2097152 字节, 从内存]
```

3. **提取完成统计**：
```
[12:39:56][INFO] (DUMPER) ==== DEX提取统计信息 ====
[12:39:56][INFO] (DUMPER) 提取的DEX文件: 5
[12:39:56][INFO] (DUMPER) 提取的类文件: 1024
[12:39:56][INFO] (DUMPER) 总大小: 12 MB
[12:39:56][INFO] (DUMPER) 唯一ClassLoader数: 3
[12:39:56][INFO] (DUMPER) 运行时间: 300.45 秒
[12:39:56][INFO] (DUMPER) 输出目录: /sdcard/frida_dumps/
[12:39:56][INFO] (DUMPER) =========================
```

#### 优点与局限性

**优点：**
- 全自动提取内存中的DEX文件，无需手动干预
- 支持主流加固保护方案的脱壳
- 同时使用多种提取方式，提高成功率
- 可以实时提取动态加载的DEX
- 内置对常见加固特征的识别和特殊处理
- 自动验证和去重，过滤无效DEX文件
- 提供详细统计和分析信息

**局限性：**
- 对高强度混淆和定制加固方案可能效果有限
- 扫描大内存可能导致应用卡顿
- 部分极端保护手段(如虚拟机保护)可能无效
- 提取过程中可能占用较大内存和存储空间
- 无法处理DEX动态解密后即时销毁的场景
- 某些高级加固可能需要结合其他技术手段
- 不适用于系统级保护方案(如阿里的KSLR)

#### 实际应用案例

**案例1：脱360加固的App**
```
[12:34:56][INFO] (DUMPER) DEX脱壳模块初始化
[12:34:57][INFO] (DUMPER) 360加固钩子设置成功: com.qihoo.util.StubApp
[12:35:02][DEBUG] (DUMPER) 360加固API调用: com.qihoo.util.StubApp.a
[12:35:03][INFO] (DUMPER) 提取DEX文件: /sdcard/frida_dumps/classes_01.dex [大小: 8392134 字节, 从ClassLoader]
[12:35:05][INFO] (DUMPER) 提取DEX文件: /sdcard/frida_dumps/classes_02.dex [大小: 5923412 字节, 从ClassLoader]
[12:35:10][INFO] (DUMPER) ==== DEX提取统计信息 ====
[12:35:10][INFO] (DUMPER) 提取的DEX文件: 2
[12:35:10][INFO] (DUMPER) 总大小: 14 MB
```
成功提取360加固的真实DEX文件。

**案例2：脱梆梆加固的App**
```
[12:34:56][INFO] (DUMPER) 梆梆加固钩子设置成功: com.secneo.apkwrapper.AW
[12:35:01][DEBUG] (DUMPER) 梆梆加固API调用: com.secneo.apkwrapper.AW.attachBaseContext
[12:35:02][DEBUG] (DUMPER) 开始加载所有类...
[12:35:45][INFO] (DUMPER) 完成类加载，共加载 2143 个类
[12:35:46][INFO] (DUMPER) 提取DEX文件: /sdcard/frida_dumps/memory_01.dex [大小: 3145728 字节, 从内存]
[12:35:47][INFO] (DUMPER) 提取DEX文件: /sdcard/frida_dumps/memory_02.dex [大小: 2097152 字节, 从内存]
```
从内存提取梆梆加固的真实DEX。

**案例3：处理混合保护的App**
某应用使用了多层保护：外层是腾讯乐固，内部DEX又使用了自定义加密：
```
[12:34:56][INFO] (DUMPER) 腾讯乐固钩子设置成功: com.tencent.StubShell.TxAppEntry
[12:35:05][DEBUG] (DUMPER) 腾讯乐固API调用: com.tencent.StubShell.TxAppEntry.onCreate
[12:35:10][INFO] (DUMPER) 提取DEX文件: /sdcard/frida_dumps/classes_01.dex [大小: 12582912 字节, 从ClassLoader]
// 稍后，当内部DEX被动态加载时
[12:36:45][DEBUG] (DUMPER) ClassLoader创建: 内存缓冲区
[12:36:46][INFO] (DUMPER) 提取DEX文件: /sdcard/frida_dumps/classes_02.dex [大小: 6291456 字节, 从ClassLoader]
```
成功提取多层保护的DEX文件。

#### 高级用法: 自定义脱壳配置

对于特殊应用可以创建定制脱壳配置：

```javascript
// 创建custom_dumper.js
var customDumperConfig = {
    // 精确定位DEX文件
    targetClassLoaders: [
        "dalvik.system.PathClassLoader",
        "dalvik.system.InMemoryDexClassLoader"
    ],
    
    // 自定义内存搜索区域
    memoryRegions: [
        { start: "0x70000000", end: "0x80000000" }
    ],
    
    // 特定的类加载事件
    classLoadEvents: [
        { className: "com.example.security.DexLoader", methodName: "loadEncryptedDex" }
    ],
    
    // 特定类触发提取
    triggerClasses: [
        "com.example.app.MainActivity",
        "com.example.app.SplashActivity"
    ],
    
    // 延迟提取配置
    delayExtraction: 10000, // 延迟10秒开始提取
    
    // 关注特定类
    focusOnClasses: [
        "com.example.app.api", 
        "com.example.app.core"
    ]
};

// 使用自定义配置加载模块
var dexDumper = require('./modules/dex_dumper.js')(config, logger, utils);

// 依次应用自定义配置
Object.keys(customDumperConfig).forEach(key => {
    if (typeof dexDumper["set" + key.charAt(0).toUpperCase() + key.slice(1)] === "function") {
        dexDumper["set" + key.charAt(0).toUpperCase() + key.slice(1)](customDumperConfig[key]);
    }
});
```

## 备份脚本目录 (backup/)

备份目录包含了拆分的单一功能脚本，可根据需要单独使用。

### 新增：系统函数监控模块 (system_api_monitor.js)

监控和记录常用Java/Android系统函数的调用，包括集合操作、字符串处理、日志和UI交互等。

**文件路径**: `modules/system_api_monitor.js`

#### 详细参数说明

系统函数监控模块支持以下参数配置：

| 参数名 | 类型 | 默认值 | 说明 |
|-------|------|-------|------|
| `enableAllCategories` | 布尔值 | true | 是否监控所有类别系统函数 |
| `categoriesEnabled` | 对象 | {} | 各类别监控的启用状态 |
| `logParameters` | 布尔值 | true | 是否记录函数调用参数 |
| `logReturnValues` | 布尔值 | true | 是否记录函数返回值 |
| `maxDataSize` | 整数 | 1024 | 记录数据的最大字节数 |
| `stackTraceDepth` | 整数 | 3 | 调用栈记录深度 |
| `customHooks` | 对象数组 | [] | 自定义Hook配置 |
| `excludeStackPatterns` | 字符串数组 | [] | 排除特定调用栈源的记录 |

#### 监控的系统函数类别

模块将监控的系统函数分类如下：

1. **集合操作**
   - `java.util.HashMap`: 所有方法（如put, get, remove等）
   - `java.util.LinkedHashMap`: 所有方法
   - `java.util.ArrayList`: 主要方法（add, addAll, set, remove等）
   - `java.util.Collections`: 静态方法（sort, shuffle等）

2. **字符串处理**
   - `android.text.TextUtils`: 所有静态方法（isEmpty, equals等）
   - `java.lang.String`: 主要方法（getBytes, substring, split等）和构造函数
   - `java.lang.StringBuilder`: 所有方法（append, insert, toString等）

3. **编解码和加密**
   - `android.util.Base64`: 编解码方法（encode, decode）
   - `java.util.zip.GZIPOutputStream`: 压缩
   - `java.util.zip.GZIPInputStream`: 解压缩

4. **系统交互**
   - `android.util.Log`: 各级别日志方法（v, d, i, w, e）
   - `android.widget.Toast`: 显示方法（show）
   - `android.os.Handler`: 消息处理方法（sendMessage, post等）

#### 参数配置方法

```javascript
// 手动加载并配置系统函数监控模块
var sysMonitor = require('./modules/system_api_monitor.js')(config, logger, utils);

// 启用或禁用特定类别
sysMonitor.enableCategory('COLLECTIONS', true);    // 启用集合操作监控
sysMonitor.enableCategory('STRING_PROCESSING', true);  // 启用字符串处理监控
sysMonitor.enableCategory('SYSTEM_INTERACTION', false);  // 禁用系统交互监控

// 仅启用特定类别，其他全部禁用
sysMonitor.enableOnly(['COLLECTIONS', 'STRING_PROCESSING']);

// 添加自定义Hook
sysMonitor.addCustomHook({
    className: "java.util.HashMap",
    methodName: "put",
    parameterLogging: true,
    returnValueLogging: true
});

// 调整日志记录选项
sysMonitor.setLogParameters(true);      // 记录调用参数
sysMonitor.setLogReturnValues(true);    // 记录返回值

// 排除特定调用栈源
sysMonitor.addExcludeStackPattern("com.android.internal");
```

#### 最佳使用方法

**场景一：通用监控**
```javascript
// 使用默认配置监控所有系统函数
require('./modules/system_api_monitor.js')(config, logger, utils);
```

**场景二：数据流分析**
```javascript
var sysMonitor = require('./modules/system_api_monitor.js')(config, logger, utils);

// 聚焦于数据处理相关函数
sysMonitor.enableOnly(['COLLECTIONS', 'STRING_PROCESSING', 'ENCODING']);

// 记录完整的数据流
sysMonitor.setMaxDataSize(4096);  // 增加数据记录大小
sysMonitor.setStackTraceDepth(5); // 增加调用栈深度
```

**场景三：简化日志调试**
```javascript
var sysMonitor = require('./modules/system_api_monitor.js')(config, logger, utils);

// 只监控日志和Toast显示
sysMonitor.disableAllCategories();
sysMonitor.enableCategory('SYSTEM_INTERACTION', true);

// 添加自定义函数过滤器
sysMonitor.setMethodFilter({
    'android.util.Log': ['e', 'w', 'i'],  // 只监控这三种日志级别
    'android.widget.Toast': ['show']      // 只监控Toast显示
});
```

#### 详细监控的系统函数列表

1. **集合类函数**
   - `java.util.HashMap.put(Object key, Object value)`
   - `java.util.HashMap.get(Object key)`
   - `java.util.LinkedHashMap.put(Object key, Object value)`
   - `java.util.LinkedHashMap.get(Object key)`
   - `java.util.ArrayList.add(Object element)`
   - `java.util.ArrayList.addAll(Collection collection)`
   - `java.util.ArrayList.set(int index, Object element)`
   - `java.util.Collections.sort(List list)`
   - `java.util.Collections.shuffle(List list)`

2. **字符串处理函数**
   - `java.lang.String.getBytes()`
   - `java.lang.String.getBytes(String charsetName)`
   - `java.lang.String.<init>(byte[] bytes)`
   - `java.lang.String.<init>(byte[] bytes, String charset)`
   - `java.lang.StringBuilder.append(String str)`
   - `java.lang.StringBuilder.toString()`
   - `android.text.TextUtils.isEmpty(CharSequence str)`
   - `android.text.TextUtils.equals(CharSequence a, CharSequence b)`

3. **编解码函数**
   - `android.util.Base64.encode(byte[] input, int flags)`
   - `android.util.Base64.decode(byte[] input, int flags)`
   - `android.util.Base64.encodeToString(byte[] input, int flags)`
   - `android.util.Base64.decode(String input, int flags)`

4. **系统交互函数**
   - `android.util.Log.v(String tag, String msg)`
   - `android.util.Log.d(String tag, String msg)`
   - `android.util.Log.i(String tag, String msg)`
   - `android.util.Log.w(String tag, String msg)`
   - `android.util.Log.e(String tag, String msg)`
   - `android.widget.Toast.show()`
   - `android.widget.Toast.makeText(Context context, CharSequence text, int duration)`

#### 输出格式示例

```
[12:34:56][INFO] (SYSTEM) 函数调用: HashMap.put
[12:34:56][INFO] (SYSTEM) 调用位置: com.example.app.DataManager.saveData
[12:34:56][DEBUG] (SYSTEM) 参数: {
  "key": "auth_token",
  "value": "eyJhbGciOiJIUzI1NiJ9..."
}
[12:34:56][DEBUG] (SYSTEM) 返回值: null

[12:34:56][INFO] (SYSTEM) 函数调用: String.getBytes
[12:34:56][INFO] (SYSTEM) 调用位置: com.example.app.Encoder.encodeData
[12:34:56][DEBUG] (SYSTEM) 参数: {
  "charset": "UTF-8"
}
[12:34:56][DEBUG] (SYSTEM) 返回值: [字节数组, 长度:128]

[12:34:56][INFO] (SYSTEM) 函数调用: Base64.encodeToString
[12:34:56][INFO] (SYSTEM) 调用位置: com.example.app.Encoder.encodeData
[12:34:56][DEBUG] (SYSTEM) 参数: {
  "input": [字节数组, 长度:128],
  "flags": 0
}
[12:34:56][DEBUG] (SYSTEM) 返回值: "SGVsbG8gV29ybGQ..."
```

#### 优点与局限性

**优点：**
- 全面监控Android/Java系统API的使用情况
- 可跟踪数据的完整流转过程，从集合到编码再到网络传输
- 特别适合追踪数据处理流程和潜在的安全问题
- 可识别应用的核心数据结构和处理模式
- 灵活配置，可针对性监控特定类别函数
- 有助于分析逆向工程中遇到的混淆代码功能

**局限性：**
- 系统函数调用非常频繁，可能产生大量日志
- 对应用性能有一定影响，特别是在监控核心集合类时
- 部分系统函数实现可能会因Android版本而有差异
- 对于自定义继承系统类的情况可能需要额外配置
- 不适合长时间全量监控，最好有针对性地使用

#### 与其他模块的配合使用

系统函数监控模块可以与其他模块配合，形成更完整的监控链：

```javascript
// 同时加载系统函数监控和网络监控
var sysMonitor = require('./modules/system_api_monitor.js')(config, logger, utils);
var networkModule = require('./modules/network_monitor.js')(config, logger, utils);

// 系统函数监控专注于数据处理
sysMonitor.enableOnly(['COLLECTIONS', 'STRING_PROCESSING', 'ENCODING']);

// 网络监控专注于HTTP请求
networkModule.addContentTypeFilter("application/json");

// 结合两者可以跟踪数据从创建、处理到发送的完整过程
```

#### 实际应用案例

**案例1：追踪加密前的原始数据**
```
[12:34:56][INFO] (SYSTEM) 函数调用: HashMap.put
[12:34:56][DEBUG] (SYSTEM) 参数: {
  "key": "password",
  "value": "user_plain_password"
}

[12:34:57][INFO] (CRYPTO) 加密操作: AES/CBC/PKCS5Padding
[12:34:57][DEBUG] (CRYPTO) 明文: {"password":"***"}
```
通过监控HashMap操作找到了加密前的明文密码。

**案例2：发现日志泄露**
```
[12:34:56][INFO] (SYSTEM) 函数调用: Log.d
[12:34:56][DEBUG] (SYSTEM) 参数: {
  "tag": "AuthManager",
  "msg": "User authenticated with token: eyJhbGciOiJIUzI1NiJ9..."
}
```
发现应用将敏感的认证令牌写入调试日志，存在信息泄露风险。

**案例3：分析数据编码流程**
```
[12:34:56][INFO] (SYSTEM) 函数调用: String.getBytes
[12:34:56][DEBUG] (SYSTEM) 返回值: [字节数组]

[12:34:56][INFO] (SYSTEM) 函数调用: Base64.encodeToString
[12:34:56][DEBUG] (SYSTEM) 返回值: "SGVsbG8gV29ybGQ="

[12:34:57][INFO] (NETWORK) 请求: POST https://api.example.com/data
[12:34:57][DEBUG] (NETWORK) 请求体: {"encoded_data":"SGVsbG8gV29ybGQ="}
```
通过跟踪系统调用，找到了从原始字符串到Base64编码再到网络发送的完整数据流。

#### 实际应用案例

以下是一些系统函数监控模块的实际应用场景：

**场景一：追踪加密数据流向**
```javascript
// 加载系统函数和加密模块
var sysMonitor = require('./modules/system_api_monitor.js')(config, logger, utils);
var cryptoModule = require('./modules/crypto_monitor.js')(config, logger, utils);

// 系统函数监控聚焦于数据处理和编码
sysMonitor.enableOnly(['COLLECTIONS', 'STRING_PROCESSING', 'ENCODING']);
sysMonitor.setMaxDataSize(4096);  // 增加数据记录大小

// 加密模块专注于关键算法
cryptoModule.setTargetAlgorithms(['AES', 'RSA']);

// 排除系统框架的干扰调用
sysMonitor.addExcludeStackPattern("com.google.gson");
sysMonitor.addExcludeStackPattern("com.alibaba.fastjson");
```

此场景可以清晰追踪数据从创建、编码到最终加密的完整流程。监控日志示例：

```
[12:34:56][INFO] (SYSTEM) 函数调用: HashMap.put
[12:34:56][INFO] (SYSTEM) 调用位置: com.example.app.DataManager.prepareData
[12:34:56][DEBUG] (SYSTEM) 参数: {"key":"user_id","value":"12345"}

[12:34:56][INFO] (SYSTEM) 函数调用: String.getBytes
[12:34:56][INFO] (SYSTEM) 调用位置: com.example.app.DataManager.encodeData
[12:34:56][DEBUG] (SYSTEM) 参数: {"charset":"UTF-8"}

[12:34:56][INFO] (SYSTEM) 函数调用: Base64.encodeToString
[12:34:56][INFO] (SYSTEM) 调用位置: com.example.app.DataManager.encodeData

[12:34:56][INFO] (CRYPTO) 加密操作: javax.crypto.Cipher.doFinal
[12:34:56][INFO] (CRYPTO) 算法: AES/ECB/PKCS5Padding
[12:34:56][INFO] (CRYPTO) 密钥: A1B2C3D4E5F6G7H8...
```

**场景二：检测敏感信息泄露**
```javascript
// 加载系统函数和网络监控模块
var sysMonitor = require('./modules/system_api_monitor.js')(config, logger, utils);
var networkModule = require('./modules/network_monitor.js')(config, logger, utils);

// 系统函数监控聚焦于剪贴板和UI交互
sysMonitor.enableOnly(['SYSTEM_INTERACTION']);
sysMonitor.setMethodFilter({
  'android.content.ClipboardManager': ['setPrimaryClip', 'getPrimaryClip'],
  'android.widget.Toast': ['show'],
  'android.app.AlertDialog': ['show', 'setMessage']
});

// 网络监控专注于数据上传
networkModule.setIncludeUrls(["upload", "log", "report", "collect"]);
```

此场景可以检测应用是否通过系统UI组件泄露敏感信息，或通过网络发送剪贴板内容。

**场景三：分析混淆代码功能**
```javascript
// 加载系统函数监控和自动提取模块
var sysMonitor = require('./modules/system_api_monitor.js')(config, logger, utils);
var extractor = require('./modules/auto_extractor.js')(config, logger, utils);

// 全面监控所有系统API
sysMonitor.enableCategory('COLLECTIONS', true);
sysMonitor.enableCategory('STRING_PROCESSING', true);
sysMonitor.enableCategory('ENCODING', true);
sysMonitor.enableCategory('SYSTEM_INTERACTION', true);

// 增加调用栈深度，帮助分析代码流程
sysMonitor.setStackTraceDepth(8);

// 设置特定类的跟踪
sysMonitor.addCustomHook({
    className: "com.example.app.a.b.c",  // 混淆后的类名
    methodName: "a",                     // 混淆后的方法名
    parameterLogging: true,
    returnValueLogging: true
});
```

此场景通过监控系统API调用模式，可以推断出混淆代码的实际功能，特别适用于逆向工程分析。

**场景四：分析字符串处理和编码链**
```javascript
// 加载系统函数监控模块
var sysMonitor = require('./modules/system_api_monitor.js')(config, logger, utils);

// 只关注字符串处理和编码
sysMonitor.enableOnly(['STRING_PROCESSING', 'ENCODING']);

// 特别关注正则表达式和编码方法
sysMonitor.setMethodFilter({
    'java.lang.String': ['matches', 'replaceAll', 'split'],
    'java.util.regex.Pattern': ['compile', 'matcher'],
    'java.util.regex.Matcher': ['find', 'group'],
    'android.util.Base64': ['encode', 'decode', 'encodeToString'],
    'java.net.URLEncoder': ['encode'],
    'java.net.URLDecoder': ['decode']
});
```

此场景可以揭示应用的数据处理流程，特别是在涉及字符串变换和多层编码时。监控日志示例：

```
[12:34:56][INFO] (SYSTEM) 函数调用: String.replaceAll
[12:34:56][INFO] (SYSTEM) 调用位置: com.example.app.StringProcessor.clean
[12:34:56][DEBUG] (SYSTEM) 参数: {"regex":"[^a-zA-Z0-9]","replacement":""}
[12:34:56][DEBUG] (SYSTEM) 返回值: "abc123XYZ"

[12:34:56][INFO] (SYSTEM) 函数调用: String.toLowerCase
[12:34:56][INFO] (SYSTEM) 调用位置: com.example.app.StringProcessor.normalize
[12:34:56][DEBUG] (SYSTEM) 返回值: "abc123xyz"

[12:34:56][INFO] (SYSTEM) 函数调用: URLEncoder.encode
[12:34:56][INFO] (SYSTEM) 调用位置: com.example.app.StringProcessor.prepare
[12:34:56][DEBUG] (SYSTEM) 参数: {"s":"abc123xyz","charset":"UTF-8"}
[12:34:56][DEBUG] (SYSTEM) 返回值: "abc123xyz"
```

这些实际应用案例展示了系统函数监控模块的多种使用场景，从数据流分析到安全检测，再到逆向工程辅助，提供了全面的监控能力。

## 示例脚本 (examples/usage_example.js)

示例脚本展示如何针对特定场景使用本框架。

**示例内容**:
- 监控特定类的所有加密方法
- 过滤特定域名的网络请求
- 提取SharedPreferences中的密钥
- 绕过特定的签名检测
- 提取JWT令牌并解析

**使用方法**:
```bash
# 运行示例脚本
frida -U -f com.example.app -l examples/usage_example.js --no-pause
```

## 高级用法

### 选择性加载模块

在`frida_master.js`中的`loadModules()`函数中注释不需要的模块：

```javascript
function loadModules() {
    require('./modules/crypto_monitor.js')(config, logger, utils);
    require('./modules/network_monitor.js')(config, logger, utils);
    // require('./modules/anti_debug.js')(config, logger, utils);  // 注释不需要的模块
}
```

### 自定义过滤器

```javascript
// 添加网络过滤器
var networkModule = require('./modules/network_monitor.js')(config, logger, utils);
networkModule.addUrlFilter("api.example.com");
networkModule.addContentTypeFilter("application/json");

// 添加加密过滤器
var cryptoModule = require('./modules/crypto_monitor.js')(config, logger, utils);
cryptoModule.setAlgorithmFilter(["AES", "RSA"]); // 只监控这些算法
```

### 获取提取的数据

```bash
# 将提取的密钥从设备拉取到电脑
adb pull /sdcard/frida_extracted_keys.json

# 将日志文件拉取到电脑
adb pull /sdcard/frida_log.txt
```

## 常见问题

- **应用崩溃**: 尝试禁用反调试绕过或减少Hook数量
  ```javascript
  var config = {
      bypassAllDetection: false,  // 禁用所有绕过功能
      // 其他配置...
  };
  ```
  
- **加密操作未捕获**: 可能是使用了Native层加密或自定义加密库
  - 解决方案: 使用backup目录中的hook_native_function.js针对特定原生函数进行Hook

- **日志过于冗长**: 调整日志级别或过滤特定类型的日志
  ```javascript
  var config = {
      logLevel: 'warn',  // 只显示警告和错误
      // 其他配置...
  };
  ```

- **Framework扩展**: 创建遵循同样结构的新模块文件
  ```javascript
  module.exports = function(config, logger, utils) {
      // 实现自定义功能...
      return {
          // 导出API...
      };
  };
  ```

## 免责声明

本框架仅用于安全研究和授权测试目的。使用前请确保您有合法权限测试目标应用。对于任何滥用导致的问题，作者不承担责任。 