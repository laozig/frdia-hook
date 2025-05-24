# Frida 中文使用指南

[English](README-EN.md) | [简体中文](README.md) | [代码详解](CODE-DETAILS.md)

## 概述

Frida 是一款基于 Python 和 JavaScript 的动态插桩工具，能够在运行时注入代码，挂钩函数，监控和修改应用行为。本指南提供全面的 Frida 使用文档，帮助你从入门到精通这一强大工具。

**主要功能：**
- 函数 Hook（劫持）和修改
- 内存读写与修改
- 方法调用栈追踪
- 动态修改程序行为
- 脚本注入和远程调试
- 原生库（Native库）分析

## 目录

1. [安装与环境配置](#安装与环境配置)
2. [基本概念](#基本概念)
3. [命令行工具](#命令行工具)
4. [JavaScript API](#javascript-api)
5. [Hook技术详解](docs/hook_techniques.md)
6. [内存操作指南](docs/memory_operations.md)
7. [拦截与跟踪](docs/interception_tracing.md)
8. [远程操作](docs/remote_operations.md)
9. [高级技巧](docs/advanced_techniques.md)
10. [常见问题解决](docs/troubleshooting.md)
11. [实际案例分析](docs/case_studies.md)
12. [完整API参考](docs/api_reference.md)
13. [代码详细解释](CODE-DETAILS.md)

## 安装与环境配置

### 安装Frida

```bash
# 安装Frida CLI和Python绑定
pip install frida-tools frida

# 验证安装
frida --version
```

### 设置Android设备

1. **启用开发者选项和USB调试**:
   - 进入设置 > 关于手机 > 连续点击"版本号"7次
   - 返回设置 > 开发者选项 > 启用USB调试
   - 如需root功能，请确保设备已正确root

2. **安装Frida服务端**:
```bash
   # 查看设备架构
   adb shell getprop ro.product.cpu.abi
   
   # 下载对应版本的frida-server
   # https://github.com/frida/frida/releases

   # 将服务端推送到设备
   adb push frida-server /data/local/tmp/
   adb shell "chmod 755 /data/local/tmp/frida-server"
   
   # 启动Frida服务
   adb shell "/data/local/tmp/frida-server &"
   
   # root设备启动（推荐）
   adb shell "su -c '/data/local/tmp/frida-server &'"
   ```

3. **验证连接**:
```bash
   # 列出设备上的进程
   frida-ps -U
   
   # 查找特定应用
   frida-ps -Ua | grep 目标应用名
   ```

### 设置iOS设备

1. **越狱设备**:
```bash
   # 通过Cydia安装Frida
   # 添加源：https://build.frida.re
   # 安装包：Frida
   
   # 或通过SSH安装
   ssh root@<设备IP> "dpkg -i frida_<版本>_iphoneos-arm.deb"
   
   # 启动Frida服务
   ssh root@<设备IP> "/usr/bin/frida-server &"
   ```

2. **非越狱设备**:
   - 使用签名的IPA包注入Frida
   - 可以使用frida-ios-dump等工具

## 基本概念

### 工作原理

Frida的工作流程：

1. **注入**: 将Frida服务（frida-server）注入目标进程
2. **脚本执行**: 加载并执行JavaScript脚本
3. **消息通信**: 在主机与目标进程之间建立通信通道
4. **实时操作**: 动态监控和修改目标程序的行为

### 核心组件

- **frida-server**: 在目标设备上运行的服务组件
- **frida-tools**: 命令行工具集
- **frida-core**: 核心库，负责注入和通信
- **frida-gum**: JavaScript绑定，提供底层API访问

## 命令行工具

### 基本命令格式

```bash
# 注入新启动的应用
frida -U -f 应用包名 -l 脚本文件路径 [--no-pause]

# 附加到运行中的应用
frida -U -p 进程ID -l 脚本文件路径

# 附加到运行中的应用（使用名称）
frida -U -n "应用名称" -l 脚本文件路径
```

### 常用参数说明

| 参数 | 说明 | 示例 |
|-----|------|-----|
| `-U` | 使用USB连接的设备 | `frida -U` |
| `-f` | 指定启动的应用包名 | `frida -f com.example.app` |
| `-p` | 指定进程ID | `frida -p 1234` |
| `-n` | 指定进程名称 | `frida -n "微信"` |
| `-l` | 加载JavaScript脚本 | `frida -l script.js` |
| `-e` | 执行一行JavaScript代码 | `frida -e "console.log('Hello')"` |
| `-q` | 静默模式 | `frida -q` |
| `--no-pause` | 注入后不暂停应用执行 | `frida --no-pause` |
| `-o` | 输出日志到文件 | `frida -o log.txt` |
| `--runtime` | 指定JavaScript运行时 | `frida --runtime=v8` |
| `-R` | 进程重启后重新附加 | `frida -R` |

### 常用工具命令

```bash
# 列出设备上的进程
frida-ps -U

# 只列出应用进程
frida-ps -Ua

# 生成跟踪信息
frida-trace -U -i "函数名" 目标应用

# 跟踪特定库中的函数
frida-trace -U -I "libc.so" 目标应用

# 列出连接的设备
frida-ls-devices
```

## JavaScript API

### 基础 API

```javascript
// 初始化Frida会话
Java.perform(function() {
    // Java类操作
    var MainActivity = Java.use("com.example.app.MainActivity");
    
    // Hook方法
    MainActivity.onCreate.overload("android.os.Bundle").implementation = function(bundle) {
        console.log("[*] onCreate 被调用");
        
        // 调用原始方法
        this.onCreate(bundle);
        
        console.log("[*] onCreate 执行完毕");
    };
});
```

### Java 层操作

```javascript
// 获取Java类
var MyClass = Java.use("com.example.app.MyClass");

// 调用静态方法
var result = MyClass.staticMethod();

// 创建实例
var instance = MyClass.$new();

// 调用实例方法
instance.instanceMethod();

// 访问字段
instance.field.value = 123;

// 获取类加载器
var classLoader = Java.classFactory.loader;

// 使用类加载器加载类
var CustomClass = Java.classFactory.use("com.example.CustomClass");

// 处理重载方法
MyClass.overloadedMethod.overload("java.lang.String").implementation = function(str) {
    console.log("参数: " + str);
    return this.overloadedMethod(str);
};
```

### Native 层操作

```javascript
// 通过符号名获取函数地址
var funcPtr = Module.findExportByName("libc.so", "open");

// 创建NativeFunction对象
var open = new NativeFunction(funcPtr, 'int', ['pointer', 'int']);

// 拦截Native函数
Interceptor.attach(funcPtr, {
    onEnter: function(args) {
        console.log("[*] open被调用");
        console.log("[*] 文件路径: " + args[0].readUtf8String());
    },
    onLeave: function(retval) {
        console.log("[*] 返回值: " + retval);
        
        // 修改返回值
        // retval.replace(0);
    }
});

// 内存读写操作
var addr = Module.findBaseAddress("libexample.so").add(0x1234);
console.log(Memory.readByteArray(addr, 10));
Memory.writeByteArray(addr, [0x90, 0x90, 0x90]);
```

## 更多资源

请查看目录中的详细文档，了解更多关于Frida的高级用法、API参考和实际案例分析。

- [Hook技术详解](docs/hook_techniques.md)
- [内存操作指南](docs/memory_operations.md)
- [拦截与跟踪](docs/interception_tracing.md)
- [远程操作](docs/remote_operations.md)
- [高级技巧](docs/advanced_techniques.md)
- [完整API参考](docs/api_reference.md)
- [代码详细解释](CODE-DETAILS.md) - 提供所有示例代码的详细解释和使用场景

### Frida Hook 脚本大全

本项目包含了一系列实用的 Frida Hook 脚本，可以帮助你快速开始 Android 应用分析：

1. **[基础API拦截](frida_hooks/基础API拦截.js)** - 拦截常见的Android API调用
2. **[SSL证书绕过](frida_hooks/SSL证书绕过.js)** - 绕过SSL证书验证，方便抓包分析HTTPS流量
3. **[反调试检测绕过](frida_hooks/反调试检测绕过.js)** - 绕过应用中的反调试检测机制
4. **[加密解密函数Hook](frida_hooks/加密解密函数Hook.js)** - 拦截常见的加密解密函数，获取明文数据
5. **[网络请求拦截](frida_hooks/网络请求拦截.js)** - 拦截HTTP/HTTPS网络请求和响应
6. **[文件操作拦截](frida_hooks/文件操作拦截.js)** - 监控文件读写、删除等操作
7. **[WebView注入](frida_hooks/WebView注入.js)** - 向WebView注入JavaScript代码
8. **[界面元素监控](frida_hooks/界面元素监控.js)** - 监控和修改界面元素属性和事件
9. **[SQLite数据库操作拦截](frida_hooks/SQLite数据库操作拦截.js)** - 监控数据库查询和修改操作
10. **[SharedPreferences操作拦截](frida_hooks/SharedPreferences操作拦截.js)** - 监控配置文件的读写操作
11. **[动态加载监控](frida_hooks/动态加载监控.js)** - 监控动态加载的类和资源
12. **[JNI函数调用监控](frida_hooks/JNI函数调用监控.js)** - 监控Java与Native层之间的调用
13. **[系统属性获取拦截](frida_hooks/系统属性获取拦截.js)** - 拦截系统属性的读取操作
14. **[定位信息模拟](frida_hooks/定位信息模拟.js)** - 模拟GPS定位信息
15. **[相机操作拦截](frida_hooks/相机操作拦截.js)** - 监控相机相关API调用
16. **[Root检测绕过](frida_hooks/Root检测绕过.js)** - 绕过应用的Root检测机制
17. **[Native层函数追踪](frida_hooks/Native层函数追踪.js)** - 追踪Native层函数的调用
18. **[内存搜索修改](frida_hooks/内存搜索修改.js)** - 在内存中搜索和修改特定值
19. **[应用保护机制绕过](frida_hooks/应用保护机制绕过.js)** - 绕过各种应用保护机制
20. **[应用启动流程监控](frida_hooks/应用启动流程监控.js)** - 监控应用启动过程和性能

### 使用方法

1. 确保已正确安装Frida并启动frida-server
2. 连接到目标设备
3. 使用以下命令注入脚本：

```bash
# 附加到运行中的应用
frida -U -l frida_hooks/脚本名称.js -n "应用名称" 

# 或使用包名启动应用
frida -U -l frida_hooks/脚本名称.js -f 应用包名 --no-pause
```

4. 观察控制台输出的信息

### 贡献

欢迎提交Pull Request来完善这个项目。如果你有好的脚本想要分享，请遵循以下格式：
1. 添加详细的注释说明功能和使用方法
2. 确保脚本经过测试且能正常工作
3. 更新README.md添加你的脚本信息

### 免责声明

本项目仅供安全研究和教育目的使用。使用这些脚本分析未经授权的应用可能违反法律法规。请确保在合法的情况下使用这些工具。

## 贡献与反馈

如果您有改进建议或发现文档中的错误，请提交Issue或Pull Request。

## 许可

本文档采用 MIT 许可证发布。