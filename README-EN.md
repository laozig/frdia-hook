# Frida Usage Guide

[English](README-EN.md) | [简体中文](README.md) | [Code Details](CODE-DETAILS.md)

## Overview

Frida is a dynamic instrumentation tool based on Python and JavaScript, capable of injecting code at runtime, hooking functions, monitoring and modifying application behavior. This guide provides comprehensive documentation for Frida, helping you master this powerful tool from beginner to expert.

**Main Features:**
- Function hooking and modification
- Memory reading and writing
- Method call stack tracing
- Dynamic program behavior modification
- Script injection and remote debugging
- Native library analysis

## Table of Contents

1. [Installation and Environment Setup](#installation-and-environment-setup)
2. [Basic Concepts](#basic-concepts)
3. [Command Line Tools](#command-line-tools)
4. [JavaScript API](#javascript-api)
5. [Hook Techniques](docs/hook_techniques.md)
6. [Memory Operations Guide](docs/memory_operations.md)
7. [Interception and Tracing](docs/interception_tracing.md)
8. [Remote Operations](docs/remote_operations.md)
9. [Advanced Techniques](docs/advanced_techniques.md)
10. [Troubleshooting](docs/troubleshooting.md)
11. [Case Studies](docs/case_studies.md)
12. [Complete API Reference](docs/api_reference.md)
13. [Code Detailed Explanation](CODE-DETAILS.md)

## Installation and Environment Setup

### Installing Frida

```bash
# Install Frida CLI and Python bindings
pip install frida-tools frida

# Verify installation
frida --version
```

### Setting Up Android Device

1. **Enable Developer Options and USB Debugging**:
   - Go to Settings > About phone > Tap "Build number" 7 times
   - Return to Settings > Developer options > Enable USB debugging
   - For root functionality, ensure your device is properly rooted

2. **Install Frida Server**:
```bash
   # Check device architecture
   adb shell getprop ro.product.cpu.abi
   
   # Download the corresponding version of frida-server
   # https://github.com/frida/frida/releases

   # Push the server to the device
   adb push frida-server /data/local/tmp/
   adb shell "chmod 755 /data/local/tmp/frida-server"
   
   # Start Frida service
   adb shell "/data/local/tmp/frida-server &"
   
   # Start on rooted device (recommended)
   adb shell "su -c '/data/local/tmp/frida-server &'"
   ```

3. **Verify Connection**:
```bash
   # List processes on the device
   frida-ps -U
   
   # Find specific application
   frida-ps -Ua | grep target_app_name
   ```

### Setting Up iOS Device

1. **Jailbroken Device**:
   ```bash
   # Install Frida via Cydia
   # Add source: https://build.frida.re
   # Install package: Frida
   
   # Or install via SSH
   ssh root@<device_IP> "dpkg -i frida_<version>_iphoneos-arm.deb"
   
   # Start Frida service
   ssh root@<device_IP> "/usr/bin/frida-server &"
   ```

2. **Non-Jailbroken Device**:
   - Use signed IPA package with Frida injected
   - Can use tools like frida-ios-dump

## Basic Concepts

### How It Works

Frida workflow:

1. **Injection**: Inject Frida service (frida-server) into the target process
2. **Script Execution**: Load and execute JavaScript scripts
3. **Message Communication**: Establish communication channel between host and target process
4. **Real-time Operation**: Dynamically monitor and modify target program behavior

### Core Components

- **frida-server**: Service component running on the target device
- **frida-tools**: Command line toolkit
- **frida-core**: Core library responsible for injection and communication
- **frida-gum**: JavaScript bindings providing low-level API access

## Command Line Tools

### Basic Command Format

```bash
# Inject into newly launched application
frida -U -f com.example.app -l script_file_path [--no-pause]

# Attach to running application
frida -U -p process_ID -l script_file_path

# Attach to running application (using name)
frida -U -n "App Name" -l script_file_path
```

### Common Parameters

| Parameter | Description | Example |
|-----|------|-----|
| `-U` | Use USB connected device | `frida -U` |
| `-f` | Specify application package name to launch | `frida -f com.example.app` |
| `-p` | Specify process ID | `frida -p 1234` |
| `-n` | Specify process name | `frida -n "WeChat"` |
| `-l` | Load JavaScript script | `frida -l script.js` |
| `-e` | Execute one line of JavaScript code | `frida -e "console.log('Hello')"` |
| `-q` | Quiet mode | `frida -q` |
| `--no-pause` | Don't pause application execution after injection | `frida --no-pause` |
| `-o` | Output logs to file | `frida -o log.txt` |
| `--runtime` | Specify JavaScript runtime | `frida --runtime=v8` |
| `-R` | Reattach after process restart | `frida -R` |

### Common Tool Commands

```bash
# List processes on device
frida-ps -U

# List only application processes
frida-ps -Ua

# Generate trace information
frida-trace -U -i "function_name" target_app

# Trace functions in specific library
frida-trace -U -I "libc.so" target_app

# List connected devices
frida-ls-devices
```

## JavaScript API

### Basic API

```javascript
// Initialize Frida session
Java.perform(function() {
    // Java class operation
    var MainActivity = Java.use("com.example.app.MainActivity");
    
    // Hook method
    MainActivity.onCreate.overload("android.os.Bundle").implementation = function(bundle) {
        console.log("[*] onCreate called");
        
        // Call original method
        this.onCreate(bundle);
        
        console.log("[*] onCreate completed");
    };
});
```

### Java Layer Operations

```javascript
// Get Java class
var MyClass = Java.use("com.example.app.MyClass");

// Call static method
var result = MyClass.staticMethod();

// Create instance
var instance = MyClass.$new();

// Call instance method
instance.instanceMethod();

// Access field
instance.field.value = 123;

// Get class loader
var classLoader = Java.classFactory.loader;

// Load class using class loader
var CustomClass = Java.classFactory.use("com.example.CustomClass");

// Handle overloaded methods
MyClass.overloadedMethod.overload("java.lang.String").implementation = function(str) {
    console.log("Parameter: " + str);
    return this.overloadedMethod(str);
};
```

### Native Layer Operations

```javascript
// Get function address by symbol name
var funcPtr = Module.findExportByName("libc.so", "open");

// Create NativeFunction object
var open = new NativeFunction(funcPtr, 'int', ['pointer', 'int']);

// Intercept Native function
Interceptor.attach(funcPtr, {
    onEnter: function(args) {
        console.log("[*] open called");
        console.log("[*] File path: " + args[0].readUtf8String());
    },
    onLeave: function(retval) {
        console.log("[*] Return value: " + retval);
        
        // Modify return value
        // retval.replace(0);
    }
});

// Memory operations
var addr = Module.findBaseAddress("libexample.so").add(0x1234);
console.log(Memory.readByteArray(addr, 10));
Memory.writeByteArray(addr, [0x90, 0x90, 0x90]);
```

## More Resources

Please check the documents in the directory for more detailed information about advanced usage, API references, and case studies.

- [Hook Techniques](docs/hook_techniques.md)
- [Memory Operations Guide](docs/memory_operations.md)
- [Interception and Tracing](docs/interception_tracing.md)
- [Remote Operations](docs/remote_operations.md)
- [Advanced Techniques](docs/advanced_techniques.md)
- [Complete API Reference](docs/api_reference.md)
- [Code Detailed Explanation](CODE-DETAILS.md) - Provides detailed explanations and usage scenarios for all example code

## Contribution and Feedback

If you have suggestions for improvements or find errors in the documentation, please submit an Issue or Pull Request.

## License

This document is released under the MIT license. 