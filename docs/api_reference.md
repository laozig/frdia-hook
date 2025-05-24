# Frida API 参考文档

本文档提供了Frida主要API的中文参考，帮助开发者快速查找和使用Frida的核心功能。

## 目录

1. [JavaScript API](#javascript-api)
   - [Frida](#frida)
   - [Process](#process)
   - [Module](#module)
   - [Memory](#memory)
   - [Interceptor](#interceptor)
   - [Stalker](#stalker)
   - [Java](#java)
   - [ObjC](#objc)
   - [NativeFunction](#nativefunction)
   - [NativeCallback](#nativecallback)
   - [File](#file)
   - [Socket](#socket)
   - [Thread](#thread)
   - [DebugSymbol](#debugsymbol)
   - [Instruction](#instruction)
   - [CModule](#cmodule)
2. [Python API](#python-api)
   - [frida](#frida模块)
   - [frida.core](#fridacore模块)
   - [frida.device](#fridadevice类)
   - [frida.session](#fridasession类)
   - [frida.script](#fridascript类)
3. [命令行工具](#命令行工具)
   - [frida](#frida命令)
   - [frida-ps](#frida-ps命令)
   - [frida-trace](#frida-trace命令)
   - [frida-discover](#frida-discover命令)
   - [frida-ls-devices](#frida-ls-devices命令)

## JavaScript API

Frida的JavaScript API是编写注入脚本的核心工具集。

### Frida

全局Frida对象提供了与Frida运行时交互的功能。

```javascript
// 获取Frida版本
console.log(Frida.version);

// 脚本通信
recv('message', function(message) {
    console.log('收到消息:', message);
    send({response: '已收到消息'});
});

// 获取当前进程
var currentProcess = Process.id;
console.log('当前进程ID:', currentProcess);

// 获取当前线程
var currentThread = Process.getCurrentThreadId();
console.log('当前线程ID:', currentThread);

// 设置崩溃处理
Process.setExceptionHandler(function(exception) {
    console.log('捕获到异常:', JSON.stringify(exception));
    return true;  // 返回true继续执行
});
```

### Process

Process对象提供了与当前进程交互的功能。

```javascript
// 获取进程ID
console.log('进程ID:', Process.id);

// 获取进程架构
console.log('进程架构:', Process.arch);

// 获取进程平台
console.log('进程平台:', Process.platform);

// 获取进程页面保护
var ranges = Process.enumerateRanges('r--');
console.log('可读内存区域数量:', ranges.length);

// 查找内存区域
var libc = Process.findRangeByAddress(Module.findBaseAddress('libc.so'));
console.log('libc内存区域:', JSON.stringify(libc));

// 获取当前线程ID
console.log('当前线程ID:', Process.getCurrentThreadId());

// 枚举线程
var threads = Process.enumerateThreads();
console.log('线程数量:', threads.length);

// 调试符号相关
Process.setExceptionHandler(function(details) {
    console.log('异常:', JSON.stringify(details));
    return true;
});

// 判断是否调试状态
console.log('是否调试状态:', Process.isDebuggerAttached());
```

### Module

Module对象用于与加载的模块（如共享库）交互。

```javascript
// 枚举所有已加载模块
var modules = Process.enumerateModules();
console.log('加载的模块数量:', modules.length);

// 查找特定模块
var mainModule = Process.getModuleByName('app_process');
console.log('主模块:', JSON.stringify(mainModule));

// 获取模块基址
var baseAddress = Module.findBaseAddress('libc.so');
console.log('libc基址:', baseAddress);

// 查找导出函数
var open = Module.findExportByName('libc.so', 'open');
console.log('open函数地址:', open);

// 枚举模块导出
var exports = Module.enumerateExports('libc.so');
console.log('libc导出函数数量:', exports.length);

// 枚举模块导入
var imports = Module.enumerateImports('target.so');
console.log('目标模块导入函数数量:', imports.length);

// 枚举模块符号
var symbols = Module.enumerateSymbols('libc.so');
console.log('libc符号数量:', symbols.length);

// 加载新模块
Module.load('libextra.so');
```

### Memory

Memory对象提供了内存读写和分配的功能。

```javascript
// 分配内存
var ptr = Memory.alloc(1024);
console.log('分配的内存地址:', ptr);

// 写入数据
Memory.writeByteArray(ptr, [0x41, 0x42, 0x43, 0x44]);
Memory.writeUtf8String(ptr.add(4), "Hello Frida");
Memory.writeS8(ptr.add(16), -42);
Memory.writeU8(ptr.add(17), 42);
Memory.writeS16(ptr.add(18), -12345);
Memory.writeU16(ptr.add(20), 12345);
Memory.writeS32(ptr.add(22), -1234567890);
Memory.writeU32(ptr.add(26), 1234567890);
Memory.writeS64(ptr.add(30), "-1234567890123456789");
Memory.writeU64(ptr.add(38), "1234567890123456789");
Memory.writeFloat(ptr.add(46), 123.456);
Memory.writeDouble(ptr.add(50), 123.456789);
Memory.writePointer(ptr.add(58), ptr);

// 读取数据
var bytes = Memory.readByteArray(ptr, 4);
console.log('读取的字节:', bytes);
var str = Memory.readUtf8String(ptr.add(4));
console.log('读取的字符串:', str);
var s8 = Memory.readS8(ptr.add(16));
console.log('读取的S8:', s8);
var u8 = Memory.readU8(ptr.add(17));
console.log('读取的U8:', u8);
var s16 = Memory.readS16(ptr.add(18));
console.log('读取的S16:', s16);
var u16 = Memory.readU16(ptr.add(20));
console.log('读取的U16:', u16);
var s32 = Memory.readS32(ptr.add(22));
console.log('读取的S32:', s32);
var u32 = Memory.readU32(ptr.add(26));
console.log('读取的U32:', u32);
var s64 = Memory.readS64(ptr.add(30));
console.log('读取的S64:', s64);
var u64 = Memory.readU64(ptr.add(38));
console.log('读取的U64:', u64);
var float = Memory.readFloat(ptr.add(46));
console.log('读取的Float:', float);
var double = Memory.readDouble(ptr.add(50));
console.log('读取的Double:', double);
var pointer = Memory.readPointer(ptr.add(58));
console.log('读取的指针:', pointer);

// 保护内存区域
Memory.protect(ptr, 1024, 'rw-');

// 扫描内存
Memory.scan(ptr, 1024, '41 42 43 44', {
    onMatch: function(address, size) {
        console.log('找到匹配:', address);
    },
    onComplete: function() {
        console.log('扫描完成');
    }
});

// 复制内存
var dst = Memory.alloc(1024);
Memory.copy(dst, ptr, 64);

// 释放内存
// Frida自动管理内存，但可以显式释放
// ptr = null; // 允许垃圾回收
```

### Interceptor

Interceptor对象用于拦截函数调用。

```javascript
// 拦截函数
var open = Module.findExportByName(null, 'open');
Interceptor.attach(open, {
    onEnter: function(args) {
        var path = args[0].readUtf8String();
        console.log('open():', path);
        
        // 保存上下文数据
        this.path = path;
    },
    onLeave: function(retval) {
        console.log('open()返回:', retval);
        
        // 可以访问onEnter中保存的数据
        console.log('打开的文件:', this.path);
        
        // 修改返回值
        if (this.path.indexOf('/sensitive/') !== -1) {
            retval.replace(-1); // 返回错误
        }
    }
});

// 替换函数
var access = Module.findExportByName(null, 'access');
Interceptor.replace(access, new NativeCallback(function(path, mode) {
    var pathStr = path.readUtf8String();
    console.log('access():', pathStr, mode);
    
    // 自定义实现
    if (pathStr.indexOf('/forbidden/') !== -1) {
        return -1; // 拒绝访问
    }
    
    // 调用原始函数
    return access(path, mode);
}, 'int', ['pointer', 'int']));

// 恢复原始函数
Interceptor.revert(access);

// 刷新指令缓存
Interceptor.flush();
```

### Stalker

Stalker对象提供了指令级跟踪功能。

```javascript
// 基本跟踪
Stalker.follow(Process.getCurrentThreadId(), {
    events: {
        call: true,  // 跟踪调用指令
        ret: true,   // 跟踪返回指令
        exec: false  // 不跟踪每条指令
    },
    onReceive: function(events) {
        // 处理跟踪事件
        console.log('收到 ' + events.length + ' 个事件');
    }
});

// 停止跟踪
Stalker.unfollow();

// 包含特定功能的跟踪
Stalker.follow(Process.getCurrentThreadId(), {
    transform: function(iterator) {
        var instruction;
        
        while ((instruction = iterator.next()) !== null) {
            iterator.keep();
            
            // 如果是调用指令
            if (instruction.mnemonic === 'call') {
                // 输出目标地址
                console.log('调用: ' + instruction.address + ' -> ' + instruction.operands[0].value);
            }
        }
    }
});

// 垃圾回收
Stalker.garbageCollect();

// 排除特定范围
Stalker.exclude({
    base: Module.findBaseAddress('libsystem.so'),
    size: 1024 * 1024 // 排除1MB
});
```

### Java

Java对象提供了与Java运行时交互的功能。

```javascript
// 基本用法
Java.perform(function() {
    // 所有与Java交互的代码都在这里
    
    // 获取Java类
    var Activity = Java.use('android.app.Activity');
    var Exception = Java.use('java.lang.Exception');
    
    // Hook方法
    Activity.onCreate.implementation = function(bundle) {
        console.log('Activity.onCreate() 被调用');
        
        // 调用原始方法
        this.onCreate(bundle);
        
        console.log('Activity.onCreate() 执行完毕');
    };
    
    // 调用静态方法
    var System = Java.use('java.lang.System');
    var currentTime = System.currentTimeMillis();
    console.log('当前时间:', currentTime);
    
    // 创建Java对象
    var HashMap = Java.use('java.util.HashMap');
    var map = HashMap.$new();
    map.put('key', 'value');
    console.log('Map内容:', map.toString());
    
    // 处理异常
    try {
        Java.use('non.existent.Class');
    } catch (e) {
        console.log('捕获到异常:', e);
    }
});

// 枚举加载的类
Java.perform(function() {
    Java.enumerateLoadedClasses({
        onMatch: function(className) {
            if (className.includes('crypto')) {
                console.log('找到加密相关类:', className);
            }
        },
        onComplete: function() {
            console.log('类枚举完成');
        }
    });
});

// 查找实例
Java.perform(function() {
    Java.choose('android.app.Activity', {
        onMatch: function(instance) {
            console.log('找到Activity实例:', instance);
            console.log('  类名:', instance.getClass().getName());
            console.log('  标题:', instance.getTitle());
        },
        onComplete: function() {
            console.log('实例搜索完成');
        }
    });
});

// 使用不同的ClassLoader
Java.perform(function() {
    Java.enumerateClassLoaders({
        onMatch: function(loader) {
            try {
                var classFactory = Java.ClassFactory.get(loader);
                var Activity = classFactory.use('android.app.Activity');
                console.log('在ClassLoader中找到Activity类:', loader);
            } catch (e) {
                // 在此ClassLoader中未找到类
            }
        },
        onComplete: function() {}
    });
});
```

### ObjC

ObjC对象提供了与Objective-C运行时交互的功能。

```javascript
// 基本用法
if (ObjC.available) {
    // 获取Objective-C类
    var UIApplication = ObjC.classes.UIApplication;
    var NSString = ObjC.classes.NSString;
    
    // 访问共享实例
    var app = UIApplication.sharedApplication();
    console.log('应用状态:', app.applicationState());
    
    // 创建字符串
    var str = NSString.stringWithString_("Hello Frida");
    console.log('字符串长度:', str.length());
    
    // 调用方法
    var upperStr = str.uppercaseString();
    console.log('大写字符串:', upperStr.toString());
    
    // 访问实例变量
    var delegate = app.delegate();
    var window = delegate.window();
    console.log('窗口:', window);
    
    // Hook方法
    Interceptor.attach(UIApplication["- sendAction:to:from:forEvent:"].implementation, {
        onEnter: function(args) {
            // args[0]是self
            // args[1]是selector
            // args[2]是action
            // args[3]是target
            // args[4]是sender
            // args[5]是event
            
            var action = ObjC.selectorAsString(args[2]);
            var target = new ObjC.Object(args[3]);
            var sender = new ObjC.Object(args[4]);
            
            console.log('Action:', action);
            console.log('Target:', target.$className);
            console.log('Sender:', sender.$className);
        }
    });
} else {
    console.log('Objective-C运行时不可用');
}

// 枚举所有类
if (ObjC.available) {
    var classList = Object.keys(ObjC.classes);
    for (var i = 0; i < classList.length; i++) {
        if (classList[i].includes('Security')) {
            console.log('找到安全相关类:', classList[i]);
        }
    }
}

// 查找实例
if (ObjC.available) {
    ObjC.choose(ObjC.classes.UIViewController, {
        onMatch: function(instance) {
            console.log('找到视图控制器:', instance.$className);
            console.log('  标题:', instance.title().toString());
        },
        onComplete: function() {
            console.log('实例搜索完成');
        }
    });
}
```

### NativeFunction

NativeFunction用于创建可调用的本地函数接口。

```javascript
// 创建函数接口
var open = new NativeFunction(Module.findExportByName(null, 'open'), 
                              'int', ['pointer', 'int']);

// 调用函数
var path = Memory.allocUtf8String('/etc/hosts');
var fd = open(path, 0); // O_RDONLY
console.log('文件描述符:', fd);

// 处理errno
var errno = Module.findExportByName(null, '__errno_location');
var errnoPtr = new NativeFunction(errno, 'pointer', [])();
var err = Memory.readS32(errnoPtr);
console.log('错误码:', err);

// 创建更复杂的函数接口
var connect = new NativeFunction(Module.findExportByName(null, 'connect'),
                                'int', ['int', 'pointer', 'int']);

// 创建sockaddr_in结构
var sockAddr = Memory.alloc(16); // sizeof(struct sockaddr_in)
Memory.writeU16(sockAddr, 2); // AF_INET
Memory.writeU16(sockAddr.add(2), Memory.readU16(ptr(0x5000).add(2))); // 端口 (网络字节序)
Memory.writeU32(sockAddr.add(4), Memory.readU32(ptr(0x5000).add(4))); // IP地址

// 调用connect
var result = connect(fd, sockAddr, 16);
console.log('连接结果:', result);
```

### NativeCallback

NativeCallback用于创建本地回调函数。

```javascript
// 创建回调
var callback = new NativeCallback(function(a, b) {
    console.log('回调被调用，参数:', a, b);
    return a + b;
}, 'int', ['int', 'int']);

// 获取回调地址
var callbackPtr = callback;
console.log('回调地址:', callbackPtr);

// 调用回调
var result = callback(5, 7);
console.log('回调返回值:', result); // 12

// 使用回调替换函数
var access = Module.findExportByName(null, 'access');
Interceptor.replace(access, new NativeCallback(function(path, mode) {
    var pathStr = path.readUtf8String();
    console.log('access():', pathStr, mode);
    
    // 自定义实现
    if (pathStr.indexOf('/forbidden/') !== -1) {
        return -1; // 拒绝访问
    }
    
    // 调用原始函数
    return new NativeFunction(access, 'int', ['pointer', 'int'])(path, mode);
}, 'int', ['pointer', 'int']));
```

### File

File对象提供了文件操作功能。

```javascript
// 写入文件
var file = new File('/data/local/tmp/frida-output.txt', 'w');
file.write('Hello Frida\n');
file.write('这是第二行\n');
file.flush();
file.close();

// 读取文件
var readFile = new File('/data/local/tmp/frida-output.txt', 'r');
var content = '';
var buf = new ArrayBuffer(1024);
var bytesRead = 0;

while ((bytesRead = readFile.read(buf)) > 0) {
    // 转换为字符串
    content += String.fromCharCode.apply(null, new Uint8Array(buf, 0, bytesRead));
}

console.log('文件内容:', content);
readFile.close();

// 检查文件是否存在
var checkFile = function(path) {
    try {
        new File(path, 'r').close();
        return true;
    } catch (e) {
        return false;
    }
};

console.log('文件存在:', checkFile('/data/local/tmp/frida-output.txt'));
console.log('文件存在:', checkFile('/non/existent/file'));
```

### Socket

Socket对象提供了网络通信功能。

```javascript
// 创建TCP客户端
var socket = new Socket('tcp');
var connected = socket.connect({
    host: '127.0.0.1',
    port: 8080
});

if (connected) {
    console.log('连接成功');
    
    // 发送数据
    socket.write('Hello from Frida\n');
    
    // 读取响应
    var response = socket.read(1024);
    console.log('收到响应:', response.readUtf8String());
    
    // 关闭连接
    socket.close();
} else {
    console.log('连接失败');
}

// 创建TCP服务器
var server = new Socket('tcp');

server.bind('127.0.0.1', 9090);
server.listen();
console.log('服务器监听在127.0.0.1:9090');

// 处理连接
var clientSocket = server.accept();
console.log('接受连接:', clientSocket.peerAddress, clientSocket.peerPort);

// 读取客户端数据
var clientData = clientSocket.read(1024);
console.log('收到客户端数据:', clientData.readUtf8String());

// 发送响应
clientSocket.write('服务器响应\n');

// 关闭连接
clientSocket.close();
server.close();
```

### Thread

Thread对象提供了线程操作功能。

```javascript
// 创建新线程
var thread = Process.spawn(function() {
    console.log('新线程开始运行');
    Thread.sleep(1);
    console.log('新线程继续运行');
    return 42;
});

// 等待线程完成
var result = thread.join();
console.log('线程返回值:', result);

// 获取当前线程ID
var currentThreadId = Process.getCurrentThreadId();
console.log('当前线程ID:', currentThreadId);

// 枚举所有线程
var threads = Process.enumerateThreads();
console.log('线程数量:', threads.length);
threads.forEach(function(thread) {
    console.log('线程ID:', thread.id);
    console.log('  状态:', thread.state);
    console.log('  上下文:', JSON.stringify(thread.context));
});

// 休眠当前线程
console.log('休眠前');
Thread.sleep(0.5); // 休眠0.5秒
console.log('休眠后');

// 获取调用栈
var backtrace = Thread.backtrace(Process.getCurrentThreadId(), Backtracer.ACCURATE);
console.log('调用栈:', backtrace.map(DebugSymbol.fromAddress).join('\n'));
```

## Python API

Frida的Python API用于构建工具和自动化Frida操作。

### frida模块

frida模块是Python API的入口点。

```python
import frida
import sys

# 获取本地设备
device = frida.get_local_device()

# 枚举进程
processes = device.enumerate_processes()
for process in processes:
    print(f"PID: {process.pid}, 名称: {process.name}")

# 附加到进程
session = device.attach("com.example.app")

# 创建脚本
script_source = """
Java.perform(function() {
    console.log("Hello from Frida!");
});
"""

script = session.create_script(script_source)

# 设置消息处理函数
def on_message(message, data):
    if message["type"] == "send":
        print("[*] 收到消息:", message["payload"])
    elif message["type"] == "error":
        print("[!] 错误:", message["stack"])

script.on("message", on_message)

# 加载脚本
script.load()

# 等待用户输入
input("[!] 按回车键退出...\n")

# 卸载脚本
script.unload()

# 分离会话
session.detach()
```

### frida.core模块

frida.core模块提供了核心功能。

```python
import frida
from frida.core import Device, Session, Script

# 获取设备管理器
device_manager = frida.get_device_manager()

# 添加远程设备
remote_device = device_manager.add_remote_device("192.168.1.100")

# 生成脚本
script_source = """
Java.perform(function() {
    var Activity = Java.use("android.app.Activity");
    Activity.onCreate.implementation = function(bundle) {
        console.log("Activity.onCreate() 被调用");
        this.onCreate(bundle);
    };
});
"""

# 枚举USB设备
usb_devices = device_manager.enumerate_usb_devices()
for device in usb_devices:
    print(f"USB设备: {device.id}, 名称: {device.name}")

# 监听设备添加事件
def on_device_added(device):
    print(f"设备已添加: {device.id}")

device_manager.on("added", on_device_added)

# 枚举已安装应用
applications = remote_device.enumerate_applications()
for app in applications:
    print(f"应用: {app.identifier}, 名称: {app.name}")
```

### frida.device类

Device类表示Frida可以交互的设备。

```python
import frida
import time

# 获取设备
device = frida.get_usb_device()

# 获取设备信息
print(f"设备ID: {device.id}")
print(f"设备名称: {device.name}")
print(f"设备类型: {device.type}")

# 枚举进程
processes = device.enumerate_processes()
for process in processes:
    print(f"PID: {process.pid}, 名称: {process.name}")

# 枚举应用
applications = device.enumerate_applications()
for app in applications:
    print(f"应用: {app.identifier}, 名称: {app.name}")

# 获取前台应用
frontmost_app = device.get_frontmost_application()
print(f"前台应用: {frontmost_app.identifier}")

# 启动应用
pid = device.spawn("com.example.app")
print(f"已启动应用，PID: {pid}")

# 恢复线程
device.resume(pid)

# 附加到进程
session = device.attach(pid)

# 等待应用启动
time.sleep(1)

# 注入脚本
script = session.create_script("""
Java.perform(function() {
    console.log("应用已启动，注入成功");
});
""")

script.load()

# 等待一段时间
time.sleep(5)

# 杀死进程
device.kill(pid)
```

### frida.session类

Session类表示与进程的会话。

```python
import frida
import time

# 附加到进程
device = frida.get_usb_device()
session = device.attach("com.example.app")

# 获取会话信息
print(f"会话ID: {session.pid}")

# 创建脚本
script = session.create_script("""
Java.perform(function() {
    console.log("Hello from Frida!");
});
""")

# 设置消息处理
def on_message(message, data):
    print("收到消息:", message)

script.on("message", on_message)

# 加载脚本
script.load()

# 列出模块
modules = session.enumerate_modules()
for module in modules:
    print(f"模块: {module.name}, 基址: {hex(module.base_address)}")

# 查找模块导出
exports = session.enumerate_exports("libc.so")
for export in exports:
    print(f"导出: {export.name}, 地址: {hex(export.relative_address)}")

# 查找模块范围
ranges = session.enumerate_ranges("r--")
print(f"可读内存区域数量: {len(ranges)}")

# 等待一段时间
time.sleep(5)

# 分离会话
session.detach()
```

### frida.script类

Script类表示注入到进程的脚本。

```python
import frida
import time

# 创建脚本
device = frida.get_usb_device()
session = device.attach("com.example.app")

script_source = """
var counter = 0;

function countUp() {
    counter++;
    send({type: "counter", value: counter});
    setTimeout(countUp, 1000);
}

countUp();

rpc.exports = {
    add: function(a, b) {
        return a + b;
    },
    sayHello: function(name) {
        return "Hello, " + name;
    }
};
"""

script = session.create_script(script_source)

# 设置消息处理
def on_message(message, data):
    if message["type"] == "send":
        payload = message["payload"]
        if payload["type"] == "counter":
            print(f"计数: {payload['value']}")
    elif message["type"] == "error":
        print(f"错误: {message['stack']}")

script.on("message", on_message)

# 加载脚本
script.load()

# 使用RPC导出
result = script.exports.add(5, 7)
print(f"5 + 7 = {result}")

greeting = script.exports.say_hello("Frida")
print(greeting)

# 发送消息给脚本
script.post({"type": "command", "action": "reset"})

# 等待一段时间
time.sleep(5)

# 卸载脚本
script.unload()
```

## 命令行工具

Frida提供了一系列命令行工具。

### frida命令

frida命令用于交互式探索进程。

```bash
# 基本用法
frida [options] target

# 选项
-h, --help                 显示帮助信息
-d, --device ID            指定设备ID
-U, --usb                  连接到USB设备
-R, --remote               连接到远程设备
-H HOST, --host HOST       连接到远程主机
-f FILE, --file FILE       使用脚本文件
-l SCRIPT, --load SCRIPT   加载脚本
-e CODE, --eval CODE       执行代码
-q                         安静模式
--no-pause                 不暂停目标进程
--runtime NAME             指定运行时 (qjs或v8)
--version                  显示版本信息

# 示例
# 附加到USB设备上的指定进程
frida -U com.android.chrome

# 启动应用并注入
frida -U -f com.example.app --no-pause

# 加载脚本文件
frida -U com.example.app -l script.js

# 执行简单代码
frida -U com.example.app -e "console.log('Hello')"
```

### frida-ps命令

frida-ps命令用于列出进程。

```bash
# 基本用法
frida-ps [options]

# 选项
-h, --help                 显示帮助信息
-d ID, --device ID         指定设备ID
-U, --usb                  连接到USB设备
-R, --remote               连接到远程设备
-H HOST, --host HOST       连接到远程主机
-a, --applications         只显示应用
-i, --installed            显示已安装应用
--version                  显示版本信息

# 示例
# 列出本地进程
frida-ps

# 列出USB设备上的进程
frida-ps -U

# 只列出应用
frida-ps -Ua

# 列出已安装应用
frida-ps -Ui
```

### frida-trace命令

frida-trace命令用于跟踪函数调用。

```bash
# 基本用法
frida-trace [options] target

# 选项
-h, --help                 显示帮助信息
-d ID, --device ID         指定设备ID
-U, --usb                  连接到USB设备
-R, --remote               连接到远程设备
-H HOST, --host HOST       连接到远程主机
-f NAME, --flag NAME       启动应用
-I MODULE, --include-module MODULE    包含模块
-X MODULE, --exclude-module MODULE    排除模块
-i FUNCTION, --include FUNCTION       包含函数
-x FUNCTION, --exclude FUNCTION       排除函数
-a MODULE!OFFSET, --add MODULE!OFFSET 添加地址
-m OBJC_METHOD, --include-objc-method OBJC_METHOD   包含ObjC方法
-M OBJC_METHOD, --exclude-objc-method OBJC_METHOD   排除ObjC方法
-j CLASS, --include-java CLASS        包含Java类
-J METHOD, --include-java-method METHOD   包含Java方法
--debug                               启用调试
--version                             显示版本信息

# 示例
# 跟踪libc中的open函数
frida-trace -U -i "open" com.example.app

# 跟踪多个函数
frida-trace -U -i "open" -i "read" -i "write" com.example.app

# 跟踪Java方法
frida-trace -U -j "java.io.File" com.example.app

# 跟踪特定Java方法
frida-trace -U -J "java.io.File.exists" com.example.app

# 跟踪Objective-C方法
frida-trace -U -m "-[NSData *]" com.example.app
```

### frida-discover命令

frida-discover命令用于发现进程中的类和方法。

```bash
# 基本用法
frida-discover [options] target

# 选项
-h, --help                 显示帮助信息
-d ID, --device ID         指定设备ID
-U, --usb                  连接到USB设备
-R, --remote               连接到远程设备
-H HOST, --host HOST       连接到远程主机
--version                  显示版本信息

# 示例
# 发现USB设备上指定进程的类和方法
frida-discover -U com.example.app

# 发现远程设备上的类和方法
frida-discover -H 192.168.1.100 com.example.app
```

### frida-ls-devices命令

frida-ls-devices命令用于列出可用设备。

```bash
# 基本用法
frida-ls-devices [options]

# 选项
-h, --help                 显示帮助信息
--version                  显示版本信息

# 示例
# 列出所有可用设备
frida-ls-devices
``` 