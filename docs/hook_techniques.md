# Frida Hook 技术详解

本文详细介绍 Frida 的各种 Hook（钩子）技术，从基础到高级，帮助你有效地拦截和修改目标应用的行为。

## 目录

1. [Hook 基础概念](#hook-基础概念)
2. [Java 层 Hook](#java-层-hook)
3. [Native 层 Hook](#native-层-hook)
4. [方法重载处理](#方法重载处理)
5. [构造函数 Hook](#构造函数-hook)
6. [类加载器处理](#类加载器处理)
7. [内部类 Hook](#内部类-hook)
8. [回调和监听器](#回调和监听器)
9. [高级技巧和最佳实践](#高级技巧和最佳实践)

## Hook 基础概念

### 什么是 Hook

Hook（钩子）技术是一种拦截和修改程序执行流程的技术。在 Frida 中，Hook 允许你：

- 拦截函数调用
- 修改函数参数
- 修改函数返回值
- 添加自定义逻辑
- 绕过特定条件或限制

### Hook 的基本结构

```javascript
Java.perform(function() {
    // 1. 获取目标类
    var TargetClass = Java.use("com.example.TargetClass");
    
    // 2. 替换目标方法的实现
    TargetClass.targetMethod.implementation = function(arg1, arg2) {
        // 3. 自定义前置逻辑
        console.log("方法被调用，参数:", arg1, arg2);
        
        // 4. 调用原始方法（可选）
        var result = this.targetMethod(arg1, arg2);
        
        // 5. 自定义后置逻辑
        console.log("方法返回值:", result);
        
        // 6. 返回原始或修改后的结果
        return result;
    };
});
```

### Hook 执行阶段

1. **前置阶段**: 方法执行前的逻辑，可访问、修改参数
2. **执行阶段**: 调用原始方法或替换执行逻辑
3. **后置阶段**: 方法执行后的逻辑，可访问、修改返回值

## Java 层 Hook

### 基本方法 Hook

```javascript
Java.perform(function() {
    // Hook普通方法
    var Button = Java.use("android.widget.Button");
    Button.setText.implementation = function(text) {
        console.log("Button.setText 被调用，参数:", text);
        
        // 修改参数
        var modifiedText = text + " [已修改]";
        
        // 调用原始方法
        this.setText(modifiedText);
    };
});
```

### 静态方法 Hook

```javascript
Java.perform(function() {
    // Hook静态方法
    var System = Java.use("java.lang.System");
    System.exit.implementation = function(status) {
        console.log("System.exit 被拦截，退出代码:", status);
        
        // 阻止应用退出
        console.log("已阻止应用退出");
        
        // 不调用原始方法，阻止退出
        // this.exit(status);
    };
});
```

### 获取类实例

```javascript
// 获取已存在的实例
Java.choose("com.example.TargetClass", {
    onMatch: function(instance) {
        console.log("找到实例:", instance);
        
        // 调用实例方法
        var result = instance.doSomething();
        console.log("方法返回:", result);
    },
    onComplete: function() {
        console.log("实例枚举完成");
    }
});
```

### 创建新实例

```javascript
// 创建新实例
var TargetClass = Java.use("com.example.TargetClass");
var instance = TargetClass.$new();  // 调用默认构造函数

// 带参数的构造函数
var instanceWithArgs = TargetClass.$new("参数1", 123);
```

## 方法重载处理

### 处理重载方法

```javascript
Java.perform(function() {
    var TextView = Java.use("android.widget.TextView");
    
    // 指定参数类型处理重载
    TextView.setText.overload("java.lang.CharSequence").implementation = function(text) {
        console.log("setText(CharSequence) 被调用");
        return this.setText(text);
    };
    
    // 处理不同参数的重载
    TextView.setText.overload("int").implementation = function(resId) {
        console.log("setText(int) 被调用, resId:", resId);
        return this.setText(resId);
    };
});
```

### 处理所有重载

```javascript
Java.perform(function() {
    var TextView = Java.use("android.widget.TextView");
    
    // 获取所有重载
    var overloads = TextView.setText.overloads;
    
    // 遍历处理所有重载方法
    overloads.forEach(function(overload) {
        overload.implementation = function() {
            console.log("setText 被调用，参数个数:", arguments.length);
            
            // 显示参数信息
            for (var i = 0; i < arguments.length; i++) {
                console.log("参数", i, ":", arguments[i]);
            }
            
            // 调用原始方法
            var result = this[overload.methodName].apply(this, arguments);
            
            return result;
        };
    });
});
```

## Native 层 Hook

### 基本 Native 函数 Hook

```javascript
// 查找导出函数
var open = Module.findExportByName(null, "open");

// 拦截函数
Interceptor.attach(open, {
    onEnter: function(args) {
        // 在函数调用时执行
        var path = args[0].readUtf8String();
        console.log("open() 被调用，路径:", path);
        
        // 存储上下文信息，在onLeave中使用
        this.path = path;
    },
    onLeave: function(retval) {
        // 在函数返回时执行
        console.log("open() 返回，文件描述符:", retval);
        
        // 访问onEnter中存储的上下文
        console.log("操作的文件:", this.path);
        
        // 修改返回值
        if (this.path.indexOf("sensitive") >= 0) {
            console.log("拦截敏感文件访问");
            retval.replace(-1); // 模拟访问失败
        }
    }
});
```

### 创建 Native 函数包装器

```javascript
// 创建函数包装器
var open = new NativeFunction(
    Module.findExportByName(null, "open"),
    'int',        // 返回类型
    ['pointer',   // 文件路径参数
     'int']       // 模式参数
);

// 调用Native函数
var fd = open(Memory.allocUtf8String("/etc/hosts"), 0);
console.log("文件描述符:", fd);
```

### Hook JNI 函数

```javascript
// Hook JNI RegisterNatives函数
var RegisterNatives = Module.findExportByName(null, "RegisterNatives");
Interceptor.attach(RegisterNatives, {
    onEnter: function(args) {
        var env = args[0];
        var clazz = args[1];
        var methods = args[2];
        var methodCount = parseInt(args[3]);
        
        // 获取类名
        var className = Java.vm.getEnv().getClassName(clazz);
        console.log("RegisterNatives:", className, "方法数:", methodCount);
        
        // 遍历注册的方法
        for (var i = 0; i < methodCount; i++) {
            var methodInfo = methods.add(i * Process.pointerSize * 3).readPointer();
            var methodName = methodInfo.readUtf8String();
            var signature = methodInfo.add(Process.pointerSize).readPointer().readUtf8String();
            var fnPtr = methodInfo.add(Process.pointerSize * 2).readPointer();
            
            console.log("\t方法名:", methodName);
            console.log("\t签名:", signature);
            console.log("\t函数指针:", fnPtr);
            
            // Hook特定的JNI方法
            if (methodName == "nativeMethod") {
                Interceptor.attach(fnPtr, {
                    onEnter: function(args) {
                        console.log("JNI nativeMethod 被调用");
                    },
                    onLeave: function(retval) {
                        console.log("JNI nativeMethod 返回:", retval);
                    }
                });
            }
        }
    }
});
```

## 构造函数 Hook

### 拦截构造函数

```javascript
Java.perform(function() {
    var TargetClass = Java.use("com.example.TargetClass");
    
    // Hook默认构造函数
    TargetClass.$init.implementation = function() {
        console.log("TargetClass 默认构造函数被调用");
        
        // 调用原构造函数
        this.$init();
    };
    
    // Hook带参数的构造函数
    TargetClass.$init.overload("java.lang.String", "int").implementation = function(str, num) {
        console.log("TargetClass 构造函数被调用，参数:", str, num);
        
        // 修改参数
        this.$init(str + "_modified", num * 2);
    };
});
```

## 类加载器处理

### 使用自定义类加载器

```javascript
Java.perform(function() {
    // 获取一个已加载的类，以获取其类加载器
    var someLoadedClass = Java.use("com.example.SomeLoadedClass");
    var classLoader = someLoadedClass.class.getClassLoader();
    
    // 通过特定类加载器加载类
    Java.classFactory.loader = classLoader;
    var HiddenClass = Java.use("com.example.hidden.HiddenClass");
    
    // 正常使用该类
    HiddenClass.someMethod.implementation = function() {
        console.log("HiddenClass.someMethod 被调用");
        return this.someMethod();
    };
});
```

### 枚举所有类加载器

```javascript
Java.perform(function() {
    Java.enumerateClassLoaders({
        onMatch: function(loader) {
            console.log("找到类加载器:", loader);
            
            try {
                // 尝试加载特定类
                var MessageDigest = loader.findClass("java.security.MessageDigest");
                console.log("成功通过此加载器加载类");
                
                // 设置为当前加载器
                Java.classFactory.loader = loader;
            } catch (e) {
                console.log("通过此加载器加载类失败");
            }
        },
        onComplete: function() {
            console.log("类加载器枚举完成");
        }
    });
});
```

## 内部类 Hook

### 访问内部类

```javascript
Java.perform(function() {
    // 静态内部类: OuterClass$InnerClass
    var StaticInnerClass = Java.use("com.example.OuterClass$StaticInnerClass");
    
    StaticInnerClass.innerMethod.implementation = function() {
        console.log("静态内部类方法被调用");
        return this.innerMethod();
    };
    
    // 非静态内部类
    var InnerClass = Java.use("com.example.OuterClass$InnerClass");
    
    InnerClass.innerMethod.implementation = function() {
        console.log("非静态内部类方法被调用");
        return this.innerMethod();
    };
    
    // 匿名内部类: OuterClass$1, OuterClass$2, 等
    var AnonymousClass = Java.use("com.example.OuterClass$1");
    
    AnonymousClass.onClick.implementation = function(view) {
        console.log("匿名内部类方法被调用");
        return this.onClick(view);
    };
});
```

## 回调和监听器

### Hook 回调函数

```javascript
Java.perform(function() {
    var OnClickListener = Java.use("android.view.View$OnClickListener");
    
    // 拦截所有点击事件
    OnClickListener.onClick.implementation = function(view) {
        // 获取视图ID
        var id = view.getId();
        var viewId = getViewName(id);
        
        console.log("点击事件被触发，视图ID:", viewId);
        
        // 调用原始点击处理
        this.onClick(view);
    };
    
    // 辅助函数: 获取视图名称
    function getViewName(id) {
        if (id == -1) return "NO_ID";
        
        var context = Java.use("android.app.ActivityThread").currentApplication().getApplicationContext();
        var resources = context.getResources();
        
        try {
            return resources.getResourceEntryName(id);
        } catch (e) {
            return "Unknown ID: " + id;
        }
    }
});
```

### 创建自定义回调

```javascript
Java.perform(function() {
    // 创建自定义回调
    var Runnable = Java.use("java.lang.Runnable");
    var CustomRunnable = Java.registerClass({
        name: "com.example.CustomRunnable",
        implements: [Runnable],
        methods: {
            run: function() {
                console.log("自定义Runnable.run 被调用");
            }
        }
    });
    
    // 创建并使用自定义回调
    var Handler = Java.use("android.os.Handler");
    var handlerInstance = Handler.$new();
    handlerInstance.post(CustomRunnable.$new());
});
```

## 高级技巧和最佳实践

### 1. 使用上下文传递数据

```javascript
Interceptor.attach(targetFunction, {
    onEnter: function(args) {
        // 在onEnter中保存状态
        this.arg0 = args[0];
        this.startTime = new Date().getTime();
    },
    onLeave: function(retval) {
        // 在onLeave中使用
        console.log("参数0:", this.arg0);
        console.log("执行时间:", new Date().getTime() - this.startTime, "ms");
    }
});
```

### 2. 防止无限递归

当你替换一个方法的实现，然后在新实现中调用原始方法时，确保使用原始引用而不是this关键字调用同名方法，否则会导致无限递归。

```javascript
// 错误方式 - 会导致递归调用和堆栈溢出
BadExample.method.implementation = function() {
    console.log("Before call");
    this.method();  // 错误! 会再次调用implementation
    console.log("After call");
};

// 正确方式
GoodExample.method.implementation = function() {
    console.log("Before call");
    var result = this.method.call(this);  // 正确，调用原始方法
    console.log("After call");
    return result;
};
```

### 3. 异常处理

始终添加异常处理以使脚本更健壮：

```javascript
Java.perform(function() {
    try {
        var TargetClass = Java.use("com.example.TargetClass");
        
        TargetClass.method.implementation = function() {
            try {
                console.log("执行方法");
                return this.method();
            } catch (e) {
                console.log("方法执行错误:", e);
                return null;
            }
        };
    } catch (e) {
        console.log("脚本错误:", e);
    }
});
```

### 4. 延迟Hook

有时需要等待应用完成初始化才能执行Hook:

```javascript
// 使用setTimeout延迟执行
setTimeout(function() {
    Java.perform(function() {
        console.log("延迟执行Hook");
        // 执行Hook操作
    });
}, 3000);  // 延迟3秒
```

### 5. 条件Hook

根据特定条件执行Hook:

```javascript
Java.perform(function() {
    var Activity = Java.use("android.app.Activity");
    
    Activity.onResume.implementation = function() {
        // 获取当前活动名称
        var activityName = this.getClass().getName();
        
        // 条件Hook
        if (activityName.indexOf("MainActivity") != -1) {
            console.log("主活动恢复");
            
            // 主活动特定的处理
            hookMainActivitySpecificMethods();
        } else if (activityName.indexOf("LoginActivity") != -1) {
            console.log("登录活动恢复");
            
            // 登录活动特定的处理
            hookLoginActivitySpecificMethods();
        }
        
        // 调用原方法
        this.onResume();
    };
});
```

### 6. 获取方法签名

获取方法的完整签名，有助于处理复杂的重载情况：

```javascript
Java.perform(function() {
    var TargetClass = Java.use("com.example.TargetClass");
    
    // 遍历所有方法
    var methods = TargetClass.class.getDeclaredMethods();
    var methodArray = methods.toArray();
    
    for (var i = 0; i < methodArray.length; i++) {
        var method = methodArray[i];
        
        console.log("方法签名:", method.toString());
        
        // 输出参数类型
        var parameterTypes = method.getParameterTypes();
        for (var j = 0; j < parameterTypes.length; j++) {
            console.log("  参数", j, ":", parameterTypes[j].getName());
        }
    }
});
```

### 7. 持久化Hook

在应用的整个生命周期中保持Hook有效：

```javascript
// 监听类加载
Java.performNow(function() {
    // 先处理已加载的类
    try {
        hookTargetClass();
    } catch (e) {
        console.log("目标类尚未加载:", e);
    }
});

// 使用classLoader监听器等待类加载
Java.classFactory.loader.find("com.example.TargetClass").then(function(targetClass) {
    console.log("目标类已加载");
    hookTargetClass();
});

function hookTargetClass() {
    var TargetClass = Java.use("com.example.TargetClass");
    // 执行Hook操作
}
```

## 实战案例

### 案例1: 绕过SSL证书验证

```javascript
Java.perform(function() {
    // 方法1: Hook TrustManager
    var TrustManager = Java.use("javax.net.ssl.X509TrustManager");
    var SSLContext = Java.use("javax.net.ssl.SSLContext");
    
    // 创建空的TrustManager
    var TrustManagerImpl = Java.registerClass({
        name: "com.custom.TrustManager",
        implements: [TrustManager],
        methods: {
            checkClientTrusted: function(chain, authType) {},
            checkServerTrusted: function(chain, authType) {},
            getAcceptedIssuers: function() {
                return [];
            }
        }
    });
    
    // 创建空的TrustManager数组
    var TrustManagers = [TrustManagerImpl.$new()];
    
    // Hook SSLContext.init方法，注入我们的TrustManager
    SSLContext.init.implementation = function(keyManager, trustManager, secureRandom) {
        console.log("SSLContext.init() 被拦截");
        this.init(keyManager, TrustManagers, secureRandom);
    };
    
    // 方法2: Hook OkHttp的证书检查
    try {
        var CertificatePinner = Java.use("okhttp3.CertificatePinner");
        CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function(hostname, certificates) {
            console.log("OkHttp CertificatePinner.check() 被绕过");
            return;  // 不执行检查
        };
    } catch (e) {
        console.log("OkHttp CertificatePinner not found");
    }
});
```

### 案例2: 提取加密密钥

```javascript
Java.perform(function() {
    // Hook 加密类
    var SecretKeySpec = Java.use("javax.crypto.spec.SecretKeySpec");
    SecretKeySpec.$init.overload("[B", "java.lang.String").implementation = function(keyBytes, algorithm) {
        var key = "";
        for (var i = 0; i < keyBytes.length; i++) {
            key += (String.fromCharCode(keyBytes[i] & 0xff));
        }
        
        console.log("[+] 发现密钥:" + key);
        console.log("[+] 密钥 (Base64):", Java.use("android.util.Base64").encodeToString(keyBytes, 0));
        console.log("[+] 算法:", algorithm);
        
        return this.$init(keyBytes, algorithm);
    };
    
    // Hook Cipher加密/解密
    var Cipher = Java.use("javax.crypto.Cipher");
    Cipher.getInstance.overload("java.lang.String").implementation = function(transformation) {
        console.log("[+] Cipher.getInstance 被调用，算法:", transformation);
        return this.getInstance(transformation);
    };
    
    Cipher.doFinal.overload("[B").implementation = function(input) {
        console.log("[+] Cipher.doFinal 被调用");
        
        // 获取当前cipher的信息
        var algorithm = this.getAlgorithm();
        var mode = this.getIV() ? "CBC" : "ECB";
        console.log("    算法:", algorithm);
        console.log("    模式:", mode);
        
        // 尝试提取输入数据
        var inputString = "";
        try {
            inputString = new Java.lang.String(input).$valueOf();
        } catch (e) {
            inputString = "[二进制数据]";
        }
        console.log("    输入:", inputString);
        
        // 执行原始方法
        var output = this.doFinal(input);
        
        // 尝试提取输出数据
        var outputString = "";
        try {
            outputString = new Java.lang.String(output).$valueOf();
        } catch (e) {
            outputString = "[二进制数据]";
        }
        console.log("    输出:", outputString);
        
        return output;
    };
});
```

### 案例3: 监控文件操作

```javascript
Java.perform(function() {
    // Hook File构造函数
    var File = Java.use("java.io.File");
    
    // Hook 构造函数
    File.$init.overload("java.lang.String").implementation = function(path) {
        console.log("[+] 新建文件对象:", path);
        return this.$init(path);
    };
    
    // Hook 文件读操作
    var FileInputStream = Java.use("java.io.FileInputStream");
    FileInputStream.$init.overload("java.io.File").implementation = function(file) {
        console.log("[+] 读取文件:", file.getAbsolutePath());
        return this.$init(file);
    };
    
    // Hook 文件写操作
    var FileOutputStream = Java.use("java.io.FileOutputStream");
    FileOutputStream.$init.overload("java.io.File").implementation = function(file) {
        console.log("[+] 写入文件:", file.getAbsolutePath());
        return this.$init(file);
    };
    
    // Hook 文件删除
    File.delete.implementation = function() {
        console.log("[+] 尝试删除文件:", this.getAbsolutePath());
        
        // 阻止特定文件被删除
        if (this.getAbsolutePath().indexOf("important.txt") != -1) {
            console.log("[!] 阻止重要文件被删除");
            return false;  // 返回删除失败
        }
        
        return this.delete();
    };
});
```

## 总结

本文档详细介绍了 Frida 的各种 Hook 技术，从基本的 Java 方法和 Native 函数 Hook，到处理方法重载、构造函数和类加载器的高级技术。掌握这些技巧将帮助你有效地分析和修改目标应用的行为。

关键是理解 Hook 的基本原理，选择合适的 Hook 点，并根据具体需求组合使用不同的技术。记得处理异常情况，避免脚本错误导致应用崩溃。 