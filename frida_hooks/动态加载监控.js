/**
 * 动态加载监控脚本
 * 
 * 功能：监控Android应用中的动态加载代码行为
 * 作用：检测应用运行时加载的DEX、SO库、JAR包等
 * 适用：分析应用动态加载行为，检测恶意代码加载
 */

// 等待Java虚拟机加载完成
Java.perform(function() {
    console.log("[*] 动态加载监控脚本已启动");

    /**
     * 工具函数：获取调用堆栈
     */
    function getStackTrace() {
        var Exception = Java.use("java.lang.Exception");
        var exception = Exception.$new();
        var stackTrace = exception.getStackTrace();
        exception.$dispose();
        
        var stack = [];
        for (var i = 0; i < stackTrace.length; i++) {
            var element = stackTrace[i];
            var className = element.getClassName();
            var methodName = element.getMethodName();
            var fileName = element.getFileName();
            var lineNumber = element.getLineNumber();
            
            // 过滤掉Frida相关的堆栈
            if (className.indexOf("com.frida") === -1) {
                stack.push(className + "." + methodName + "(" + fileName + ":" + lineNumber + ")");
            }
            
            // 只获取前10个堆栈元素
            if (stack.length >= 10) break;
        }
        
        return stack.join("\n    ");
    }

    /**
     * 一、拦截DexClassLoader
     * 用于加载外部DEX文件
     */
    var DexClassLoader = Java.use("dalvik.system.DexClassLoader");
    
    // 拦截构造函数
    DexClassLoader.$init.implementation = function(dexPath, optimizedDirectory, librarySearchPath, parent) {
        console.log("\n[+] DexClassLoader初始化");
        console.log("    DEX路径: " + dexPath);
        console.log("    优化目录: " + optimizedDirectory);
        console.log("    库搜索路径: " + librarySearchPath);
        console.log("    父加载器: " + parent);
        console.log("    调用堆栈:\n    " + getStackTrace());
        
        // 尝试读取DEX文件信息
        try {
            var File = Java.use("java.io.File");
            var dexFile = File.$new(dexPath);
            console.log("    DEX文件大小: " + dexFile.length() + " 字节");
            console.log("    DEX文件最后修改时间: " + new Date(dexFile.lastModified()).toLocaleString());
        } catch (e) {
            console.log("    无法获取DEX文件信息: " + e);
        }
        
        return this.$init(dexPath, optimizedDirectory, librarySearchPath, parent);
    };
    
    // 拦截loadClass方法
    DexClassLoader.loadClass.overload("java.lang.String").implementation = function(name) {
        console.log("\n[+] DexClassLoader.loadClass");
        console.log("    加载类: " + name);
        console.log("    调用堆栈:\n    " + getStackTrace());
        
        try {
            var result = this.loadClass(name);
            console.log("    加载结果: 成功");
            return result;
        } catch (e) {
            console.log("    加载结果: 失败 - " + e);
            throw e;
        }
    };

    /**
     * 二、拦截PathClassLoader
     * Android默认的类加载器
     */
    var PathClassLoader = Java.use("dalvik.system.PathClassLoader");
    
    // 拦截构造函数
    PathClassLoader.$init.overload("java.lang.String", "java.lang.ClassLoader").implementation = function(dexPath, parent) {
        console.log("\n[+] PathClassLoader初始化");
        console.log("    DEX路径: " + dexPath);
        console.log("    父加载器: " + parent);
        console.log("    调用堆栈:\n    " + getStackTrace());
        
        return this.$init(dexPath, parent);
    };
    
    PathClassLoader.$init.overload("java.lang.String", "java.lang.String", "java.lang.ClassLoader").implementation = function(dexPath, librarySearchPath, parent) {
        console.log("\n[+] PathClassLoader初始化(带库路径)");
        console.log("    DEX路径: " + dexPath);
        console.log("    库搜索路径: " + librarySearchPath);
        console.log("    父加载器: " + parent);
        console.log("    调用堆栈:\n    " + getStackTrace());
        
        return this.$init(dexPath, librarySearchPath, parent);
    };

    /**
     * 三、拦截InMemoryDexClassLoader
     * Android 8.0+中用于从内存加载DEX的加载器
     */
    try {
        var InMemoryDexClassLoader = Java.use("dalvik.system.InMemoryDexClassLoader");
        
        // 拦截构造函数
        InMemoryDexClassLoader.$init.overload("java.nio.ByteBuffer", "java.lang.ClassLoader").implementation = function(buffer, parent) {
            console.log("\n[+] InMemoryDexClassLoader初始化");
            console.log("    ByteBuffer容量: " + buffer.capacity() + " 字节");
            console.log("    父加载器: " + parent);
            console.log("    调用堆栈:\n    " + getStackTrace());
            
            return this.$init(buffer, parent);
        };
        
        console.log("[+] InMemoryDexClassLoader拦截设置完成");
    } catch (e) {
        console.log("[-] InMemoryDexClassLoader可能不可用: " + e);
    }

    /**
     * 四、拦截DexFile
     * 用于直接操作DEX文件
     */
    var DexFile = Java.use("dalvik.system.DexFile");
    
    // 拦截构造函数
    DexFile.$init.overload("java.lang.String").implementation = function(fileName) {
        console.log("\n[+] DexFile初始化");
        console.log("    文件名: " + fileName);
        console.log("    调用堆栈:\n    " + getStackTrace());
        
        return this.$init(fileName);
    };
    
    // 拦截loadDex静态方法
    DexFile.loadDex.overload("java.lang.String", "java.lang.String", "int").implementation = function(sourcePathName, outputPathName, flags) {
        console.log("\n[+] DexFile.loadDex");
        console.log("    源路径: " + sourcePathName);
        console.log("    输出路径: " + outputPathName);
        console.log("    标志: " + flags);
        console.log("    调用堆栈:\n    " + getStackTrace());
        
        return this.loadDex(sourcePathName, outputPathName, flags);
    };
    
    // 拦截loadClass方法
    DexFile.loadClass.implementation = function(name, classLoader) {
        console.log("\n[+] DexFile.loadClass");
        console.log("    类名: " + name);
        console.log("    类加载器: " + classLoader);
        console.log("    调用堆栈:\n    " + getStackTrace());
        
        return this.loadClass(name, classLoader);
    };

    /**
     * 五、拦截System.load和System.loadLibrary
     * 用于加载Native库
     */
    var System = Java.use("java.lang.System");
    
    // 拦截load方法
    System.load.implementation = function(filename) {
        console.log("\n[+] System.load");
        console.log("    文件名: " + filename);
        console.log("    调用堆栈:\n    " + getStackTrace());
        
        // 尝试获取库文件信息
        try {
            var File = Java.use("java.io.File");
            var libFile = File.$new(filename);
            console.log("    库文件大小: " + libFile.length() + " 字节");
            console.log("    库文件最后修改时间: " + new Date(libFile.lastModified()).toLocaleString());
        } catch (e) {
            console.log("    无法获取库文件信息: " + e);
        }
        
        this.load(filename);
        console.log("    库加载成功");
    };
    
    // 拦截loadLibrary方法
    System.loadLibrary.implementation = function(libname) {
        console.log("\n[+] System.loadLibrary");
        console.log("    库名称: " + libname);
        console.log("    调用堆栈:\n    " + getStackTrace());
        
        this.loadLibrary(libname);
        console.log("    库加载成功");
    };

    /**
     * 六、拦截Runtime.exec
     * 可能用于执行shell命令加载或运行代码
     */
    var Runtime = Java.use("java.lang.Runtime");
    
    // 拦截exec方法
    Runtime.exec.overload("java.lang.String").implementation = function(command) {
        console.log("\n[+] Runtime.exec");
        console.log("    命令: " + command);
        console.log("    调用堆栈:\n    " + getStackTrace());
        
        return this.exec(command);
    };
    
    Runtime.exec.overload("[Ljava.lang.String;").implementation = function(cmdArray) {
        console.log("\n[+] Runtime.exec (数组)");
        console.log("    命令: " + JSON.stringify(cmdArray));
        console.log("    调用堆栈:\n    " + getStackTrace());
        
        return this.exec(cmdArray);
    };
    
    Runtime.exec.overload("java.lang.String", "[Ljava.lang.String;").implementation = function(command, envp) {
        console.log("\n[+] Runtime.exec (带环境变量)");
        console.log("    命令: " + command);
        console.log("    环境变量: " + JSON.stringify(envp));
        console.log("    调用堆栈:\n    " + getStackTrace());
        
        return this.exec(command, envp);
    };

    /**
     * 七、拦截反射调用
     * 可能用于动态调用加载的代码
     */
    var Method = Java.use("java.lang.reflect.Method");
    
    // 拦截invoke方法
    Method.invoke.implementation = function(obj, args) {
        console.log("\n[+] Method.invoke");
        console.log("    类: " + this.getDeclaringClass().getName());
        console.log("    方法: " + this.getName());
        console.log("    调用堆栈:\n    " + getStackTrace());
        
        return this.invoke(obj, args);
    };

    /**
     * 八、拦截类加载
     * 监控应用加载的所有类
     */
    var ClassLoader = Java.use("java.lang.ClassLoader");
    
    // 拦截loadClass方法
    ClassLoader.loadClass.overload("java.lang.String").implementation = function(name) {
        // 过滤掉系统类和常见库类，减少日志量
        if (!name.startsWith("android.") && 
            !name.startsWith("java.") && 
            !name.startsWith("javax.") && 
            !name.startsWith("sun.") && 
            !name.startsWith("com.android.") &&
            !name.startsWith("androidx.")) {
            
            console.log("\n[+] ClassLoader.loadClass");
            console.log("    类名: " + name);
            console.log("    类加载器: " + this.getClass().getName());
            console.log("    调用堆栈:\n    " + getStackTrace());
        }
        
        return this.loadClass(name);
    };

    /**
     * 九、拦截动态代理
     * 监控动态创建的代理类
     */
    var Proxy = Java.use("java.lang.reflect.Proxy");
    
    // 拦截newProxyInstance方法
    Proxy.newProxyInstance.implementation = function(loader, interfaces, handler) {
        console.log("\n[+] Proxy.newProxyInstance");
        console.log("    类加载器: " + loader);
        
        // 打印接口信息
        var interfaceNames = [];
        for (var i = 0; i < interfaces.length; i++) {
            interfaceNames.push(interfaces[i].getName());
        }
        console.log("    接口: " + JSON.stringify(interfaceNames));
        console.log("    调用处理器: " + handler.getClass().getName());
        console.log("    调用堆栈:\n    " + getStackTrace());
        
        return this.newProxyInstance(loader, interfaces, handler);
    };

    /**
     * 十、拦截Asset资源加载
     * 应用可能从Asset中加载DEX或其他代码
     */
    var AssetManager = Java.use("android.content.res.AssetManager");
    
    // 拦截open方法
    AssetManager.open.overload("java.lang.String").implementation = function(fileName) {
        // 过滤可能包含代码的文件类型
        if (fileName.endsWith(".dex") || 
            fileName.endsWith(".jar") || 
            fileName.endsWith(".so") || 
            fileName.endsWith(".apk") || 
            fileName.endsWith(".zip")) {
            
            console.log("\n[+] AssetManager.open");
            console.log("    文件名: " + fileName);
            console.log("    调用堆栈:\n    " + getStackTrace());
        }
        
        return this.open(fileName);
    };

    console.log("[*] 动态加载监控设置完成");
}); 