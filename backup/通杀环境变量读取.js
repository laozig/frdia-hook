/*
 * 脚本名称：通杀环境变量读取.js
 * 功能：自动监控应用中对系统环境变量的读取与设置操作
 * 适用场景：环境检测分析、环境变量依赖调试、安全沙盒检测分析
 * 使用方法：
 *   1. frida -U -f 包名 -l 通杀环境变量读取.js --no-pause
 *   2. 查看控制台输出，获取环境变量读写信息
 * 启动方式说明：
 *   - -U 代表使用USB连接的设备
 *   - -f 代表以spawn方式启动目标应用
 *   - --no-pause 指示Frida不要暂停应用执行，保证App正常运行
 *   - 也可使用 -F 以attach方式附加到已运行的进程
 * 参数说明：
 *   - 包名：目标应用的包名，如com.example.app
 * 监控函数说明：
 *   - System.getenv(): 获取指定环境变量的值
 *   - System.getenv(String): 获取单个环境变量的值
 *   - System.getenv(Map): 返回所有环境变量的映射
 *   - System.setenv(): 设置环境变量(如有)
 *   - ProcessBuilder.environment(): 获取进程的环境变量映射
 *   - Native getenv(): 通过libc获取环境变量
 *   - Native setenv(): 通过libc设置环境变量
 * 重要环境变量列表：
 *   - PATH: 可执行文件查找路径，可用于安全检查
 *   - LD_LIBRARY_PATH: 共享库加载路径，注入检测关键
 *   - HOME: 用户主目录，可获取用户信息
 *   - USER/LOGNAME: 当前用户名
 *   - ANDROID_ROOT: Android系统根目录(/system)
 *   - ANDROID_DATA: Android数据目录(/data)
 *   - EXTERNAL_STORAGE: 外部存储路径
 *   - BOOTCLASSPATH: Java引导类路径
 *   - TMPDIR: 临时目录
 * 输出内容：
 *   - 变量名：被访问的环境变量名
 *   - 变量值：环境变量的值
 *   - 访问位置：代码中获取环境变量的位置
 * 实际应用场景：
 *   - 分析应用如何检测Root或越狱环境
 *   - 调试环境变量依赖问题
 *   - 检测对敏感环境变量的访问
 *   - 分析应用沙箱逃逸行为
 * 注意事项：
 *   - 某些加固应用需配合反检测脚本
 *   - Android应用通常不直接依赖环境变量，但可能通过JNI调用
 *   - 安全检测工具可能会重点关注环境变量读取操作
 */

// 通杀环境变量读取
Java.perform(function () {
    // 敏感环境变量列表，这些变量通常用于安全检测或信息收集
    var sensitiveEnvVars = [
        "PATH",
        "LD_LIBRARY_PATH",
        "LD_PRELOAD",
        "HOME",
        "ANDROID_ROOT",
        "ANDROID_DATA",
        "EXTERNAL_STORAGE",
        "BOOTCLASSPATH",
        "TMPDIR",
        "SHELL",
        "USER",
        "LOGNAME",
        "TERM",
        "LANGUAGE",
        "JAVA_HOME",
        "CLASSPATH",
        "PYTHONPATH"
    ];
    
    // 辅助函数：检查是否为敏感环境变量
    function isSensitiveEnv(key) {
        if (!key) return false;
        var upperKey = key.toUpperCase();
        
        // 精确匹配
        for (var i = 0; i < sensitiveEnvVars.length; i++) {
            if (sensitiveEnvVars[i].toUpperCase() === upperKey) {
                return true;
            }
        }
        
        return false;
    }
    
    // 辅助函数：获取简短调用堆栈
    function getStackShort() {
        return Java.use("android.util.Log").getStackTraceString(
            Java.use("java.lang.Exception").$new()).split('\n').slice(2, 5).join('\n    ');
    }
    
    //====== Java层环境变量监控 ======
    
    // 监控System.getenv单个变量读取
    var System = Java.use('java.lang.System');
    System.getenv.overload('java.lang.String').implementation = function (key) {
        var value = this.getenv(key);
        console.log('[*] System.getenv("' + key + '"): ' + value);
        
        // 对敏感环境变量添加标记
        if (isSensitiveEnv(key)) {
            console.log('    [!] 敏感环境变量');
        }
        
        // 打印调用堆栈
        console.log('    调用堆栈: \n    ' + getStackShort());
        
        return value;
    };
    
    // 监控System.getenv获取全部环境变量
    System.getenv.overload().implementation = function () {
        var env = this.getenv();
        console.log('[*] System.getenv() 获取全部环境变量');
        
        // 打印环境变量数量
        var envSize = 0;
        var envIterator = env.keySet().iterator();
        while (envIterator.hasNext()) {
            envSize++;
            envIterator.next();
        }
        console.log('    环境变量数量: ' + envSize);
        
        // 打印调用堆栈
        console.log('    调用堆栈: \n    ' + getStackShort());
        
        return env;
    };
    
    // 监控System.setProperties (Java不直接支持setenv，但监控相关函数)
    try {
        System.setProperties.implementation = function (props) {
            console.log('[*] System.setProperties 被调用');
            
            // 获取一些重要的系统属性
            try {
                var keys = ["java.home", "java.library.path", "java.class.path", "java.io.tmpdir"];
                for (var i = 0; i < keys.length; i++) {
                    var key = keys[i];
                    if (props.containsKey(key)) {
                        console.log('    设置系统属性 "' + key + '" = ' + props.getProperty(key));
                    }
                }
            } catch (e) {}
            
            // 打印调用堆栈
            console.log('    调用堆栈: \n    ' + getStackShort());
            
            return this.setProperties(props);
        };
    } catch (e) {}
    
    // 监控ProcessBuilder.environment - 用于设置进程环境变量
    try {
        var ProcessBuilder = Java.use('java.lang.ProcessBuilder');
        
        // 监控environment()方法，它返回环境变量Map
        ProcessBuilder.environment.implementation = function () {
            var env = this.environment();
            console.log('[*] ProcessBuilder.environment() 被调用');
            console.log('    调用堆栈: \n    ' + getStackShort());
            return env;
        };
        
        // 监控环境变量Map的put方法，捕获设置的环境变量
        var envMap = Java.use('java.util.Map');
        // 注意：这是一个泛型接口，可能需要具体实现类的hook
        try {
            envMap.put.implementation = function (key, value) {
                if (key.toString().indexOf("ANDROID_") !== -1 || 
                    key.toString().indexOf("LD_") !== -1 || 
                    isSensitiveEnv(key.toString())) {
                    console.log('[*] 设置环境变量: ' + key + ' = ' + value);
                    console.log('    调用堆栈: \n    ' + getStackShort());
                }
                return this.put(key, value);
            };
        } catch (e) {
            // 可能需要hook具体实现类
        }
    } catch (e) {
        console.log("[-] ProcessBuilder监控失败: " + e);
    }
    
    //====== Native层环境变量监控 ======
    try {
        // 监控C标准库中的getenv函数
        // 函数原型: char *getenv(const char *name);
        var getenvPtr = Module.findExportByName(null, 'getenv');
        if (getenvPtr) {
            Interceptor.attach(getenvPtr, {
                onEnter: function (args) {
                    this.envName = Memory.readUtf8String(args[0]);
                },
                onLeave: function (retval) {
                    // 注意：如果环境变量不存在，getenv返回NULL
                    var envValue = retval.isNull() ? "<未定义>" : Memory.readUtf8String(retval);
                    console.log('[*] Native getenv("' + this.envName + '"): ' + envValue);
                    
                    // 对敏感环境变量添加标记
                    if (isSensitiveEnv(this.envName)) {
                        console.log('    [!] 敏感环境变量');
                    }
                    
                    // 打印调用堆栈
                    console.log('    调用堆栈: ');
                    console.log('    ' + Thread.backtrace(this.context, Backtracer.ACCURATE)
                                 .map(DebugSymbol.fromAddress).join('\n    '));
                }
            });
            
            console.log("[+] 成功Hook Native getenv函数");
        }
        
        // 监控C标准库中的setenv函数
        // 函数原型: int setenv(const char *name, const char *value, int overwrite);
        var setenvPtr = Module.findExportByName(null, 'setenv');
        if (setenvPtr) {
            Interceptor.attach(setenvPtr, {
                onEnter: function (args) {
                    this.envName = Memory.readUtf8String(args[0]);
                    this.envValue = Memory.readUtf8String(args[1]);
                    this.overwrite = args[2].toInt32();
                },
                onLeave: function (retval) {
                    var result = retval.toInt32();
                    console.log('[*] Native setenv("' + this.envName + '", "' + this.envValue + '", ' + 
                               this.overwrite + '): ' + (result === 0 ? "成功" : "失败"));
                    
                    // 对敏感环境变量添加标记
                    if (isSensitiveEnv(this.envName)) {
                        console.log('    [!] 设置敏感环境变量');
                    }
                    
                    // 打印调用堆栈
                    console.log('    调用堆栈: ');
                    console.log('    ' + Thread.backtrace(this.context, Backtracer.ACCURATE)
                                 .map(DebugSymbol.fromAddress).join('\n    '));
                }
            });
            
            console.log("[+] 成功Hook Native setenv函数");
        }
        
        // 监控C标准库中的unsetenv函数
        // 函数原型: int unsetenv(const char *name);
        var unsetenvPtr = Module.findExportByName(null, 'unsetenv');
        if (unsetenvPtr) {
            Interceptor.attach(unsetenvPtr, {
                onEnter: function (args) {
                    this.envName = Memory.readUtf8String(args[0]);
                },
                onLeave: function (retval) {
                    var result = retval.toInt32();
                    console.log('[*] Native unsetenv("' + this.envName + '"): ' + 
                               (result === 0 ? "成功" : "失败"));
                    
                    // 对敏感环境变量添加标记
                    if (isSensitiveEnv(this.envName)) {
                        console.log('    [!] 删除敏感环境变量');
                    }
                }
            });
            
            console.log("[+] 成功Hook Native unsetenv函数");
        }
        
        // 监控C标准库中的putenv函数
        // 函数原型: int putenv(char *string);
        var putenvPtr = Module.findExportByName(null, 'putenv');
        if (putenvPtr) {
            Interceptor.attach(putenvPtr, {
                onEnter: function (args) {
                    var envString = Memory.readUtf8String(args[0]);
                    console.log('[*] Native putenv("' + envString + '")');
                    
                    // 解析环境变量名
                    var envName = envString.split('=')[0];
                    
                    // 对敏感环境变量添加标记
                    if (envName && isSensitiveEnv(envName)) {
                        console.log('    [!] 修改敏感环境变量');
                    }
                }
            });
            
            console.log("[+] 成功Hook Native putenv函数");
        }
        
    } catch (e) {
        console.log("[-] Native环境变量函数监控失败: " + e);
    }
    
    console.log("[*] 环境变量读取监控已启动");
    console.log("[*] 监控范围: Java System.getenv和Native环境变量函数");
    
    // 可选：显示一些重要的环境变量当前值
    try {
        var importantVars = ["PATH", "LD_LIBRARY_PATH", "ANDROID_ROOT", "ANDROID_DATA"];
        console.log("[*] 当前重要环境变量:");
        for (var i = 0; i < importantVars.length; i++) {
            var value = System.getenv(importantVars[i]);
            if (value) {
                console.log("    " + importantVars[i] + " = " + value);
            }
        }
    } catch (e) {}
}); 