/*
 * 脚本名称：通杀类加载.js
 * 功能：自动监控所有Java类加载相关API，辅助分析动态加载、壳、插件等
 * 适用场景：动态加载、插件化、热修复、壳自定义ClassLoader等
 * 使用方法：
 *   1. frida -U -f 包名 -l 通杀类加载.js --no-pause
 *   2. 查看控制台输出，获取类加载信息
 * 启动方式说明：
 *   - -U 代表使用USB连接的设备
 *   - -f 代表以spawn方式启动目标应用（推荐，可以捕获启动阶段的类加载）
 *   - --no-pause 指示Frida不要暂停应用执行，保证App正常运行
 *   - 也可使用 -F 以attach方式附加到已运行的进程
 * 参数说明：
 *   - 包名：目标应用的包名，如com.example.app
 * 监控范围：
 *   - Class.forName：通过类名加载Java类
 *   - ClassLoader.loadClass：通过类加载器加载类
 *   - DexClassLoader：常用于动态加载dex/jar/apk文件中的类
 *   - PathClassLoader：Android默认的类加载器
 *   - InMemoryDexClassLoader：Android 8.0+内存中的类加载器
 * 输出信息：
 *   - 类名：被加载的类名
 *   - 加载器：使用的类加载器类型
 *   - 路径：加载类的dex文件路径（如果有）
 * 实际应用：
 *   - 分析动态加载的代码逻辑
 *   - 监控热修复/插件化框架加载的类
 *   - 检测壳程序动态解密和加载的类
 * 注意事项：
 *   - 某些加固应用需配合反检测脚本（如通杀绕过反Frida检测.js）
 *   - 可以结合dump_dex文件.js提取动态加载的类
 *   - 部分应用可能会使用自定义的类加载方式，需要根据情况额外Hook
 */

// 通杀类加载
Java.perform(function () {
    // 过滤不需要显示的包名前缀，减少输出噪音
    var filters = [
        'android.', 
        'androidx.', 
        'java.', 
        'javax.', 
        'com.android.', 
        'dalvik.',
        'kotlin.'
    ];
    
    // 过滤函数，判断是否为需要关注的类
    function shouldLog(className) {
        if (!className) return false;
        
        // 检查是否匹配过滤前缀
        for (var i = 0; i < filters.length; i++) {
            if (className.startsWith(filters[i])) {
                return false; // 忽略Android系统类
            }
        }
        return true; // 记录应用自身的类
    }
    
    // Hook Class.forName方法的三个重载
    // 这是最常用的类加载方法，通过类名字符串加载类
    var Class = Java.use('java.lang.Class');
    
    // Class.forName(String)
    Class.forName.overload('java.lang.String').implementation = function(className) {
        if (shouldLog(className)) {
            console.log('[*] Class.forName加载: ' + className);
            // 打印调用堆栈，便于分析类加载的来源
            console.log('    调用堆栈: ' + Java.use('android.util.Log').getStackTraceString(Java.use('java.lang.Exception').$new()).split('\n')[2]);
        }
        return this.forName(className);
    };
    
    // Class.forName(String, boolean, ClassLoader)
    Class.forName.overload('java.lang.String', 'boolean', 'java.lang.ClassLoader').implementation = function(className, initialize, loader) {
        if (shouldLog(className)) {
            console.log('[*] Class.forName加载(带ClassLoader): ' + className);
            if (loader) {
                console.log('    ClassLoader类型: ' + loader.getClass().getName());
            }
        }
        return this.forName(className, initialize, loader);
    };
    
    // Hook ClassLoader.loadClass方法
    // 这是类加载器的核心方法，所有自定义类加载器都会调用此方法
    var ClassLoader = Java.use('java.lang.ClassLoader');
    
    // ClassLoader.loadClass(String)
    ClassLoader.loadClass.overload('java.lang.String').implementation = function(className) {
        if (shouldLog(className)) {
            var loaderClassName = this.getClass().getName();
            console.log('[*] ' + loaderClassName + '.loadClass: ' + className);
        }
        return this.loadClass(className);
    };
    
    // ClassLoader.loadClass(String, boolean)
    ClassLoader.loadClass.overload('java.lang.String', 'boolean').implementation = function(className, resolve) {
        if (shouldLog(className)) {
            var loaderClassName = this.getClass().getName();
            console.log('[*] ' + loaderClassName + '.loadClass(resolve=' + resolve + '): ' + className);
        }
        return this.loadClass(className, resolve);
    };
    
    // Hook DexClassLoader构造函数
    // DexClassLoader用于加载.dex/.apk/.jar/.zip文件中的类，常用于动态加载场景
    try {
        var DexClassLoader = Java.use('dalvik.system.DexClassLoader');
        DexClassLoader.$init.implementation = function(dexPath, optimizedDirectory, librarySearchPath, parent) {
            console.log('[+] 创建DexClassLoader');
            console.log('    DEX路径: ' + dexPath);
            console.log('    优化目录: ' + optimizedDirectory);
            console.log('    库搜索路径: ' + librarySearchPath);
            
            // 打印调用堆栈，便于分析类加载器的创建来源
            console.log('    调用堆栈: ');
            console.log('    ' + Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()).split('\n').slice(2, 7).join('\n    '));
            
            return this.$init(dexPath, optimizedDirectory, librarySearchPath, parent);
        };
    } catch (e) {
        console.log("[-] DexClassLoader Hook失败: " + e);
    }
    
    // Hook PathClassLoader构造函数
    // PathClassLoader是Android默认的类加载器，用于加载已安装应用的类
    try {
        var PathClassLoader = Java.use('dalvik.system.PathClassLoader');
        PathClassLoader.$init.overload('java.lang.String', 'java.lang.ClassLoader').implementation = function(dexPath, parent) {
            console.log('[+] 创建PathClassLoader');
            console.log('    DEX路径: ' + dexPath);
            return this.$init(dexPath, parent);
        };
        
        // 另一个构造函数重载
        PathClassLoader.$init.overload('java.lang.String', 'java.lang.String', 'java.lang.ClassLoader').implementation = function(dexPath, librarySearchPath, parent) {
            console.log('[+] 创建PathClassLoader(带库路径)');
            console.log('    DEX路径: ' + dexPath);
            console.log('    库搜索路径: ' + librarySearchPath);
            return this.$init(dexPath, librarySearchPath, parent);
        };
    } catch (e) {
        console.log("[-] PathClassLoader Hook失败: " + e);
    }
    
    // Hook InMemoryDexClassLoader (Android 8.0+)
    // 在内存中加载dex字节码的类加载器
    try {
        var InMemoryDexClassLoader = Java.use('dalvik.system.InMemoryDexClassLoader');
        if (InMemoryDexClassLoader) {
            InMemoryDexClassLoader.$init.implementation = function(buffer, parent) {
                console.log('[+] 创建InMemoryDexClassLoader');
                console.log('    缓冲区大小: ' + buffer.capacity());
                return this.$init(buffer, parent);
            };
        }
    } catch (e) {
        // 忽略错误，可能是API版本低于26
    }
    
    // 打印已加载的自定义类加载器
    Java.enumerateClassLoaders({
        onMatch: function(loader) {
            var className = loader.getClass().getName();
            // 过滤掉系统类加载器
            if (!className.startsWith("dalvik.") && !className.startsWith("java.") && 
                !className.startsWith("android.") && !className.startsWith("com.android.")) {
                console.log("[i] 发现自定义ClassLoader: " + className);
            }
        },
        onComplete: function() {}
    });
    
    console.log("[*] 类加载监控已启动");
}); 