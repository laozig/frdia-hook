/**
 * 文件操作拦截脚本
 * 
 * 功能：拦截Android应用中的文件读写操作
 * 作用：监控应用对文件系统的访问，包括读取、写入、删除等操作
 * 适用：分析应用数据存储方式，敏感信息存储位置等
 */

// 等待Java虚拟机加载完成
Java.perform(function() {
    console.log("[*] 文件操作拦截脚本已启动");

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
     * 工具函数：判断是否为敏感文件
     */
    function isSensitiveFile(path) {
        var sensitiveKeywords = [
            "password", "token", "secret", "key", "cert", "credential", "auth",
            "account", "login", "user", "config", "setting", "preference",
            "database", "db", "sqlite", "realm", ".so", "dex", ".xml", ".json"
        ];
        
        var lowercasePath = path.toLowerCase();
        for (var i = 0; i < sensitiveKeywords.length; i++) {
            if (lowercasePath.indexOf(sensitiveKeywords[i]) !== -1) {
                return true;
            }
        }
        
        return false;
    }

    /**
     * 工具函数：读取文件内容
     */
    function readFileContent(path) {
        try {
            var File = Java.use("java.io.File");
            var FileInputStream = Java.use("java.io.FileInputStream");
            var ByteArrayOutputStream = Java.use("java.io.ByteArrayOutputStream");
            
            var file = File.$new(path);
            if (!file.exists() || !file.isFile() || !file.canRead()) {
                return "无法读取文件内容";
            }
            
            // 检查文件大小，避免读取过大的文件
            var fileSize = file.length();
            if (fileSize > 1024 * 100) { // 限制为100KB
                return "文件过大，跳过内容读取 (" + fileSize + " 字节)";
            }
            
            var fis = FileInputStream.$new(file);
            var baos = ByteArrayOutputStream.$new();
            var buffer = Java.array('byte', new Array(1024).fill(0));
            var len;
            
            while ((len = fis.read(buffer)) !== -1) {
                baos.write(buffer, 0, len);
            }
            
            fis.close();
            var content = baos.toString();
            baos.close();
            
            // 尝试判断文件类型
            if (path.endsWith(".json")) {
                try {
                    var JSONObject = Java.use("org.json.JSONObject");
                    var jsonObj = JSONObject.$new(content);
                    return JSON.stringify(JSON.parse(content), null, 2);
                } catch (e) {
                    // 不是有效的JSON，返回原始内容
                    return content;
                }
            } else if (path.endsWith(".xml")) {
                // XML内容直接返回
                return content;
            } else if (/\.(jpg|jpeg|png|gif|bmp)$/i.test(path)) {
                return "[图片文件]";
            } else if (/\.(mp3|wav|ogg|m4a)$/i.test(path)) {
                return "[音频文件]";
            } else if (/\.(mp4|3gp|mkv|avi)$/i.test(path)) {
                return "[视频文件]";
            } else if (/\.(pdf|doc|docx|ppt|pptx|xls|xlsx)$/i.test(path)) {
                return "[文档文件]";
            } else if (/\.(zip|rar|tar|gz|7z)$/i.test(path)) {
                return "[压缩文件]";
            } else if (/\.(so|dex|apk|jar)$/i.test(path)) {
                return "[二进制文件]";
            } else if (/\.(db|sqlite|sqlite3)$/i.test(path)) {
                return "[数据库文件]";
            } else {
                // 尝试判断是否为文本文件
                if (/[\x00-\x08\x0E-\x1F\x7F-\xFF]/.test(content)) {
                    return "[二进制数据]";
                } else {
                    return content;
                }
            }
        } catch (e) {
            return "读取文件内容失败: " + e;
        }
    }

    /**
     * 一、拦截Java标准文件操作类
     */
    
    /**
     * 1. 拦截File类
     */
    var File = Java.use("java.io.File");
    
    // 拦截构造函数
    File.$init.overload("java.lang.String").implementation = function(path) {
        console.log("\n[+] 创建File对象: " + path);
        
        if (isSensitiveFile(path)) {
            console.log("    [!] 检测到可能的敏感文件");
            console.log("    调用堆栈:\n    " + getStackTrace());
        }
        
        return this.$init(path);
    };
    
    // 拦截创建文件
    File.createNewFile.implementation = function() {
        var path = this.getAbsolutePath();
        console.log("\n[+] 创建新文件: " + path);
        console.log("    调用堆栈:\n    " + getStackTrace());
        
        var result = this.createNewFile();
        console.log("    创建结果: " + result);
        return result;
    };
    
    // 拦截删除文件
    File.delete.implementation = function() {
        var path = this.getAbsolutePath();
        console.log("\n[+] 删除文件: " + path);
        console.log("    调用堆栈:\n    " + getStackTrace());
        
        var result = this.delete();
        console.log("    删除结果: " + result);
        return result;
    };
    
    // 拦截文件重命名
    File.renameTo.implementation = function(dest) {
        var srcPath = this.getAbsolutePath();
        var destPath = dest.getAbsolutePath();
        console.log("\n[+] 重命名文件: " + srcPath + " -> " + destPath);
        console.log("    调用堆栈:\n    " + getStackTrace());
        
        var result = this.renameTo(dest);
        console.log("    重命名结果: " + result);
        return result;
    };

    /**
     * 2. 拦截FileInputStream - 文件读取
     */
    var FileInputStream = Java.use("java.io.FileInputStream");
    
    // 拦截构造函数
    FileInputStream.$init.overload("java.io.File").implementation = function(file) {
        var path = file.getAbsolutePath();
        console.log("\n[+] 读取文件: " + path);
        
        if (isSensitiveFile(path)) {
            console.log("    [!] 检测到读取敏感文件");
            console.log("    调用堆栈:\n    " + getStackTrace());
            
            // 读取敏感文件内容
            var fileContent = readFileContent(path);
            console.log("    文件内容: " + fileContent);
        }
        
        return this.$init(file);
    };
    
    FileInputStream.$init.overload("java.lang.String").implementation = function(path) {
        console.log("\n[+] 读取文件: " + path);
        
        if (isSensitiveFile(path)) {
            console.log("    [!] 检测到读取敏感文件");
            console.log("    调用堆栈:\n    " + getStackTrace());
            
            // 读取敏感文件内容
            var fileContent = readFileContent(path);
            console.log("    文件内容: " + fileContent);
        }
        
        return this.$init(path);
    };

    /**
     * 3. 拦截FileOutputStream - 文件写入
     */
    var FileOutputStream = Java.use("java.io.FileOutputStream");
    
    // 拦截构造函数
    FileOutputStream.$init.overload("java.io.File", "boolean").implementation = function(file, append) {
        var path = file.getAbsolutePath();
        console.log("\n[+] 写入文件: " + path + (append ? " (追加模式)" : " (覆盖模式)"));
        
        if (isSensitiveFile(path)) {
            console.log("    [!] 检测到写入敏感文件");
            console.log("    调用堆栈:\n    " + getStackTrace());
        }
        
        return this.$init(file, append);
    };
    
    FileOutputStream.$init.overload("java.lang.String", "boolean").implementation = function(path, append) {
        console.log("\n[+] 写入文件: " + path + (append ? " (追加模式)" : " (覆盖模式)"));
        
        if (isSensitiveFile(path)) {
            console.log("    [!] 检测到写入敏感文件");
            console.log("    调用堆栈:\n    " + getStackTrace());
        }
        
        return this.$init(path, append);
    };
    
    // 拦截写入方法
    FileOutputStream.write.overload("[B").implementation = function(bytes) {
        try {
            var content = Java.use("java.lang.String").$new(bytes);
            console.log("    写入内容: " + content);
        } catch (e) {
            console.log("    写入内容: [二进制数据]");
        }
        
        return this.write(bytes);
    };

    /**
     * 二、拦截Android特有的文件操作
     */
    
    /**
     * 1. 拦截Context.getSharedPreferences
     * 用于访问应用的SharedPreferences文件
     */
    var Context = Java.use("android.content.Context");
    Context.getSharedPreferences.implementation = function(name, mode) {
        console.log("\n[+] 访问SharedPreferences: " + name);
        console.log("    模式: " + mode);
        console.log("    调用堆栈:\n    " + getStackTrace());
        
        return this.getSharedPreferences(name, mode);
    };

    /**
     * 2. 拦截Context.openFileOutput
     * 用于打开应用私有文件进行写入
     */
    Context.openFileOutput.implementation = function(name, mode) {
        console.log("\n[+] 打开应用私有文件进行写入: " + name);
        console.log("    模式: " + mode);
        console.log("    调用堆栈:\n    " + getStackTrace());
        
        return this.openFileOutput(name, mode);
    };

    /**
     * 3. 拦截Context.openFileInput
     * 用于打开应用私有文件进行读取
     */
    Context.openFileInput.implementation = function(name) {
        console.log("\n[+] 打开应用私有文件进行读取: " + name);
        console.log("    调用堆栈:\n    " + getStackTrace());
        
        // 尝试读取文件内容
        try {
            var fileDir = this.getFilesDir().getAbsolutePath();
            var filePath = fileDir + "/" + name;
            var fileContent = readFileContent(filePath);
            console.log("    文件内容: " + fileContent);
        } catch (e) {
            console.log("    无法读取文件内容: " + e);
        }
        
        return this.openFileInput(name);
    };

    /**
     * 4. 拦截Context.deleteFile
     * 用于删除应用私有文件
     */
    Context.deleteFile.implementation = function(name) {
        console.log("\n[+] 删除应用私有文件: " + name);
        console.log("    调用堆栈:\n    " + getStackTrace());
        
        var result = this.deleteFile(name);
        console.log("    删除结果: " + result);
        return result;
    };

    /**
     * 5. 拦截SQLiteDatabase文件操作
     * 用于监控数据库文件的访问
     */
    try {
        var SQLiteDatabase = Java.use("android.database.sqlite.SQLiteDatabase");
        
        SQLiteDatabase.openOrCreateDatabase.overload("java.io.File", "android.database.sqlite.SQLiteDatabase$CursorFactory").implementation = function(file, factory) {
            var path = file.getAbsolutePath();
            console.log("\n[+] 打开或创建SQLite数据库: " + path);
            console.log("    调用堆栈:\n    " + getStackTrace());
            
            return this.openOrCreateDatabase(file, factory);
        };
        
        SQLiteDatabase.openOrCreateDatabase.overload("java.lang.String", "android.database.sqlite.SQLiteDatabase$CursorFactory", "android.database.DatabaseErrorHandler").implementation = function(path, factory, errorHandler) {
            console.log("\n[+] 打开或创建SQLite数据库: " + path);
            console.log("    调用堆栈:\n    " + getStackTrace());
            
            return this.openOrCreateDatabase(path, factory, errorHandler);
        };
        
        console.log("[+] SQLiteDatabase拦截设置完成");
    } catch (e) {
        console.log("[-] SQLiteDatabase拦截设置失败: " + e);
    }

    /**
     * 三、拦截第三方存储库
     */
    
    /**
     * 1. 拦截Realm数据库操作
     */
    try {
        var RealmConfiguration = Java.use("io.realm.RealmConfiguration");
        var Realm = Java.use("io.realm.Realm");
        
        Realm.getInstance.overload("io.realm.RealmConfiguration").implementation = function(config) {
            console.log("\n[+] 打开Realm数据库");
            console.log("    文件名: " + config.getRealmFileName());
            console.log("    路径: " + config.getRealmDirectory());
            console.log("    调用堆栈:\n    " + getStackTrace());
            
            return this.getInstance(config);
        };
        
        console.log("[+] Realm数据库拦截设置完成");
    } catch (e) {
        console.log("[-] Realm可能未被使用: " + e);
    }
    
    /**
     * 2. 拦截MMKV操作
     * 微信开源的高性能键值存储库
     */
    try {
        var MMKV = Java.use("com.tencent.mmkv.MMKV");
        
        MMKV.mmkvWithID.overload("java.lang.String").implementation = function(id) {
            console.log("\n[+] 打开MMKV存储: " + id);
            console.log("    调用堆栈:\n    " + getStackTrace());
            
            return this.mmkvWithID(id);
        };
        
        console.log("[+] MMKV拦截设置完成");
    } catch (e) {
        console.log("[-] MMKV可能未被使用: " + e);
    }

    console.log("[*] 文件操作拦截设置完成");
}); 