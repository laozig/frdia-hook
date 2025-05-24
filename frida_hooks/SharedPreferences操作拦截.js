/**
 * SharedPreferences操作拦截脚本
 * 
 * 功能：拦截Android应用中的SharedPreferences操作
 * 作用：监控应用配置文件的读写，包括敏感信息的存储
 * 适用：分析应用配置信息存储，监控账号密码等敏感数据
 */

// 等待Java虚拟机加载完成
Java.perform(function() {
    console.log("[*] SharedPreferences操作拦截脚本已启动");

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
     * 一、拦截SharedPreferences的获取
     */
    var Context = Java.use("android.content.Context");
    
    // 拦截getSharedPreferences方法
    Context.getSharedPreferences.implementation = function(name, mode) {
        console.log("\n[+] Context.getSharedPreferences");
        console.log("    名称: " + name);
        console.log("    模式: " + mode);
        console.log("    调用堆栈:\n    " + getStackTrace());
        
        return this.getSharedPreferences(name, mode);
    };

    /**
     * 二、拦截SharedPreferences的读操作
     */
    var SharedPreferences = Java.use("android.content.SharedPreferences");
    
    // 拦截getString方法
    SharedPreferences.getString.implementation = function(key, defValue) {
        var value = this.getString(key, defValue);
        console.log("\n[+] SharedPreferences.getString");
        console.log("    键: " + key);
        console.log("    值: " + value);
        console.log("    默认值: " + defValue);
        console.log("    调用堆栈:\n    " + getStackTrace());
        
        return value;
    };
    
    // 拦截getInt方法
    SharedPreferences.getInt.implementation = function(key, defValue) {
        var value = this.getInt(key, defValue);
        console.log("\n[+] SharedPreferences.getInt");
        console.log("    键: " + key);
        console.log("    值: " + value);
        console.log("    默认值: " + defValue);
        console.log("    调用堆栈:\n    " + getStackTrace());
        
        return value;
    };
    
    // 拦截getLong方法
    SharedPreferences.getLong.implementation = function(key, defValue) {
        var value = this.getLong(key, defValue);
        console.log("\n[+] SharedPreferences.getLong");
        console.log("    键: " + key);
        console.log("    值: " + value);
        console.log("    默认值: " + defValue);
        console.log("    调用堆栈:\n    " + getStackTrace());
        
        return value;
    };
    
    // 拦截getFloat方法
    SharedPreferences.getFloat.implementation = function(key, defValue) {
        var value = this.getFloat(key, defValue);
        console.log("\n[+] SharedPreferences.getFloat");
        console.log("    键: " + key);
        console.log("    值: " + value);
        console.log("    默认值: " + defValue);
        console.log("    调用堆栈:\n    " + getStackTrace());
        
        return value;
    };
    
    // 拦截getBoolean方法
    SharedPreferences.getBoolean.implementation = function(key, defValue) {
        var value = this.getBoolean(key, defValue);
        console.log("\n[+] SharedPreferences.getBoolean");
        console.log("    键: " + key);
        console.log("    值: " + value);
        console.log("    默认值: " + defValue);
        console.log("    调用堆栈:\n    " + getStackTrace());
        
        return value;
    };
    
    // 拦截getStringSet方法
    SharedPreferences.getStringSet.implementation = function(key, defValues) {
        var value = this.getStringSet(key, defValues);
        console.log("\n[+] SharedPreferences.getStringSet");
        console.log("    键: " + key);
        
        if (value) {
            var valueArray = [];
            var iterator = value.iterator();
            while (iterator.hasNext()) {
                valueArray.push(iterator.next());
            }
            console.log("    值: " + JSON.stringify(valueArray));
        } else {
            console.log("    值: null");
        }
        
        console.log("    调用堆栈:\n    " + getStackTrace());
        
        return value;
    };
    
    // 拦截getAll方法
    SharedPreferences.getAll.implementation = function() {
        var map = this.getAll();
        console.log("\n[+] SharedPreferences.getAll");
        
        if (map) {
            var entries = {};
            var keySet = map.keySet();
            var iterator = keySet.iterator();
            
            while (iterator.hasNext()) {
                var key = iterator.next();
                var value = map.get(key);
                entries[key] = value ? value.toString() : "null";
            }
            
            console.log("    所有键值对: " + JSON.stringify(entries, null, 2));
        } else {
            console.log("    所有键值对: null");
        }
        
        console.log("    调用堆栈:\n    " + getStackTrace());
        
        return map;
    };
    
    // 拦截contains方法
    SharedPreferences.contains.implementation = function(key) {
        var result = this.contains(key);
        console.log("\n[+] SharedPreferences.contains");
        console.log("    键: " + key);
        console.log("    结果: " + result);
        console.log("    调用堆栈:\n    " + getStackTrace());
        
        return result;
    };

    /**
     * 三、拦截SharedPreferences的写操作
     */
    var SharedPreferences_Editor = Java.use("android.content.SharedPreferences$Editor");
    
    // 拦截putString方法
    SharedPreferences_Editor.putString.implementation = function(key, value) {
        console.log("\n[+] SharedPreferences.Editor.putString");
        console.log("    键: " + key);
        console.log("    值: " + value);
        console.log("    调用堆栈:\n    " + getStackTrace());
        
        return this.putString(key, value);
    };
    
    // 拦截putInt方法
    SharedPreferences_Editor.putInt.implementation = function(key, value) {
        console.log("\n[+] SharedPreferences.Editor.putInt");
        console.log("    键: " + key);
        console.log("    值: " + value);
        console.log("    调用堆栈:\n    " + getStackTrace());
        
        return this.putInt(key, value);
    };
    
    // 拦截putLong方法
    SharedPreferences_Editor.putLong.implementation = function(key, value) {
        console.log("\n[+] SharedPreferences.Editor.putLong");
        console.log("    键: " + key);
        console.log("    值: " + value);
        console.log("    调用堆栈:\n    " + getStackTrace());
        
        return this.putLong(key, value);
    };
    
    // 拦截putFloat方法
    SharedPreferences_Editor.putFloat.implementation = function(key, value) {
        console.log("\n[+] SharedPreferences.Editor.putFloat");
        console.log("    键: " + key);
        console.log("    值: " + value);
        console.log("    调用堆栈:\n    " + getStackTrace());
        
        return this.putFloat(key, value);
    };
    
    // 拦截putBoolean方法
    SharedPreferences_Editor.putBoolean.implementation = function(key, value) {
        console.log("\n[+] SharedPreferences.Editor.putBoolean");
        console.log("    键: " + key);
        console.log("    值: " + value);
        console.log("    调用堆栈:\n    " + getStackTrace());
        
        return this.putBoolean(key, value);
    };
    
    // 拦截putStringSet方法
    SharedPreferences_Editor.putStringSet.implementation = function(key, values) {
        console.log("\n[+] SharedPreferences.Editor.putStringSet");
        console.log("    键: " + key);
        
        if (values) {
            var valueArray = [];
            var iterator = values.iterator();
            while (iterator.hasNext()) {
                valueArray.push(iterator.next());
            }
            console.log("    值: " + JSON.stringify(valueArray));
        } else {
            console.log("    值: null");
        }
        
        console.log("    调用堆栈:\n    " + getStackTrace());
        
        return this.putStringSet(key, values);
    };
    
    // 拦截remove方法
    SharedPreferences_Editor.remove.implementation = function(key) {
        console.log("\n[+] SharedPreferences.Editor.remove");
        console.log("    键: " + key);
        console.log("    调用堆栈:\n    " + getStackTrace());
        
        return this.remove(key);
    };
    
    // 拦截clear方法
    SharedPreferences_Editor.clear.implementation = function() {
        console.log("\n[+] SharedPreferences.Editor.clear");
        console.log("    调用堆栈:\n    " + getStackTrace());
        
        return this.clear();
    };
    
    // 拦截commit方法
    SharedPreferences_Editor.commit.implementation = function() {
        console.log("\n[+] SharedPreferences.Editor.commit");
        console.log("    调用堆栈:\n    " + getStackTrace());
        
        var result = this.commit();
        console.log("    提交结果: " + result);
        
        return result;
    };
    
    // 拦截apply方法
    SharedPreferences_Editor.apply.implementation = function() {
        console.log("\n[+] SharedPreferences.Editor.apply");
        console.log("    调用堆栈:\n    " + getStackTrace());
        
        return this.apply();
    };

    /**
     * 四、拦截EncryptedSharedPreferences（如果使用）
     * 这是AndroidX安全库中的加密SharedPreferences实现
     */
    try {
        var EncryptedSharedPreferences = Java.use("androidx.security.crypto.EncryptedSharedPreferences");
        
        // 拦截create方法
        EncryptedSharedPreferences.create.overload(
            "java.lang.String", 
            "android.security.keystore.KeyGenParameterSpec", 
            "android.content.Context"
        ).implementation = function(fileName, keyGenParameterSpec, context) {
            console.log("\n[+] EncryptedSharedPreferences.create");
            console.log("    文件名: " + fileName);
            console.log("    调用堆栈:\n    " + getStackTrace());
            
            return this.create(fileName, keyGenParameterSpec, context);
        };
        
        console.log("[+] EncryptedSharedPreferences拦截设置完成");
    } catch (e) {
        console.log("[-] EncryptedSharedPreferences可能未被使用: " + e);
    }

    console.log("[*] SharedPreferences操作拦截设置完成");
}); 