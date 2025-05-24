/*
 * 脚本名称：监控反射调用.js
 * 功能：全面监控Java反射调用，包括方法、字段、构造器等反射操作
 * 适用场景：
 *   - 分析混淆代码的行为
 *   - 检测反射调用的敏感API
 *   - 逆向算法和业务逻辑
 *   - 监控反射绕过安全机制的行为
 * 使用方法：
 *   1. frida -U -f 包名 -l 监控反射调用.js --no-pause
 *   2. 查看控制台输出，了解应用的反射调用
 * 启动方式说明：
 *   - -U 代表使用USB连接的设备
 *   - -f 代表以spawn方式启动目标应用（推荐，可捕获启动阶段的反射调用）
 *   - --no-pause 指示Frida不要暂停应用执行
 * 支持特性：
 *   - 监控Method.invoke调用
 *   - 监控Constructor.newInstance调用
 *   - 监控Field的get/set操作
 *   - 监控getDeclaredMethod/getMethod等方法获取
 *   - 参数和返回值的详细显示
 *   - 调用位置追踪
 *   - 敏感API检测
 */

Java.perform(function () {
    // 配置选项
    var config = {
        logLevel: 2,               // 0:关闭 1:错误 2:基本信息 3:详细
        printStack: true,          // 是否打印调用堆栈
        showArguments: true,       // 是否显示参数
        showReturnValue: true,     // 是否显示返回值
        maxStackDepth: 5,          // 最大堆栈深度
        maxArgumentLength: 100,    // 参数和返回值最大显示长度
        filterPackages: [],        // 包名过滤，例如 ["com.example", "com.target"]，空表示不过滤
        sensitiveApis: [           // 需要特别关注的敏感API
            "android.app.ActivityManager",
            "java.lang.Runtime",
            "java.lang.System",
            "android.content.pm.PackageManager",
            "javax.crypto",
            "java.security",
            "android.telephony",
            "android.location"
        ]
    };

    // 计数器
    var stats = {
        methodInvocations: 0,
        constructorInvocations: 0,
        fieldAccess: 0,
        methodLookups: 0
    };

    // 辅助函数：日志输出
    function log(level, message) {
        if (level <= config.logLevel) {
            var prefix = "";
            switch (level) {
                case 1: prefix = "[!] "; break;
                case 2: prefix = "[*] "; break;
                case 3: prefix = "[+] "; break;
            }
            console.log(prefix + message);
        }
    }

    // 辅助函数：获取调用堆栈
    function getStackTrace() {
        if (!config.printStack) return "";
        
        try {
            var exception = Java.use("java.lang.Exception").$new();
            var stackElements = exception.getStackTrace();
            var limit = Math.min(stackElements.length, config.maxStackDepth);
            
            var stack = "\n        调用堆栈:";
            for (var i = 0; i < limit; i++) {
                var element = stackElements[i];
                var className = element.getClassName();
                // 跳过Frida相关的堆栈
                if (className.indexOf("com.android.internal.os") !== -1) continue;
                
                stack += "\n            " + className + "." + 
                         element.getMethodName() + "(" + 
                         (element.getFileName() != null ? element.getFileName() : "Unknown Source") + ":" + 
                         element.getLineNumber() + ")";
            }
            return stack;
            
        } catch (e) {
            return "\n        调用堆栈获取失败: " + e;
        }
    }

    // 辅助函数：格式化对象为字符串
    function formatObject(obj) {
        if (obj === null) return "null";
        if (obj === undefined) return "undefined";
        
        try {
            var objString = obj.toString();
            if (objString.length > config.maxArgumentLength) {
                return objString.substring(0, config.maxArgumentLength) + "... (长度: " + objString.length + ")";
            }
            return objString;
        } catch (e) {
            return "<无法获取对象信息: " + e + ">";
        }
    }

    // 辅助函数：格式化数组
    function formatArray(array) {
        if (array === null) return "null";
        
        try {
            var result = "[";
            var length = Math.min(array.length, 10); // 最多显示10个元素
            
            for (var i = 0; i < length; i++) {
                result += formatObject(array[i]);
                if (i < length - 1) result += ", ";
            }
            
            if (array.length > 10) {
                result += ", ... (共" + array.length + "个元素)";
            }
            
            result += "]";
            return result;
        } catch (e) {
            return "<无法解析数组: " + e + ">";
        }
    }

    // 辅助函数：检测是否为敏感API
    function isSensitiveAPI(className) {
        for (var i = 0; i < config.sensitiveApis.length; i++) {
            if (className.indexOf(config.sensitiveApis[i]) !== -1) {
                return true;
            }
        }
        return false;
    }

    // 辅助函数：是否匹配过滤包名
    function matchesFilter(className) {
        // 如果过滤列表为空，则不过滤
        if (config.filterPackages.length === 0) return true;
        
        for (var i = 0; i < config.filterPackages.length; i++) {
            if (className.indexOf(config.filterPackages[i]) === 0) {
                return true;
            }
        }
        return false;
    }

    // 1. 监控Method.invoke
    var Method = Java.use('java.lang.reflect.Method');
    Method.invoke.implementation = function (obj, args) {
        var className = this.getDeclaringClass().getName();
        var methodName = this.getName();
        
        // 应用过滤规则
        if (!matchesFilter(className)) {
            return this.invoke(obj, args);
        }
        
        stats.methodInvocations++;
        
        var description = '反射调用方法: ' + className + "." + methodName;
        if (isSensitiveAPI(className)) {
            log(1, description + " [敏感API]");
        } else {
            log(2, description);
        }
        
        // 显示参数
        if (config.showArguments && args) {
            log(3, "    参数: " + formatArray(args));
        }
        
        var retVal;
        try {
            retVal = this.invoke(obj, args);
            
            // 显示返回值
            if (config.showReturnValue) {
                log(3, "    返回值: " + formatObject(retVal));
            }
            
            // 显示调用堆栈
            if (config.printStack) {
                log(3, getStackTrace());
            }
            
            return retVal;
        } catch (e) {
            log(1, "    异常: " + e);
            throw e;
        }
    };

    // 2. 监控Constructor.newInstance
    var Constructor = Java.use('java.lang.reflect.Constructor');
    Constructor.newInstance.implementation = function (args) {
        var className = this.getDeclaringClass().getName();
        
        // 应用过滤规则
        if (!matchesFilter(className)) {
            return this.newInstance(args);
        }
        
        stats.constructorInvocations++;
        
        var description = '反射创建实例: ' + className;
        if (isSensitiveAPI(className)) {
            log(1, description + " [敏感API]");
        } else {
            log(2, description);
        }
        
        // 显示参数
        if (config.showArguments && args) {
            log(3, "    构造参数: " + formatArray(args));
        }
        
        var instance;
        try {
            instance = this.newInstance(args);
            
            // 显示调用堆栈
            if (config.printStack) {
                log(3, getStackTrace());
            }
            
            return instance;
        } catch (e) {
            log(1, "    创建实例异常: " + e);
            throw e;
        }
    };

    // 3. 监控Field的获取与设置
    var Field = Java.use('java.lang.reflect.Field');
    
    // 获取字段值
    Field.get.implementation = function (obj) {
        var className = this.getDeclaringClass().getName();
        var fieldName = this.getName();
        
        // 应用过滤规则
        if (!matchesFilter(className)) {
            return this.get(obj);
        }
        
        stats.fieldAccess++;
        
        var objClass = (obj != null) ? obj.getClass().getName() : "静态字段";
        log(2, '反射获取字段: ' + className + "." + fieldName + " (对象类型: " + objClass + ")");
        
        var value;
        try {
            value = this.get(obj);
            
            // 显示字段值
            log(3, "    字段值: " + formatObject(value));
            
            // 显示调用堆栈
            if (config.printStack) {
                log(3, getStackTrace());
            }
            
            return value;
        } catch (e) {
            log(1, "    获取字段异常: " + e);
            throw e;
        }
    };
    
    // 设置字段值
    Field.set.implementation = function (obj, value) {
        var className = this.getDeclaringClass().getName();
        var fieldName = this.getName();
        
        // 应用过滤规则
        if (!matchesFilter(className)) {
            this.set(obj, value);
            return;
        }
        
        stats.fieldAccess++;
        
        var objClass = (obj != null) ? obj.getClass().getName() : "静态字段";
        log(2, '反射设置字段: ' + className + "." + fieldName + " (对象类型: " + objClass + ")");
        
        // 显示新值
        log(3, "    新值: " + formatObject(value));
        
        try {
            this.set(obj, value);
            
            // 显示调用堆栈
            if (config.printStack) {
                log(3, getStackTrace());
            }
        } catch (e) {
            log(1, "    设置字段异常: " + e);
            throw e;
        }
    };

    // 4. 监控获取Method的方法
    var Class = Java.use('java.lang.Class');
    
    // getDeclaredMethod
    Class.getDeclaredMethod.implementation = function (name, paramTypes) {
        var method = this.getDeclaredMethod(name, paramTypes);
        var className = this.getName();
        
        // 应用过滤规则
        if (!matchesFilter(className)) {
            return method;
        }
        
        stats.methodLookups++;
        
        log(3, '获取声明方法: ' + className + "." + name);
        
        // 显示调用堆栈
        if (config.printStack) {
            log(3, getStackTrace());
        }
        
        return method;
    };
    
    // getMethod
    Class.getMethod.implementation = function (name, paramTypes) {
        var method = this.getMethod(name, paramTypes);
        var className = this.getName();
        
        // 应用过滤规则
        if (!matchesFilter(className)) {
            return method;
        }
        
        stats.methodLookups++;
        
        log(3, '获取公共方法: ' + className + "." + name);
        
        return method;
    };
    
    // getMethods
    Class.getMethods.implementation = function () {
        var methods = this.getMethods();
        var className = this.getName();
        
        // 应用过滤规则
        if (!matchesFilter(className)) {
            return methods;
        }
        
        stats.methodLookups++;
        
        log(3, '获取所有公共方法: ' + className + " (数量: " + methods.length + ")");
        
        return methods;
    };

    // 5. 监控getDeclaredConstructor和getConstructor方法
    Class.getDeclaredConstructor.implementation = function (paramTypes) {
        var constructor = this.getDeclaredConstructor(paramTypes);
        var className = this.getName();
        
        // 应用过滤规则
        if (!matchesFilter(className)) {
            return constructor;
        }
        
        log(3, '获取声明构造器: ' + className);
        
        return constructor;
    };
    
    Class.getConstructor.implementation = function (paramTypes) {
        var constructor = this.getConstructor(paramTypes);
        var className = this.getName();
        
        // 应用过滤规则
        if (!matchesFilter(className)) {
            return constructor;
        }
        
        log(3, '获取公共构造器: ' + className);
        
        return constructor;
    };

    // 6. 监控通过反射修改访问权限的操作
    var AccessibleObject = Java.use('java.lang.reflect.AccessibleObject');
    AccessibleObject.setAccessible.overload('boolean').implementation = function (flag) {
        if (flag) {
            var className = "未知";
            try {
                if (this instanceof Method) {
                    var method = Java.cast(this, Method);
                    className = method.getDeclaringClass().getName() + "." + method.getName();
                } else if (this instanceof Field) {
                    var field = Java.cast(this, Field);
                    className = field.getDeclaringClass().getName() + "." + field.getName();
                } else if (this instanceof Constructor) {
                    var ctor = Java.cast(this, Constructor);
                    className = ctor.getDeclaringClass().getName() + " (构造器)";
                }
                log(2, '修改反射对象访问权限: ' + className + " (设置为: " + flag + ")");
                
                // 显示调用堆栈
                if (config.printStack) {
                    log(3, getStackTrace());
                }
            } catch (e) {
                // 忽略转换错误
            }
        }
        
        return this.setAccessible(flag);
    };

    // 打印初始化信息
    log(2, "反射调用监控已启动");
    log(2, "监控范围: Method.invoke, Constructor.newInstance, Field.get/set, 方法查找");
    if (config.filterPackages.length > 0) {
        log(2, "包名过滤: " + config.filterPackages.join(", "));
    }
    log(2, "敏感API监控: " + config.sensitiveApis.length + " 个类别");
    
    // 定期打印统计信息
    setInterval(function() {
        if (stats.methodInvocations > 0 || stats.constructorInvocations > 0 || 
            stats.fieldAccess > 0 || stats.methodLookups > 0) {
            log(2, "反射统计: 方法调用(" + stats.methodInvocations + 
                 "), 构造器调用(" + stats.constructorInvocations + 
                 "), 字段访问(" + stats.fieldAccess + 
                 "), 方法查找(" + stats.methodLookups + ")");
        }
    }, 10000); // 每10秒打印一次
}); 