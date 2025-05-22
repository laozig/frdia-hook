/**
 * Frida系统函数监控模块
 * 监控常用Java/Android系统函数的调用，包括集合操作、字符串处理、日志和UI交互等
 */

module.exports = function(userConfig, logger, utils) {
    const tag = "SYSTEM";
    
    // 默认配置
    const defaultConfig = {
        enableAllCategories: true,
        logParameters: true,
        logReturnValues: true,
        maxDataSize: 1024,
        stackTraceDepth: 3,
        customHooks: [],
        excludeStackPatterns: []
    };
    
    // 合并用户配置
    const config = Object.assign({}, defaultConfig, userConfig || {});
    
    // 类别状态
    const categories = {
        COLLECTIONS: true,           // 集合操作
        STRING_PROCESSING: true,     // 字符串处理
        ENCODING: true,              // 编解码和加密
        SYSTEM_INTERACTION: true     // 系统交互
    };
    
    // 自定义钩子
    const customHooks = [];
    
    // 排除特定调用栈源
    const excludeStackPatterns = [];
    
    // 方法过滤器
    let methodFilters = {};
    
    // 初始化模块
    function initialize() {
        logger.info(tag, "系统函数监控模块初始化");
        
        // 设置类别状态
        if (!config.enableAllCategories) {
            Object.keys(categories).forEach(category => {
                categories[category] = false;
            });
        }
        
        // 添加自定义钩子
        if (Array.isArray(config.customHooks)) {
            config.customHooks.forEach(hook => {
                addCustomHook(hook);
            });
        }
        
        // 添加排除模式
        if (Array.isArray(config.excludeStackPatterns)) {
            config.excludeStackPatterns.forEach(pattern => {
                addExcludeStackPattern(pattern);
            });
        }
        
        // 开始监控
        Java.perform(setupAllHooks);
    }
    
    // 设置所有钩子函数
    function setupAllHooks() {
        logger.debug(tag, "正在设置系统函数钩子");
        
        try {
            // 设置集合类钩子
            if (categories.COLLECTIONS) {
                setupCollectionHooks();
            }
            
            // 设置字符串处理钩子
            if (categories.STRING_PROCESSING) {
                setupStringHooks();
            }
            
            // 设置编解码钩子
            if (categories.ENCODING) {
                setupEncodingHooks();
            }
            
            // 设置系统交互钩子
            if (categories.SYSTEM_INTERACTION) {
                setupSystemInteractionHooks();
            }
            
            // 设置自定义钩子
            setupCustomHooks();
            
            logger.info(tag, "系统函数钩子设置完成");
        } catch (error) {
            logger.error(tag, "设置系统函数钩子时出错: " + error);
        }
    }
    
    // 设置集合类钩子
    function setupCollectionHooks() {
        // HashMap
        hookClass("java.util.HashMap", ["put", "get", "remove", "clear", "containsKey", "size"], "COLLECTIONS");
        
        // LinkedHashMap
        hookClass("java.util.LinkedHashMap", ["put", "get", "remove", "clear"], "COLLECTIONS");
        
        // ArrayList
        hookClass("java.util.ArrayList", ["add", "addAll", "set", "remove", "clear", "get", "size", "contains"], "COLLECTIONS");
        
        // Collections
        hookJavaStaticMethods("java.util.Collections", ["sort", "shuffle", "reverse", "unmodifiableList", "unmodifiableMap"], "COLLECTIONS");
        
        // HashSet
        try {
            hookClass("java.util.HashSet", ["add", "remove", "contains", "clear"], "COLLECTIONS");
        } catch (e) {
            logger.debug(tag, "HashSet类不可用: " + e);
        }
        
        // TreeMap
        try {
            hookClass("java.util.TreeMap", ["put", "get", "remove"], "COLLECTIONS");
        } catch (e) {
            logger.debug(tag, "TreeMap类不可用: " + e);
        }
    }
    
    // 设置字符串处理钩子
    function setupStringHooks() {
        // String
        hookJavaMethods("java.lang.String", ["getBytes", "substring", "split", "replace", "replaceAll", "matches", "trim", "toLowerCase", "toUpperCase"], "STRING_PROCESSING");
        
        // String constructors
        const String = Java.use("java.lang.String");
        
        String.$init.overload("[B").implementation = function(bytes) {
            const result = this.$init(bytes);
            logMethodCall("java.lang.String.<init>", "STRING_PROCESSING", [{ name: "bytes", value: bytes }], this);
            return result;
        };
        
        String.$init.overload("[B", "java.lang.String").implementation = function(bytes, charset) {
            const result = this.$init(bytes, charset);
            logMethodCall("java.lang.String.<init>", "STRING_PROCESSING", [
                { name: "bytes", value: bytes },
                { name: "charset", value: charset }
            ], this);
            return result;
        };
        
        String.$init.overload("[B", "int", "int").implementation = function(bytes, offset, length) {
            const result = this.$init(bytes, offset, length);
            logMethodCall("java.lang.String.<init>", "STRING_PROCESSING", [
                { name: "bytes", value: bytes },
                { name: "offset", value: offset },
                { name: "length", value: length }
            ], this);
            return result;
        };
        
        // StringBuilder
        hookClass("java.lang.StringBuilder", ["append", "toString", "insert", "delete", "replace"], "STRING_PROCESSING");
        
        // StringBuffer
        try {
            hookClass("java.lang.StringBuffer", ["append", "toString", "insert", "delete", "replace"], "STRING_PROCESSING");
        } catch (e) {
            logger.debug(tag, "StringBuffer类不可用: " + e);
        }
        
        // TextUtils
        hookJavaStaticMethods("android.text.TextUtils", ["isEmpty", "equals", "join", "split", "htmlEncode"], "STRING_PROCESSING");
        
        // Pattern/Matcher
        try {
            hookJavaStaticMethods("java.util.regex.Pattern", ["compile", "matches"], "STRING_PROCESSING");
            hookJavaMethods("java.util.regex.Matcher", ["find", "group", "matches"], "STRING_PROCESSING");
        } catch (e) {
            logger.debug(tag, "Pattern/Matcher类不可用: " + e);
        }
    }
    
    // 设置编解码钩子
    function setupEncodingHooks() {
        // Base64
        try {
            // Android的Base64
            hookJavaStaticMethods("android.util.Base64", ["encode", "decode", "encodeToString"], "ENCODING");
        } catch (e) {
            logger.debug(tag, "Android Base64类不可用: " + e);
        }
        
        // Java 8+ Base64
        try {
            hookJavaStaticMethods("java.util.Base64", ["getEncoder", "getDecoder"], "ENCODING");
            
            try {
                const Base64Encoder = Java.use("java.util.Base64$Encoder");
                hookJavaMethods(Base64Encoder.class.getName(), ["encode", "encodeToString"], "ENCODING");
                
                const Base64Decoder = Java.use("java.util.Base64$Decoder");
                hookJavaMethods(Base64Decoder.class.getName(), ["decode"], "ENCODING");
            } catch (e) {
                logger.debug(tag, "Java 8 Base64编解码器方法不可用: " + e);
            }
        } catch (e) {
            logger.debug(tag, "Java 8 Base64类不可用: " + e);
        }
        
        // GZIP compression
        try {
            hookConstructor("java.util.zip.GZIPOutputStream", ["java.io.OutputStream"], "ENCODING");
            hookConstructor("java.util.zip.GZIPInputStream", ["java.io.InputStream"], "ENCODING");
            
            // 额外监控写入和读取方法
            hookJavaMethods("java.util.zip.GZIPOutputStream", ["write", "finish", "close"], "ENCODING");
            hookJavaMethods("java.util.zip.GZIPInputStream", ["read", "close"], "ENCODING");
        } catch (e) {
            logger.debug(tag, "GZIP类不可用: " + e);
        }
        
        // URL编解码
        try {
            hookJavaStaticMethods("java.net.URLEncoder", ["encode"], "ENCODING");
            hookJavaStaticMethods("java.net.URLDecoder", ["decode"], "ENCODING");
        } catch (e) {
            logger.debug(tag, "URL编解码类不可用: " + e);
        }
        
        // 十六进制转换
        try {
            // Android系统十六进制工具
            hookJavaStaticMethods("android.util.HexDump", ["dumpHexString", "toHexString"], "ENCODING");
        } catch (e) {
            logger.debug(tag, "HexDump类不可用: " + e);
        }
    }
    
    // 设置系统交互钩子
    function setupSystemInteractionHooks() {
        // 日志
        hookJavaStaticMethods("android.util.Log", ["v", "d", "i", "w", "e"], "SYSTEM_INTERACTION");
        
        // Toast
        hookJavaMethods("android.widget.Toast", ["show"], "SYSTEM_INTERACTION");
        hookJavaStaticMethods("android.widget.Toast", ["makeText"], "SYSTEM_INTERACTION");
        
        // Handler
        try {
            hookJavaMethods("android.os.Handler", ["sendMessage", "post", "postDelayed"], "SYSTEM_INTERACTION");
        } catch (e) {
            logger.debug(tag, "Handler类不可用: " + e);
        }
        
        // Dialog
        try {
            hookJavaMethods("android.app.AlertDialog", ["show", "setMessage", "setTitle"], "SYSTEM_INTERACTION");
            hookJavaMethods("android.app.AlertDialog$Builder", ["setMessage", "setTitle", "setPositiveButton", "setNegativeButton"], "SYSTEM_INTERACTION");
        } catch (e) {
            logger.debug(tag, "AlertDialog类不可用: " + e);
        }
        
        // Clipboard
        try {
            const clipboardManager = Java.use("android.content.ClipboardManager");
            hookJavaMethods(clipboardManager.class.getName(), ["setPrimaryClip", "getPrimaryClip"], "SYSTEM_INTERACTION");
        } catch (e) {
            logger.debug(tag, "ClipboardManager类不可用: " + e);
        }
    }
    
    // 设置自定义钩子
    function setupCustomHooks() {
        customHooks.forEach(hook => {
            try {
                if (!hook.className || !hook.methodName) {
                    return;
                }
                
                const clazz = Java.use(hook.className);
                const methodName = hook.methodName;
                
                if (typeof clazz[methodName] === 'undefined') {
                    logger.error(tag, `方法 ${hook.className}.${methodName} 不存在`);
                    return;
                }
                
                if (typeof clazz[methodName].overloads === 'undefined') {
                    logger.error(tag, `无法获取 ${hook.className}.${methodName} 的重载方法`);
                    return;
                }
                
                clazz[methodName].overloads.forEach(overload => {
                    overload.implementation = function() {
                        const args = [];
                        for (let i = 0; i < arguments.length; i++) {
                            args.push({ name: `arg${i}`, value: arguments[i] });
                        }
                        
                        const result = this[methodName].apply(this, arguments);
                        logMethodCall(`${hook.className}.${methodName}`, "CUSTOM", args, result);
                        return result;
                    };
                });
                
                logger.debug(tag, `自定义钩子设置成功: ${hook.className}.${methodName}`);
            } catch (error) {
                logger.error(tag, `设置自定义钩子 ${hook.className}.${methodName} 时出错: ${error}`);
            }
        });
    }
    
    // 通用类方法钩子
    function hookClass(className, methodNames, category) {
        try {
            const clazz = Java.use(className);
            
            methodNames.forEach(methodName => {
                // 检查是否应该过滤此方法
                if (shouldFilterMethod(className, methodName)) {
                    try {
                        clazz[methodName].overloads.forEach(overload => {
                            const paramTypes = overload.argumentTypes.map(type => type.className);
                            const methodSig = `${methodName}(${paramTypes.join(",")})`;
                            
                            overload.implementation = function() {
                                const args = [];
                                for (let i = 0; i < arguments.length; i++) {
                                    args.push({ name: overload.argumentTypes[i].name || `arg${i}`, value: arguments[i] });
                                }
                                
                                const retVal = this[methodName].apply(this, arguments);
                                logMethodCall(`${className}.${methodSig}`, category, args, retVal);
                                return retVal;
                            };
                        });
                        
                        logger.debug(tag, `类方法Hook成功: ${className}.${methodName}`);
                    } catch (methodError) {
                        logger.error(tag, `Hook方法 ${className}.${methodName} 出错: ${methodError}`);
                    }
                }
            });
        } catch (classError) {
            logger.debug(tag, `类 ${className} 不可用或无法Hook: ${classError}`);
        }
    }
    
    // 通用Java实例方法钩子
    function hookJavaMethods(className, methodNames, category) {
        try {
            const clazz = Java.use(className);
            
            methodNames.forEach(methodName => {
                // 检查是否应该过滤此方法
                if (shouldFilterMethod(className, methodName)) {
                    try {
                        clazz[methodName].overloads.forEach(overload => {
                            overload.implementation = function() {
                                const args = [];
                                for (let i = 0; i < arguments.length; i++) {
                                    args.push({ name: overload.argumentTypes[i].name || `arg${i}`, value: arguments[i] });
                                }
                                
                                const retVal = this[methodName].apply(this, arguments);
                                logMethodCall(`${className}.${methodName}`, category, args, retVal);
                                return retVal;
                            };
                        });
                        
                        logger.debug(tag, `实例方法Hook成功: ${className}.${methodName}`);
                    } catch (methodError) {
                        logger.error(tag, `Hook方法 ${className}.${methodName} 出错: ${methodError}`);
                    }
                }
            });
        } catch (classError) {
            logger.debug(tag, `类 ${className} 不可用或无法Hook: ${classError}`);
        }
    }
    
    // 通用Java静态方法钩子
    function hookJavaStaticMethods(className, methodNames, category) {
        try {
            const clazz = Java.use(className);
            
            methodNames.forEach(methodName => {
                // 检查是否应该过滤此方法
                if (shouldFilterMethod(className, methodName)) {
                    try {
                        clazz[methodName].overloads.forEach(overload => {
                            overload.implementation = function() {
                                const args = [];
                                for (let i = 0; i < arguments.length; i++) {
                                    args.push({ name: overload.argumentTypes[i].name || `arg${i}`, value: arguments[i] });
                                }
                                
                                const retVal = this[methodName].apply(this, arguments);
                                logMethodCall(`${className}.${methodName}`, category, args, retVal);
                                return retVal;
                            };
                        });
                        
                        logger.debug(tag, `静态方法Hook成功: ${className}.${methodName}`);
                    } catch (methodError) {
                        logger.error(tag, `Hook方法 ${className}.${methodName} 出错: ${methodError}`);
                    }
                }
            });
        } catch (classError) {
            logger.debug(tag, `类 ${className} 不可用或无法Hook: ${classError}`);
        }
    }
    
    // 构造函数钩子
    function hookConstructor(className, paramTypes, category) {
        try {
            const clazz = Java.use(className);
            
            if (!paramTypes || paramTypes.length === 0) {
                // 默认构造函数
                clazz.$init.overload().implementation = function() {
                    const result = this.$init();
                    logMethodCall(`${className}.<init>`, category, [], this);
                    return result;
                };
                logger.debug(tag, `构造函数Hook成功: ${className}.<init>()`);
                return;
            }
            
            // 特定参数构造函数
            clazz.$init.overload.apply(clazz.$init, paramTypes).implementation = function() {
                const args = [];
                for (let i = 0; i < arguments.length; i++) {
                    args.push({ name: `arg${i}`, value: arguments[i] });
                }
                
                const result = this.$init.apply(this, arguments);
                logMethodCall(`${className}.<init>`, category, args, this);
                return result;
            };
            
            logger.debug(tag, `构造函数Hook成功: ${className}.<init>(${paramTypes.join(',')})`);
        } catch (error) {
            logger.debug(tag, `Hook构造函数 ${className}.<init>(${paramTypes ? paramTypes.join(',') : ''}) 出错: ${error}`);
        }
    }
    
    // 记录方法调用
    function logMethodCall(methodName, category, args, returnValue) {
        // 检查是否应该记录此调用
        if (!shouldLogCall(methodName, category)) {
            return;
        }
        
        // 获取调用栈
        const stackTrace = getStackTrace();
        
        // 检查是否应该排除此调用栈
        if (shouldExcludeStack(stackTrace)) {
            return;
        }
        
        // 记录方法调用
        logger.info(tag, `函数调用: ${methodName}`);
        
        // 从调用栈中提取最相关的调用方
        if (stackTrace && stackTrace.length > 0) {
            logger.info(tag, `调用位置: ${stackTrace[0]}`);
        }
        
        // 记录参数
        if (config.logParameters && args && args.length > 0) {
            const paramsObj = {};
            args.forEach(arg => {
                paramsObj[arg.name] = formatValue(arg.value);
            });
            logger.debug(tag, `参数: ${JSON.stringify(paramsObj, null, 2)}`);
        }
        
        // 记录返回值
        if (config.logReturnValues && returnValue !== undefined) {
            logger.debug(tag, `返回值: ${formatValue(returnValue)}`);
        }
        
        // 记录完整调用栈（如果启用）
        if (stackTrace && stackTrace.length > 1) {
            logger.debug(tag, `调用栈: \n${stackTrace.join('\n')}`);
        }
        
        logger.debug(tag, "-------------------");
    }
    
    // 格式化值输出
    function formatValue(value) {
        if (value === null) {
            return "null";
        }
        
        if (value === undefined) {
            return "undefined";
        }
        
        try {
            // 对于字节数组特殊处理
            if (value.$className === "java.lang.String") {
                if (value.length() > config.maxDataSize) {
                    return `${value.substring(0, config.maxDataSize)}... (长度:${value.length()})`;
                }
                return value.toString();
            } else if (Array.isArray(value) || value.type === "array") {
                return `[${value.constructor.name}, 长度:${value.length}]`;
            } else if (value.$className && value.$className.startsWith("java.")) {
                return `[${value.$className}]`;
            } else if (typeof value === "object") {
                return JSON.stringify(value).substring(0, config.maxDataSize);
            }
            
            return String(value).substring(0, config.maxDataSize);
        } catch (e) {
            return `[Object:${typeof value}]`;
        }
    }
    
    // 获取调用栈信息
    function getStackTrace() {
        if (config.stackTraceDepth <= 0) {
            return [];
        }
        
        try {
            const Exception = Java.use("java.lang.Exception");
            const exception = Exception.$new();
            const stackElements = exception.getStackTrace();
            exception.$dispose();
            
            const result = [];
            let skipCount = 0;
            
            // 跳过Frida和本模块调用栈
            for (let i = 0; i < stackElements.length; i++) {
                const element = stackElements[i];
                const className = element.getClassName();
                
                if (className.indexOf("com.android.internal.os") >= 0 ||
                    className.indexOf("dalvik.system") >= 0 ||
                    className.indexOf("java.lang.reflect") >= 0) {
                    skipCount++;
                } else {
                    break;
                }
            }
            
            // 获取有效调用栈
            for (let i = skipCount; i < stackElements.length && result.length < config.stackTraceDepth; i++) {
                const element = stackElements[i];
                const className = element.getClassName();
                const methodName = element.getMethodName();
                const fileName = element.getFileName();
                const lineNumber = element.getLineNumber();
                
                result.push(`${className}.${methodName}(${fileName}:${lineNumber})`);
            }
            
            return result;
        } catch (e) {
            logger.debug(tag, `获取调用栈失败: ${e}`);
            return [];
        }
    }
    
    // 检查是否应该记录这个函数调用
    function shouldLogCall(methodName, category) {
        return categories[category] === true;
    }
    
    // 检查是否应该过滤这个方法
    function shouldFilterMethod(className, methodName) {
        if (!methodFilters[className]) {
            return true;
        }
        
        // 如果存在过滤设置，则只监控指定的方法
        return methodFilters[className].indexOf(methodName) !== -1;
    }
    
    // 检查是否应该排除这个调用栈
    function shouldExcludeStack(stackTrace) {
        if (!stackTrace || stackTrace.length === 0 || excludeStackPatterns.length === 0) {
            return false;
        }
        
        for (let i = 0; i < stackTrace.length; i++) {
            const stackLine = stackTrace[i];
            for (let j = 0; j < excludeStackPatterns.length; j++) {
                if (stackLine.indexOf(excludeStackPatterns[j]) !== -1) {
                    return true;
                }
            }
        }
        
        return false;
    }
    
    // 启用/禁用特定类别
    function enableCategory(category, enabled) {
        if (categories.hasOwnProperty(category)) {
            categories[category] = !!enabled;
            logger.debug(tag, `类别 ${category} 现在已${enabled ? '启用' : '禁用'}`);
        } else {
            logger.error(tag, `类别 ${category} 不存在`);
        }
    }
    
    // 仅启用指定的类别，禁用其他所有类别
    function enableOnly(categoryList) {
        // 先禁用所有类别
        Object.keys(categories).forEach(category => {
            categories[category] = false;
        });
        
        // 启用指定类别
        if (Array.isArray(categoryList)) {
            categoryList.forEach(category => {
                if (categories.hasOwnProperty(category)) {
                    categories[category] = true;
                    logger.debug(tag, `类别 ${category} 已启用`);
                } else {
                    logger.error(tag, `类别 ${category} 不存在`);
                }
            });
        }
    }
    
    // 禁用所有类别
    function disableAllCategories() {
        Object.keys(categories).forEach(category => {
            categories[category] = false;
        });
        logger.debug(tag, "已禁用所有类别");
    }
    
    // 添加自定义钩子
    function addCustomHook(hook) {
        if (!hook.className || !hook.methodName) {
            logger.error(tag, "添加自定义钩子：缺少className或methodName");
            return;
        }
        
        // 规范化钩子选项
        const normalizedHook = {
            className: hook.className,
            methodName: hook.methodName,
            parameterLogging: hook.parameterLogging !== false,
            returnValueLogging: hook.returnValueLogging !== false
        };
        
        customHooks.push(normalizedHook);
        logger.debug(tag, `已添加自定义钩子: ${normalizedHook.className}.${normalizedHook.methodName}`);
        
        // 如果Java已准备就绪，立即设置钩子
        if (Java.available) {
            Java.perform(() => {
                try {
                    const clazz = Java.use(normalizedHook.className);
                    const methodName = normalizedHook.methodName;
                    
                    if (typeof clazz[methodName] !== 'undefined' && clazz[methodName].overloads) {
                        clazz[methodName].overloads.forEach(overload => {
                            overload.implementation = function() {
                                const args = [];
                                for (let i = 0; i < arguments.length; i++) {
                                    args.push({ name: `arg${i}`, value: arguments[i] });
                                }
                                
                                const result = this[methodName].apply(this, arguments);
                                logMethodCall(`${normalizedHook.className}.${methodName}`, "CUSTOM", args, result);
                                return result;
                            };
                        });
                        
                        logger.debug(tag, `实时添加的自定义钩子已设置: ${normalizedHook.className}.${methodName}`);
                    }
                } catch (e) {
                    logger.error(tag, `实时设置自定义钩子失败: ${e}`);
                }
            });
        }
    }
    
    // 添加排除堆栈模式
    function addExcludeStackPattern(pattern) {
        if (pattern && typeof pattern === 'string') {
            excludeStackPatterns.push(pattern);
            logger.debug(tag, `已添加排除堆栈模式: ${pattern}`);
        }
    }
    
    // 设置方法过滤器
    function setMethodFilter(filters) {
        if (filters && typeof filters === 'object') {
            methodFilters = filters;
            logger.debug(tag, `已设置方法过滤器: ${JSON.stringify(filters)}`);
        }
    }
    
    // 设置是否记录参数
    function setLogParameters(enabled) {
        config.logParameters = !!enabled;
        logger.debug(tag, `参数记录已${enabled ? '启用' : '禁用'}`);
    }
    
    // 设置是否记录返回值
    function setLogReturnValues(enabled) {
        config.logReturnValues = !!enabled;
        logger.debug(tag, `返回值记录已${enabled ? '启用' : '禁用'}`);
    }
    
    // 设置数据记录的最大大小
    function setMaxDataSize(size) {
        if (typeof size === 'number' && size > 0) {
            config.maxDataSize = size;
            logger.debug(tag, `数据记录的最大大小已设置为: ${size}`);
        } else {
            logger.error(tag, `无效的数据大小: ${size}`);
        }
    }
    
    // 设置调用栈深度
    function setStackTraceDepth(depth) {
        if (typeof depth === 'number' && depth >= 0) {
            config.stackTraceDepth = depth;
            logger.debug(tag, `调用栈深度已设置为: ${depth}`);
        } else {
            logger.error(tag, `无效的调用栈深度: ${depth}`);
        }
    }
    
    // 初始化模块
    initialize();
    
    // 导出公共接口
    return {
        enableCategory,
        enableOnly,
        disableAllCategories,
        addCustomHook,
        addExcludeStackPattern,
        setMethodFilter,
        setLogParameters,
        setLogReturnValues,
        setMaxDataSize,
        setStackTraceDepth
    };
}; 