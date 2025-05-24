/*
 * 脚本名称：通杀JNI函数调用.js
 * 功能：自动监控所有JNI RegisterNatives注册的函数调用，辅助分析Java与Native交互
 * 适用场景：so逆向、动态注册native分析、协议分析
 * 使用方法：
 *   1. frida -U -f 包名 -l 通杀JNI函数调用.js --no-pause
 *   2. 查看控制台输出，获取JNI注册信息
 * 启动方式说明：
 *   - -U 代表使用USB连接的设备
 *   - -f 代表以spawn方式启动目标应用（推荐，可以捕获启动阶段的JNI注册）
 *   - --no-pause 指示Frida不要暂停应用执行，保证App正常运行
 *   - 也可使用 -F 以attach方式附加到已运行的进程
 * 参数说明：
 *   - 包名：目标应用的包名，如com.example.app
 * RegisterNatives函数详解：
 *   - 原型：jint RegisterNatives(JNIEnv* env, jclass clazz, const JNINativeMethod* methods, jint nMethods)
 *   - 参数：
 *     - env: JNI环境指针
 *     - clazz: 注册本地方法的Java类
 *     - methods: JNINativeMethod结构体数组，包含方法名、签名和函数指针
 *     - nMethods: 注册方法的数量
 *   - JNINativeMethod结构体：
 *     struct JNINativeMethod {
 *         const char* name;       // Java中的方法名
 *         const char* signature;  // 方法签名（参数和返回类型）
 *         void*       fnPtr;      // 本地函数指针
 *     }
 * 方法签名格式说明：
 *   - 参数类型：
 *     - Z: boolean
 *     - B: byte
 *     - C: char
 *     - S: short
 *     - I: int
 *     - J: long
 *     - F: float
 *     - D: double
 *     - L全限定类名;: 对象类型，如Ljava/lang/String;
 *     - [类型: 数组类型，如[I表示int[]
 *   - 返回类型：使用相同的编码，V表示void
 *   - 示例：(Ljava/lang/String;I)Z 表示接收String和int参数，返回boolean
 * 功能特性：
 *   - 自动解析动态注册的JNI方法
 *   - 提取方法名、签名和函数地址
 *   - 自动将so地址转换为模块偏移，便于静态分析
 *   - 可选择性Hook动态注册的函数
 * 注意事项：
 *   - 某些加固应用需配合反检测脚本使用
 *   - 复杂方法签名可能需要手动解析
 *   - 多个SO库可能都会调用RegisterNatives
 *   - 可能需要配合dump_动态注册native.js使用
 */

// 通杀JNI函数调用
// 全局变量，用于存储已注册的native方法信息
var registeredMethods = {};
var lastHookedClasses = [];

// 辅助函数：将JNI方法签名转换为可读格式
function prettifyMethodSignature(signature) {
    if (!signature) return "Unknown";
    
    // 提取返回类型
    var returnType = signature.substring(signature.lastIndexOf(')') + 1);
    var prettyReturn = returnType;
    
    // 提取参数类型
    var params = signature.substring(1, signature.lastIndexOf(')'));
    var prettyParams = [];
    
    // 转换参数类型为可读形式
    var i = 0;
    while (i < params.length) {
        var char = params.charAt(i);
        if (char === 'Z') {
            prettyParams.push("boolean");
            i++;
        } else if (char === 'B') {
            prettyParams.push("byte");
            i++;
        } else if (char === 'C') {
            prettyParams.push("char");
            i++;
        } else if (char === 'S') {
            prettyParams.push("short");
            i++;
        } else if (char === 'I') {
            prettyParams.push("int");
            i++;
        } else if (char === 'J') {
            prettyParams.push("long");
            i++;
        } else if (char === 'F') {
            prettyParams.push("float");
            i++;
        } else if (char === 'D') {
            prettyParams.push("double");
            i++;
        } else if (char === 'V') {
            prettyParams.push("void");
            i++;
        } else if (char === 'L') {
            // 处理对象类型
            var endIndex = params.indexOf(';', i);
            var className = params.substring(i + 1, endIndex).replace(/\//g, '.');
            prettyParams.push(className);
            i = endIndex + 1;
        } else if (char === '[') {
            // 处理数组类型
            var arrayDimension = 0;
            while (params.charAt(i) === '[') {
                arrayDimension++;
                i++;
            }
            
            var arrayType = "";
            if (params.charAt(i) === 'L') {
                var endIndex = params.indexOf(';', i);
                arrayType = params.substring(i + 1, endIndex).replace(/\//g, '.');
                i = endIndex + 1;
            } else {
                switch(params.charAt(i)) {
                    case 'Z': arrayType = "boolean"; break;
                    case 'B': arrayType = "byte"; break;
                    case 'C': arrayType = "char"; break;
                    case 'S': arrayType = "short"; break;
                    case 'I': arrayType = "int"; break;
                    case 'J': arrayType = "long"; break;
                    case 'F': arrayType = "float"; break;
                    case 'D': arrayType = "double"; break;
                    default: arrayType = "unknown"; break;
                }
                i++;
            }
            
            for (var j = 0; j < arrayDimension; j++) {
                arrayType += "[]";
            }
            
            prettyParams.push(arrayType);
        } else {
            prettyParams.push("unknown");
            i++;
        }
    }
    
    // 转换返回类型为可读形式
    var readableReturn = returnType;
    if (returnType === 'Z') readableReturn = "boolean";
    else if (returnType === 'B') readableReturn = "byte";
    else if (returnType === 'C') readableReturn = "char";
    else if (returnType === 'S') readableReturn = "short";
    else if (returnType === 'I') readableReturn = "int";
    else if (returnType === 'J') readableReturn = "long";
    else if (returnType === 'F') readableReturn = "float";
    else if (returnType === 'D') readableReturn = "double";
    else if (returnType === 'V') readableReturn = "void";
    else if (returnType.startsWith('L')) {
        readableReturn = returnType.substring(1, returnType.length - 1).replace(/\//g, '.');
    } else if (returnType.startsWith('[')) {
        var arrayDim = 0;
        var baseType = returnType;
        
        while (baseType.charAt(0) === '[') {
            arrayDim++;
            baseType = baseType.substring(1);
        }
        
        if (baseType === 'Z') baseType = "boolean";
        else if (baseType === 'B') baseType = "byte";
        else if (baseType === 'C') baseType = "char";
        else if (baseType === 'S') baseType = "short";
        else if (baseType === 'I') baseType = "int";
        else if (baseType === 'J') baseType = "long";
        else if (baseType === 'F') baseType = "float";
        else if (baseType === 'D') baseType = "double";
        else if (baseType.startsWith('L')) {
            baseType = baseType.substring(1, baseType.length - 1).replace(/\//g, '.');
        }
        
        readableReturn = baseType;
        for (var k = 0; k < arrayDim; k++) {
            readableReturn += "[]";
        }
    }
    
    return readableReturn + " (" + prettyParams.join(", ") + ")";
}

// 辅助函数：查找函数地址所属的模块和偏移量
function findModuleAndOffset(address) {
    var modules = Process.enumerateModules();
    for (var i = 0; i < modules.length; i++) {
        var module = modules[i];
        var baseAddress = module.base;
        var size = module.size;
        
        // 检查地址是否在当前模块范围内
        if (address >= baseAddress && address < baseAddress.add(size)) {
            var offset = address.sub(baseAddress);
            return {
                name: module.name,
                offset: "0x" + offset.toString(16)
            };
        }
    }
    
    return {
        name: "unknown",
        offset: "0x" + address.toString(16)
    };
}

// 主要Hook点: RegisterNatives函数
Interceptor.attach(Module.findExportByName(null, 'RegisterNatives'), {
    onEnter: function (args) {
        // 获取参数
        var env = args[0];
        var jclazz = args[1];
        var methods = args[2];
        var count = args[3].toInt32();
        
        // 获取Java类名
        var className = "";
        try {
            // 获取jclass引用的类名
            var findClassHandle = env.add(Process.pointerSize * 6).readPointer();
            var getClassNameHandle = env.add(Process.pointerSize * 7).readPointer();
            
            // 使用JNIEnv函数获取类名
            var jcls = jclazz;
            if (getClassNameHandle) {
                var jstr = new NativeFunction(getClassNameHandle, 'pointer', ['pointer', 'pointer'])(env, jcls);
                if (jstr.isNull() === false) {
                    var getStringUtfCharsHandle = env.add(Process.pointerSize * 67).readPointer();
                    if (getStringUtfCharsHandle) {
                        var cstr = new NativeFunction(getStringUtfCharsHandle, 'pointer', ['pointer', 'pointer', 'pointer'])(env, jstr, ptr(0));
                        if (cstr.isNull() === false) {
                            className = Memory.readUtf8String(cstr);
                        }
                    }
                }
            }
        } catch (e) {
            console.log("[-] 无法获取类名: " + e);
            className = "UnknownClass";
        }
        
        // 如果无法获取类名，尝试通过堆栈分析得到一个可能的类名
        if (!className || className === "UnknownClass") {
            try {
                var backtrace = Thread.backtrace(this.context, Backtracer.ACCURATE);
                if (backtrace.length > 0) {
                    // 使用回溯地址的函数名作为类名的一部分
                    var functionName = DebugSymbol.fromAddress(backtrace[0]).name;
                    if (functionName) {
                        className = "Class_from_" + functionName.replace(/[^a-zA-Z0-9_]/g, '_');
                    }
                }
            } catch (e) {}
        }
        
        // 保存上下文信息，以便在onLeave中使用
        this.className = className.replace(/\//g, '.');
        this.methodsPtr = methods;
        this.methodCount = count;
        
        console.log('\n[+] RegisterNatives called: ' + this.className);
        console.log('    注册方法数量: ' + count);
    },
    
    onLeave: function (retval) {
        // 如果方法数量大于0，则遍历并打印所有注册的方法
        if (this.methodCount > 0) {
            // 打印类名和分隔线
            console.log('\n[*] 类 ' + this.className + ' 注册了 ' + this.methodCount + ' 个Native方法:');
            console.log('    ' + '-'.repeat(60));
            console.log('    | 序号 | 方法名                 | 函数地址         | 模块:偏移量');
            console.log('    ' + '-'.repeat(60));
            
            // JNINativeMethod结构体大小
            var NATIVE_METHOD_SIZE = Process.pointerSize * 3; // name, signature, fnPtr
            
            // 遍历所有方法
            for (var i = 0; i < this.methodCount; i++) {
                // 计算当前方法的结构体偏移
                var methodPtr = this.methodsPtr.add(i * NATIVE_METHOD_SIZE);
                
                // 读取方法名、签名和函数指针
                var namePtr = Memory.readPointer(methodPtr);
                var sigPtr = Memory.readPointer(methodPtr.add(Process.pointerSize));
                var fnPtrPtr = Memory.readPointer(methodPtr.add(Process.pointerSize * 2));
                
                // 转换为JavaScript字符串
                var name = Memory.readUtf8String(namePtr);
                var sig = Memory.readUtf8String(sigPtr);
                
                // 查找函数地址所属的模块和偏移
                var moduleInfo = findModuleAndOffset(fnPtrPtr);
                
                // 添加到全局注册方法表
                if (!registeredMethods[this.className]) {
                    registeredMethods[this.className] = [];
                }
                registeredMethods[this.className].push({
                    name: name,
                    signature: sig,
                    fnPtr: fnPtrPtr,
                    moduleName: moduleInfo.name,
                    offset: moduleInfo.offset
                });
                
                // 格式化输出
                console.log('    | ' + i.toString().padEnd(4) + ' | ' + 
                           name.padEnd(20) + ' | ' + 
                           fnPtrPtr + ' | ' + 
                           moduleInfo.name + ':' + moduleInfo.offset);
                
                // 打印方法签名的可读格式
                var prettySignature = prettifyMethodSignature(sig);
                console.log('    |      | 签名: ' + sig);
                console.log('    |      | 可读签名: ' + prettySignature);
                
                // 在特定情况下，可以自动Hook这些native函数
                // 例如，可以根据方法名或方法签名自动Hook敏感函数
                if (name.includes("encrypt") || name.includes("decrypt") || 
                    name.includes("sign") || name.includes("verify")) {
                    try {
                        // 创建一个针对这个native函数的Hook
                        console.log('    |      | [!] 自动Hook敏感函数');
                        
                        Interceptor.attach(fnPtrPtr, {
                            onEnter: function (args) {
                                console.log('[!] 调用敏感Native方法: ' + name);
                                // 打印调用堆栈
                                console.log('    调用堆栈: ');
                                console.log('    ' + Thread.backtrace(this.context, Backtracer.ACCURATE)
                                    .map(DebugSymbol.fromAddress).join('\n    '));
                            },
                            onLeave: function (retval) {
                                // 根据方法签名，可以尝试解析返回值
                                console.log('    返回值: ' + retval);
                            }
                        });
                    } catch (e) {
                        console.log('    |      | [-] Hook失败: ' + e.message);
                    }
                }
            }
            console.log('    ' + '-'.repeat(60));
            
            // 将此类添加到已Hook类列表
            lastHookedClasses.push(this.className);
            
            // 保持最多显示最近的5个类
            if (lastHookedClasses.length > 5) {
                lastHookedClasses.shift();
            }
        }
    }
});

// 辅助功能：定时检查注册了Native方法的类
setInterval(function() {
    var totalMethods = 0;
    var totalClasses = Object.keys(registeredMethods).length;
    
    // 计算总注册方法数
    for (var className in registeredMethods) {
        totalMethods += registeredMethods[className].length;
    }
    
    if (totalClasses > 0) {
        console.log('\n[*] 统计信息 - 已注册 ' + totalMethods + ' 个Native方法，分布在 ' + totalClasses + ' 个类中');
        console.log('    最近处理的类: ' + lastHookedClasses.join(', '));
    }
}, 10000);  // 每10秒显示一次统计信息

console.log('[*] JNI函数调用监控已启动');
console.log('[*] 正在等待RegisterNatives调用...');

/*
// 可选功能：手动Hook所有已注册的Native方法
function hookAllRegisteredNatives() {
    console.log('\n[*] 手动Hook所有注册的Native方法...');
    
    for (var className in registeredMethods) {
        var methods = registeredMethods[className];
        for (var i = 0; i < methods.length; i++) {
            var method = methods[i];
            try {
                Interceptor.attach(method.fnPtr, {
                    onEnter: function (args) {
                        console.log('[*] 调用Native方法: ' + className + '.' + method.name);
                    }
                });
                console.log('    [+] 成功Hook: ' + className + '.' + method.name);
            } catch (e) {
                console.log('    [-] Hook失败: ' + className + '.' + method.name + ' - ' + e.message);
            }
        }
    }
}

// 可以通过发送消息触发手动Hook
recv('hook_all', function() {
    hookAllRegisteredNatives();
});
*/ 