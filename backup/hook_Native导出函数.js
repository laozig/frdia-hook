/*
 * 脚本名称：hook_Native导出函数.js
 * 功能描述：监控Android应用中native层so库导出函数的调用，获取参数和返回值
 * 
 * 适用场景：
 *   - 分析native层加密解密算法
 *   - 逆向分析so库中的关键函数逻辑
 *   - 监控JNI函数调用过程
 *   - 提取so库函数的输入输出数据
 *   - 分析带有反调试或混淆保护的native代码
 *
 * 使用方法：
 *   1. 修改脚本中的库名和函数名为目标so库和函数
 *      - 将"libnative-lib.so"替换为要监控的实际so库名
 *      - 将"native_function"替换为要监控的实际函数名
 *   2. frida -U -f 目标应用包名 -l hook_Native导出函数.js --no-pause
 *   3. 或者 frida -U --attach-pid 目标进程PID -l hook_Native导出函数.js
 *   4. 操作应用，触发native函数调用，观察控制台输出
 *
 * 启动方式说明：
 *   - -U: 使用USB连接的设备
 *   - -f: 指定以spawn方式启动的应用包名
 *   - --attach-pid: 附加到已运行的进程
 *   - --no-pause: 注入后不暂停应用执行
 *
 * 工作原理：
 *   使用Frida的Interceptor.attach API挂钩指定so库导出的函数，当函数被调用时，
 *   可以拦截函数调用前(onEnter)和调用后(onLeave)的时机，记录函数参数和返回值。
 *   这对于分析应用中的native层代码非常有用，特别是涉及加密算法、防护措施等核心功能。
 *
 * 高级技巧：
 *   - 使用Memory API可以读取和解析内存中的数据结构
 *   - 使用NativePointer相关方法可以操作内存指针
 *   - 可以使用NativeFunction调用其他native函数
 *   - 使用Stalker API可以进行指令级跟踪
 */

// Hook Native 层的导出函数，打印参数和返回值
// 作用：监控 so 库中导出函数的调用，获取参数和返回值，分析底层实现。
Java.perform(function() {
    // 等待Java环境初始化完成后再执行native hook
    try {
        // 配置参数 - 根据需要调整
        var soName = "libnative-lib.so"; // 修改为目标so库名
        var functionName = "native_function"; // 修改为目标函数名
        
        console.log("[*] 正在定位" + soName + "中的" + functionName + "函数...");
        
        // 首先确保目标模块已加载
        var targetModule = Process.findModuleByName(soName);
        if (!targetModule) {
            console.log("[!] 目标so库未加载，等待加载...");
            
            // 如果模块未加载，监听模块加载事件
            var moduleLoadListener = Interceptor.attach(Module.findExportByName(null, "dlopen"), {
                onEnter: function(args) {
                    this.path = args[0].readCString();
                },
                onLeave: function(retval) {
                    if (this.path && this.path.indexOf(soName) !== -1) {
                        console.log("[*] 检测到目标so库加载: " + this.path);
                        // 尝试再次查找模块和函数
                        hookTargetFunction();
                        // 卸载dlopen监听器
                        moduleLoadListener.detach();
                    }
                }
            });
        } else {
            hookTargetFunction();
        }
        
        function hookTargetFunction() {
            var targetFunction = Module.findExportByName(soName, functionName);
            
            if (!targetFunction) {
                console.log("[!] 无法找到函数: " + functionName + "，该函数可能不是导出函数");
                console.log("    尝试使用其他方法定位函数，如搜索符号或内存扫描");
                return;
            }
            
            console.log("[*] 找到函数地址: " + targetFunction);
            
            Interceptor.attach(targetFunction, {
                onEnter: function(args) {
                    console.log("[*] " + functionName + " 被调用");
                    
                    // 保存调用上下文
                    this.args = [];
                    
                    // 记录前几个参数
                    try {
                        // 这里只显示前4个参数，可以根据实际情况增减
                        for (var i = 0; i < 4; i++) {
                            // 保存参数引用
                            this.args.push(args[i]);
                            
                            // 尝试以不同格式解释参数
                            var intValue = args[i].toInt32();
                            var hexValue = args[i].toString();
                            var strValue = "";
                            
                            // 尝试读取字符串，可能会失败
                            try {
                                if (args[i] != 0) {
                                    strValue = Memory.readCString(args[i]);
                                }
                            } catch (e) { 
                                strValue = "<不是字符串>";
                            }
                            
                            console.log("    参数" + i + ": " + hexValue + 
                                       (intValue !== 0 ? " (int: " + intValue + ")" : "") +
                                       (strValue ? " (字符串: " + strValue + ")" : ""));
                        }
                    } catch (e) {
                        console.log("    读取参数错误: " + e);
                    }
                    
                    // 打印调用堆栈
                    console.log("    调用堆栈:");
                    console.log("    " + Thread.backtrace(this.context, Backtracer.ACCURATE)
                        .map(DebugSymbol.fromAddress).join("\n    "));
                },
                onLeave: function(retval) {
                    console.log("    返回值: " + retval);
                    
                    // 尝试解释返回值
                    try {
                        var intRetVal = retval.toInt32();
                        if (intRetVal !== 0) {
                            console.log("    返回值(int): " + intRetVal);
                        }
                        
                        // 如果返回值可能是指针，尝试读取内存
                        if (intRetVal > 0x1000) {
                            try {
                                var strRetVal = Memory.readCString(retval);
                                if (strRetVal && strRetVal.length > 0) {
                                    console.log("    返回字符串: " + strRetVal);
                                }
                            } catch (e) {
                                // 不是字符串指针，忽略错误
                            }
                        }
                    } catch (e) {
                        console.log("    解析返回值错误: " + e);
                    }
                    
                    console.log("-----------------------------");
                }
            });
            
            console.log("[*] Hook已设置成功，等待函数被调用...");
        }
        
    } catch (e) {
        console.log('[!] hook_native_function错误:', e);
    }
}); 