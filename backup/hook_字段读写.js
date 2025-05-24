/*
 * 脚本名称：hook_字段读写.js
 * 功能描述：监控Android应用中指定Java类的字段读写操作，追踪敏感数据访问和修改
 * 
 * 适用场景：
 *   - 追踪敏感数据的流动和处理
 *   - 监控加密密钥、令牌等重要字段
 *   - 分析应用内部状态变化
 *   - 调试特定字段的赋值来源
 *   - 拦截和修改字段值以改变应用行为
 *
 * 使用方法：
 *   1. 修改脚本中的类名和字段名为目标类和字段
 *      - 将"com.example.app.TargetClass"替换为要监控的实际类名
 *      - 将"targetField"替换为要监控的实际字段名
 *   2. frida -U -f 目标应用包名 -l hook_字段读写.js --no-pause
 *   3. 或者 frida -U --attach-pid 目标进程PID -l hook_字段读写.js
 *   4. 操作应用，观察控制台输出的字段读写信息
 *
 * 启动方式说明：
 *   - -U: 使用USB连接的设备
 *   - -f: 指定以spawn方式启动的应用包名
 *   - --attach-pid: 附加到已运行的进程
 *   - --no-pause: 注入后不暂停应用执行
 *
 * 工作原理：
 *   使用JavaScript的Object.defineProperty方法重新定义目标类字段的getter和setter，
 *   当字段被读取或修改时，脚本会拦截这些操作并记录相关信息，同时保持原有功能不变。
 *   这种方式可以无侵入地监控字段的访问，不会改变应用的正常行为。
 *
 * 注意事项：
 *   - 此方法主要适用于类的实例字段，而非静态字段
 *   - 如需监控静态字段，需要使用不同的语法
 *   - 某些字段可能被混淆处理，需要根据实际情况调整
 */

// Hook Java 层的字段读写
// 作用：监控指定类的字段读写操作，获取字段的读取和修改值，用于追踪敏感数据。
Java.perform(function () {
    try {
        // 修改以下变量为目标类和字段名
        var className = "com.example.app.TargetClass";
        var fieldName = "targetField"; 
        var isStaticField = false; // 是否为静态字段，如果是静态字段设为true
        
        console.log("[*] 开始监控字段: " + className + "." + fieldName);
        var TargetClass = Java.use(className);
        
        if (isStaticField) {
            // 监控静态字段
            var originalValue = TargetClass[fieldName].value;
            
            // 备份原始值
            TargetClass["_" + fieldName] = { value: originalValue };
            
            // 重定义静态字段
            Object.defineProperty(TargetClass, fieldName, {
                set: function (val) {
                    console.log("[*] 静态字段 " + fieldName + " 被修改:");
                    console.log("    旧值: " + TargetClass["_" + fieldName].value);
                    console.log("    新值: " + val);
                    
                    // 打印调用堆栈
                    console.log("    调用堆栈: \n    " + 
                        Java.use("android.util.Log").getStackTraceString(
                        Java.use("java.lang.Exception").$new()).split('\n').slice(2, 5).join('\n    '));
                    
                    // 更新备份的值
                    TargetClass["_" + fieldName].value = val;
                    // 设置实际字段值
                    this[fieldName].value = val;
                },
                get: function () {
                    var val = this[fieldName].value;
                    console.log("[*] 静态字段 " + fieldName + " 被读取: " + val);
                    return val;
                }
            });
        } else {
            // 监控实例字段
            // 使用 Object.defineProperty 重新定义字段的读写操作
            Object.defineProperty(TargetClass.prototype, fieldName, {
                set: function (val) {
                    console.log("[*] 字段 " + fieldName + " 被修改:");
                    console.log("    新值: " + val);
                    
                    // 如果需要，可以打印旧值
                    if (this["_" + fieldName] !== undefined) {
                        console.log("    旧值: " + this["_" + fieldName]);
                    }
                    
                    // 打印调用堆栈
                    console.log("    调用堆栈: \n    " + 
                        Java.use("android.util.Log").getStackTraceString(
                        Java.use("java.lang.Exception").$new()).split('\n').slice(2, 5).join('\n    '));
                    
                    // 保存值到隐藏字段
                    this["_" + fieldName] = val;
                },
                get: function () {
                    var val = this["_" + fieldName];
                    console.log("[*] 字段 " + fieldName + " 被读取: " + val);
                    return val;
                }
            });
        }
        
        console.log("[*] 字段监控已设置完成");
        
    } catch (e) {
        console.log('[!] hook_field错误:', e);
    }
}); 