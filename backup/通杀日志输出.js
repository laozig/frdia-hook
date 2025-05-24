/*
 * 脚本名称：通杀日志输出.js
 * 功能：自动监控所有日志输出相关API，辅助分析日志泄露、调试信息
 * 适用场景：日志分析、调试信息收集、反检测
 * 使用方法：
 *   1. frida -U -f 包名 -l 通杀日志输出.js --no-pause
 *   2. 查看控制台输出，获取日志输出信息
 * 启动方式说明：
 *   - -U 代表使用USB连接的设备
 *   - -f 代表以spawn方式启动目标应用（推荐，可以捕获启动阶段的日志）
 *   - --no-pause 指示Frida不要暂停应用执行，保证App正常运行
 *   - 也可使用 -F 以attach方式附加到已运行的进程
 * 参数说明：
 *   - 包名：目标应用的包名，如com.example.app
 * 输出信息说明：
 *   - 日志级别：Android日志分为以下几个级别
 *     - v: verbose（最低级别，显示所有日志）
 *     - d: debug（调试日志）
 *     - i: info（信息日志）
 *     - w: warn（警告日志）
 *     - e: error（错误日志）
 *   - 捕获内容：标签(tag)和日志内容(message)
 * 实际应用：
 *   - 查找敏感信息泄露（如API密钥、令牌等）
 *   - 分析应用内部逻辑和控制流
 *   - 发现隐藏的调试信息和开发者注释
 * 注意事项：
 *   - 某些加固应用需配合反检测脚本（如通杀绕过反Frida检测.js）
 *   - 大型应用可能产生大量日志，可根据需要过滤特定tag
 *   - 某些应用可能使用自定义日志系统或第三方日志库（如Timber）
 */

// 通杀日志输出
Java.perform(function () {
    // 获取Android日志类的引用
    var Log = Java.use('android.util.Log');
    
    // 监控所有日志级别的方法：debug, error, info, warn, verbose
    ['d', 'e', 'i', 'w', 'v'].forEach(function (level) {
        // 每个日志级别可能有多个重载方法，全部拦截
        Log[level].overloads.forEach(function (overload) {
            // 替换原有实现
            overload.implementation = function () {
                // 收集所有参数
                var args = Array.prototype.slice.call(arguments);
                
                // 根据不同的日志级别，可以添加不同的处理逻辑
                // 例如，可以针对error级别日志进行特殊处理
                if (level === 'e') {
                    // 错误日志可能包含重要的异常信息
                    console.log('[!] 发现错误日志: ' + JSON.stringify(args));
                    // 可以在此添加堆栈跟踪
                    // console.log(Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()));
                } else {
                    // 输出常规日志
                    console.log('[*] Log.' + level + ' 输出: ' + JSON.stringify(args));
                }
                
                // 日志参数通常为：tag, message
                if (args.length >= 2) {
                    console.log('    标签: ' + args[0] + ', 内容: ' + args[1]);
                }
                
                // 调用原始方法，保持正常功能
                return overload.apply(this, arguments);
            };
        });
    });
    
    // 监控System.out标准输出流
    var SystemOut = Java.use('java.lang.System').out.value;
    // 拦截println方法
    SystemOut.println.overload('java.lang.String').implementation = function (str) {
        // 输出捕获到的标准输出内容
        console.log('[*] System.out 输出: ' + str);
        // 调用原始方法，保持正常功能
        return this.println(str);
    };
    
    // 监控System.err错误输出流
    var SystemErr = Java.use('java.lang.System').err.value;
    // 拦截println方法
    SystemErr.println.overload('java.lang.String').implementation = function (str) {
        // 输出捕获到的错误输出内容
        console.log('[*] System.err 输出: ' + str);
        // 调用原始方法，保持正常功能
        return this.println(str);
    };
    
    // 注：更完整的实现应该包括：
    // 1. 监控其他打印方法如print(), printf()
    // 2. 监控Throwable.printStackTrace()
    // 3. 监控第三方日志库如com.orhanobut.logger, timber等
    // 4. 可以添加过滤功能，只显示包含特定关键词的日志
}); 