/*
 * 脚本名称：阻止System_exit退出.js
 * 功能描述：阻止Android应用调用System.exit()方法强制退出应用的行为
 * 
 * 适用场景：
 *   - 防止应用在检测到异常环境时自动退出
 *   - 绕过应用的自我保护机制
 *   - 分析应用的退出逻辑和触发条件
 *   - 调试被反调试保护的应用
 *   - 保持应用在特定条件下继续运行
 *
 * 使用方法：
 *   1. frida -U -f 目标应用包名 -l 阻止System_exit退出.js --no-pause
 *   2. 或者 frida -U --attach-pid 目标进程PID -l 阻止System_exit退出.js
 *   3. 操作应用，当应用尝试调用System.exit()时将被阻止
 *
 * 启动方式说明：
 *   - -U: 使用USB连接的设备
 *   - -f: 指定以spawn方式启动的应用包名
 *   - --attach-pid: 附加到已运行的进程
 *   - --no-pause: 注入后不暂停应用执行
 *
 * 工作原理：
 *   Hook java.lang.System类的exit方法，当应用调用System.exit()尝试终止进程时，
 *   脚本会拦截这个调用并记录退出码，但不会执行原始的退出操作，从而使应用继续运行。
 *   这种方式可以绕过一些应用在检测到非正常环境时自动退出的保护措施。
 *
 * 注意事项：
 *   - 阻止应用正常退出可能导致应用处于不一致状态
 *   - 某些应用可能使用其他方式强制终止进程，如Process.killProcess()
 *   - 应用可能在被阻止退出后尝试其他保护措施
 *   - 建议与"阻止Process_Kill终止.js"配合使用以获得更全面的保护
 *   - 部分应用可能使用Native层的exit()函数，此脚本对此无效
 */

// Hook System.exit，防止应用退出
Java.perform(function () {
    var System = Java.use("java.lang.System");
    System.exit.implementation = function (code) {
        console.log("[*] System.exit调用被拦截，退出码: " + code + " (已阻止)");
        // 不调用原始方法，阻止退出
        
        // 可选：打印调用堆栈，分析退出来源
        console.log("    调用堆栈: \n    " + 
            Java.use("android.util.Log").getStackTraceString(
            Java.use("java.lang.Exception").$new()).split('\n').slice(1, 4).join('\n    '));
    };
    
    console.log("[*] System.exit拦截已启用");
}); 