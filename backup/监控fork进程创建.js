/*
 * 脚本名称：监控fork进程创建.js
 * 功能描述：监控Android应用进程fork子进程的行为，用于分析进程创建和反调试机制
 * 
 * 适用场景：
 *   - 分析应用创建子进程的行为
 *   - 检测通过fork实现的反调试和反分析技术
 *   - 分析多进程应用架构
 *   - 监控可能的防护机制和自保护行为
 *   - 辅助分析Native层恶意代码
 *
 * 使用方法：
 *   1. frida -U -f 目标应用包名 -l 监控fork进程创建.js --no-pause
 *   2. 或者 frida -U --attach-pid 目标进程PID -l 监控fork进程创建.js
 *   3. 观察控制台输出，分析应用的进程创建行为
 *
 * 启动方式说明：
 *   - -U: 使用USB连接的设备
 *   - -f: 指定以spawn方式启动的应用包名
 *   - --attach-pid: 附加到已运行的进程
 *   - --no-pause: 注入后不暂停应用执行
 *
 * 工作原理：
 *   Hook libc.so库中的fork函数，这是Linux系统创建新进程的基础系统调用。
 *   当应用通过Native层代码调用fork时，脚本会记录该行为。
 *   fork函数的返回值为0表示在子进程中执行，大于0表示在父进程中执行并返回子进程PID，
 *   小于0表示创建失败。
 *   
 * 安全关注点：
 *   - 一些应用使用fork+execve来启动保护进程监视主进程
 *   - 恶意应用可能使用子进程隐藏敏感行为
 *   - 某些反调试技术使用fork检测父进程死亡（防止调试器附加）
 *   - 创建的子进程可能执行敏感操作如root检测、环境检测等
 */

// Hook fork，监控进程创建（常用于反检测、反调试）
Interceptor.attach(Module.findExportByName("libc.so", "fork"), {
    onEnter: function (args) {
        console.log("[*] 检测到fork系统调用");
        
        // 打印调用堆栈
        console.log("    调用堆栈:");
        console.log(Thread.backtrace(this.context, Backtracer.ACCURATE)
            .map(DebugSymbol.fromAddress).join('\n    '));
    },
    onLeave: function (retval) {
        // 分析返回值
        var pid = retval.toInt32();
        if (pid > 0) {
            console.log("[*] fork在父进程中返回 - 子进程PID: " + pid);
        } else if (pid == 0) {
            console.log("[*] fork在子进程中返回");
            
            // 可选：监控子进程行为
            /*
            Interceptor.attach(Module.findExportByName("libc.so", "execve"), {
                onEnter: function (args) {
                    var path = Memory.readCString(args[0]);
                    console.log("[*] 子进程执行: " + path);
                }
            });
            */
        } else {
            console.log("[!] fork失败，返回值: " + pid);
        }
    }
});

// 可选：也可以监控其他进程创建函数
/*
// vfork比fork更轻量，但子进程会共享父进程的地址空间
Interceptor.attach(Module.findExportByName("libc.so", "vfork"), {
    onEnter: function (args) {
        console.log("[*] vfork系统调用");
    },
    onLeave: function (retval) {
        console.log("[*] vfork返回: " + retval);
    }
});

// clone是Linux创建线程和进程的底层函数
Interceptor.attach(Module.findExportByName("libc.so", "clone"), {
    onEnter: function (args) {
        console.log("[*] clone系统调用");
    }
});
*/

console.log("[*] 进程创建监控已启动"); 