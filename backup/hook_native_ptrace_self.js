// Hook ptrace(PTRACE_ATTACH, getpid, ...) 反调试，阻止自身被调试
// 作用：阻止调试器通过 ptrace attach 当前进程，实现反调试保护。
try {
    Interceptor.attach(Module.findExportByName("libc.so", "ptrace"), {
        onEnter: function (args) {
            var request = args[0].toInt32();
            var pid = args[1].toInt32();
            // 检查是否为 attach 当前进程
            if (request === 16 /* PTRACE_ATTACH */ && pid === Process.id) {
                console.log("[*] ptrace(PTRACE_ATTACH, self) called (bypass)");
                this.bypass = true;
            }
        },
        onLeave: function (retval) {
            if (this.bypass) {
                retval.replace(-1); // 阻止 attach
            }
        }
    });
} catch (e) {
    console.log('[!] hook_native_ptrace_self error:', e);
} 