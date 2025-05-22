// Hook ptrace，绕过 native 反调试
Interceptor.attach(Module.findExportByName("libc.so", "ptrace"), {
    onEnter: function (args) {
        console.log("[*] ptrace called, bypassing anti-debug");
        args[0] = ptr(-1); // 让 ptrace 失效
    },
    onLeave: function (retval) {
        retval.replace(0);
    }
}); 