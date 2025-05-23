// Hook so 文件中的符号（非导出函数）
// 作用：监控 so 库中的内部函数调用，包括未导出的符号，适用于分析闭源库的内部实现。
try {
    var moduleName = "libnative-lib.so";
    var symbolName = "_Z12targetSymbolv"; // 替换为实际符号名
    // 查找符号地址（导出或内部）
    var addr = Module.findExportByName(moduleName, symbolName) || Module.findSymbolByName(moduleName, symbolName);

    if (addr) {
        Interceptor.attach(addr, {
            onEnter: function (args) {
                console.log("[*] " + symbolName + " called");
            },
            onLeave: function (retval) {
                console.log("[*] " + symbolName + " return: " + retval);
            }
        });
    } else {
        console.log("[-] Symbol not found!");
    }
} catch (e) {
    console.log('[!] hook_so_symbol error:', e);
} 