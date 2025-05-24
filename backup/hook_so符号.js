/*
 * 脚本名称：hook_so符号.js
 * 功能描述：Hook并监控SO库中的内部函数调用，包括非导出符号
 * 
 * 适用场景：
 *   - 分析闭源原生库的内部实现
 *   - 监控应用中关键算法的执行流程
 *   - 逆向分析加密、解密、校验等核心功能
 *   - 调试难以通过常规方式观察的原生代码
 *   - 追踪SO库内部函数调用链和参数传递
 *
 * 使用方法：
 *   1. 修改脚本中的moduleName为目标SO库名称
 *   2. 修改symbolName为要监控的函数符号名称（如C++的符号名）
 *   3. frida -U -f 目标应用包名 -l hook_so符号.js --no-pause
 *   4. 或者 frida -U --attach-pid 目标进程PID -l hook_so符号.js
 *   5. 操作应用触发相关函数调用，观察控制台输出
 *
 * 启动方式说明：
 *   - -U: 使用USB连接的设备
 *   - -f: 指定以spawn方式启动的应用包名
 *   - --attach-pid: 附加到已运行的进程
 *   - --no-pause: 注入后不暂停应用执行
 *
 * 工作原理：
 *   脚本首先查找指定SO库中的符号（函数），不仅限于导出函数，还包括内部函数。
 *   它使用Module.findExportByName检查导出符号，如果未找到则使用Module.findSymbolByName
 *   尝试查找内部符号。一旦找到目标函数地址，便使用Interceptor.attach进行Hook，
 *   从而监控函数调用时的参数和返回值。这种方法可以深入分析SO库的内部行为，
 *   即使是那些开发者并未公开导出的函数。
 *
 * 注意事项：
 *   - 需要知道准确的符号名称，C++函数通常会被名字修饰（name mangling）
 *   - 对于混淆或加壳的SO库，符号可能被剥离或加密
 *   - 在没有调试符号的情况下，可能需要先使用IDA Pro等工具分析SO找到符号名
 *   - 64位和32位进程的符号处理可能有所不同
 *   - 某些敏感应用可能实现了反调试或反Hook机制
 */

// Hook SO库中的符号（包括非导出函数）
try {
    var moduleName = "libnative-lib.so";  // 目标SO库名称，根据实际情况修改
    var symbolName = "_Z12targetSymbolv"; // 目标符号名称，通常是C++名字修饰后的格式
    
    // 尝试查找符号地址（优先检查导出符号，然后查找内部符号）
    var addr = Module.findExportByName(moduleName, symbolName) || Module.findSymbolByName(moduleName, symbolName);

    if (addr) {
        // 成功找到符号，进行Hook
        Interceptor.attach(addr, {
            onEnter: function (args) {
                console.log("[*] " + symbolName + " called");
                // 根据函数签名，可以在此处添加代码提取参数信息
            },
            onLeave: function (retval) {
                console.log("[*] " + symbolName + " return: " + retval);
                // 如需修改返回值，可以使用retval.replace()
            }
        });
    } else {
        console.log("[-] Symbol not found!");
    }
} catch (e) {
    console.log('[!] hook_so_symbol error:', e);
} 