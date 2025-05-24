/*
 * 脚本名称：监控malloc内存分配.js
 * 功能描述：监控应用在Native层通过malloc函数分配内存的行为
 * 
 * 适用场景：
 *   - 分析应用在Native层的内存使用模式
 *   - 发现可能的内存泄漏或过度分配问题
 *   - 监控应用在特定操作时的内存分配行为
 *   - 分析加密、解密等操作的内存使用特征
 *   - 追踪动态内存分配中可能存储敏感数据的区域
 *
 * 使用方法：
 *   1. frida -U -f 目标应用包名 -l 监控malloc内存分配.js --no-pause
 *   2. 或者 frida -U --attach-pid 目标进程PID -l 监控malloc内存分配.js
 *   3. 操作应用，观察控制台输出的内存分配信息
 *
 * 启动方式说明：
 *   - -U: 使用USB连接的设备
 *   - -f: 指定以spawn方式启动的应用包名
 *   - --attach-pid: 附加到已运行的进程
 *   - --no-pause: 注入后不暂停应用执行
 *
 * 工作原理：
 *   Hook libc.so库中的malloc函数，该函数是C/C++中动态分配内存的标准函数。
 *   当应用在Native层请求分配内存时，会调用此函数，脚本会拦截这些调用并记录分配的内存大小和返回的内存地址，
 *   这有助于分析应用在Native层的内存使用模式，发现异常的内存分配行为。
 *
 * 注意事项：
 *   - malloc调用非常频繁，会产生大量日志，建议添加大小过滤条件
 *   - 可以修改脚本，只关注特定大小范围的内存分配
 *   - 对于关键内存区域，可以结合Memory.readByteArray进行内容分析
 *   - 某些应用可能使用自定义内存分配器而不直接调用malloc
 *   - 大量Hook可能影响应用性能，请谨慎使用
 */

// Hook libc 的 malloc，监控内存分配
Interceptor.attach(Module.findExportByName("libc.so", "malloc"), {
    onEnter: function (args) {
        console.log("[*] malloc called, size: " + args[0].toInt32());
    },
    onLeave: function (retval) {
        console.log("[*] malloc return ptr: " + retval);
    }
}); 