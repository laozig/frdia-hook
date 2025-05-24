/*
 * 脚本名称：dump_so文件.js
 * 功能描述：监控动态链接库(so库)的加载过程，用于辅助提取应用使用的native库文件
 * 
 * 适用场景：
 *   - 监控应用加载的so库
 *   - 分析应用对native库的依赖
 *   - 配合内存dump工具提取运行时加载的so文件
 *   - 逆向分析加固应用的脱壳过程
 *
 * 使用方法：
 *   1. frida -U -f 目标应用包名 -l dump_so文件.js --no-pause
 *   2. 或者 frida -U --attach-pid 目标进程PID -l dump_so文件.js
 *
 * 启动方式说明：
 *   - -U: 使用USB连接的设备
 *   - -f: 指定以spawn方式启动的应用包名
 *   - --attach-pid: 附加到已运行的进程
 *   - --no-pause: 注入后不暂停应用执行
 *
 * 工作原理：
 *   通过Hook系统的dlopen函数来监控so库的加载。dlopen是Android系统用于
 *   动态加载共享库的函数，所有通过System.loadLibrary或dlopen加载的
 *   动态链接库都会被此脚本监控到。
 *
 * 高级用法：
 *   可结合frida-memdump、frida-dexdump等工具进行内存dump操作，
 *   在监测到目标so库加载后自动提取其内存映射，这对于分析加壳应用
 *   或动态加载的库特别有用。
 */

// dump_so文件.js
Interceptor.attach(Module.findExportByName(null, 'dlopen'), {
    onEnter: function (args) {
        var soName = args[0].readCString();
        if (soName && soName.indexOf('.so') !== -1) {
            console.log('[*] so库加载: ' + soName);
            // 这里可结合frida-memdump等工具自动dump内存so
        }
    },
    onLeave: function (retval) {}
}); 