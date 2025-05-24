/*
 * 脚本名称：dump_动态注册native.js
 * 功能描述：监控并记录Android应用动态注册的native方法
 * 
 * 适用场景：
 *   - 分析应用使用JNI动态注册的本地方法
 *   - 发现应用隐藏在SO库中的关键功能实现
 *   - 逆向分析时定位关键native方法的实现位置
 *   - 寻找可能的hook点以修改本地方法行为
 *   - 查找加密、解密、验证等核心算法的入口点
 *
 * 使用方法：
 *   1. frida -U -f 目标应用包名 -l dump_动态注册native.js --no-pause
 *   2. 或者 frida -U --attach-pid 目标进程PID -l dump_动态注册native.js
 *   3. 观察控制台输出，记录所有动态注册的native方法
 *
 * 启动方式说明：
 *   - -U: 使用USB连接的设备
 *   - -f: 指定以spawn方式启动的应用包名
 *   - --attach-pid: 附加到已运行的进程
 *   - --no-pause: 注入后不暂停应用执行
 *
 * 工作原理：
 *   Hook系统的RegisterNatives函数，该函数是JNI用于动态注册本地方法的关键API。
 *   当应用调用此函数注册native方法时，脚本会拦截并记录相关信息，
 *   包括注册的方法数量。可以进一步修改此脚本以提取更详细的信息，
 *   如每个方法的名称、签名、实现地址等。
 *
 * 注意事项：
 *   - 部分应用可能在启动早期就注册native方法，建议使用spawn模式以捕获所有注册
 *   - 可以扩展此脚本以dump methods参数中的详细内容，包括函数名、签名和函数指针
 *   - 与内存dump工具结合使用，可以进一步分析本地函数的实现
 */

// Hook RegisterNatives函数，捕获动态注册的native方法
Interceptor.attach(Module.findExportByName(null, 'RegisterNatives'), {
    onEnter: function (args) {
        var env = args[0];
        var clazz = args[1];
        var methods = args[2];
        var count = args[3].toInt32();
        console.log('[*] RegisterNatives 动态注册native方法, 数量: ' + count);
        // 这里可进一步dump methods结构体内容
    }
}); 