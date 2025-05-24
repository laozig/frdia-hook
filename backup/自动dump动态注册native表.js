/*
 * 脚本名称：自动dump动态注册native表.js
 * 功能描述：监控并记录应用通过JNI动态注册的本地方法
 * 
 * 适用场景：
 *   - 分析应用在SO库中实现的核心功能
 *   - 发现隐藏在Native层的关键算法
 *   - 辅助逆向分析SO库
 *   - 配合IDA Pro等工具定位关键函数
 *   - 研究应用与Native层的交互机制
 *
 * 使用方法：
 *   1. frida -U -f 目标应用包名 -l 自动dump动态注册native表.js --no-pause
 *   2. 或者 frida -U --attach-pid 目标进程PID -l 自动dump动态注册native表.js
 *   3. 操作应用，观察控制台输出的动态注册native方法信息
 *   4. 结合输出信息在IDA等工具中定位相关函数
 *
 * 启动方式说明：
 *   - -U: 使用USB连接的设备
 *   - -f: 指定以spawn方式启动的应用包名（推荐，可捕获启动时注册的方法）
 *   - --attach-pid: 附加到已运行的进程
 *   - --no-pause: 注入后不暂停应用执行
 *
 * 工作原理：
 *   Hook JNI函数RegisterNatives，该函数是Android应用动态注册Native方法的标准API。
 *   当应用调用此函数注册本地方法时，脚本会拦截调用并记录相关信息，包括注册的方法数量。
 *   RegisterNatives函数接收JNIEnv指针、Java类引用、JNINativeMethod结构体数组和方法数量作为参数，
 *   其中JNINativeMethod结构体包含了方法名、签名和函数指针等关键信息。
 *   通过分析这些信息，可以建立Java方法与Native函数的对应关系，辅助逆向分析。
 *
 * 注意事项：
 *   - 需要root权限或Frida服务器具有对应权限
 *   - 可以扩展脚本以提取更详细的方法信息，如方法名、签名和函数地址
 *   - 某些应用可能在启动早期就注册native方法，建议使用spawn模式
 *   - 部分应用可能使用反调试或混淆技术隐藏关键函数
 *   - 建议与dump_so文件.js等脚本配合使用，获取完整SO库信息
 *   - 可以修改脚本，将提取的信息保存到文件中，便于后续分析
 */

// 自动dump动态注册native表.js
Interceptor.attach(Module.findExportByName(null, 'RegisterNatives'), {
    onEnter: function (args) {
        var env = args[0];
        var clazz = args[1];
        var methods = args[2];
        var count = args[3].toInt32();
        console.log('[*] RegisterNatives 动态注册native方法, 数量: ' + count);
        // 可进一步dump methods结构体内容
        
        // 示例扩展：提取更详细的方法信息
        /*
        for (var i = 0; i < count; i++) {
            var methodsPtr = methods.add(i * Process.pointerSize * 3);
            var name = Memory.readCString(Memory.readPointer(methodsPtr));
            var sig = Memory.readCString(Memory.readPointer(methodsPtr.add(Process.pointerSize)));
            var fnPtr = Memory.readPointer(methodsPtr.add(Process.pointerSize * 2));
            console.log('[+] 方法名: ' + name + ', 签名: ' + sig + ', 函数地址: ' + fnPtr);
        }
        */
    }
}); 