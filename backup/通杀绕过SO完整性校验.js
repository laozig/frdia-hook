/*
 * 脚本名称：通杀绕过SO完整性校验.js
 * 功能描述：绕过应用对本地库文件(SO)的完整性校验，便于修改和分析本地代码
 * 
 * 适用场景：
 *   - 分析和修改应用的本地库文件
 *   - 绕过应用的二进制保护机制
 *   - 调试经过修改的本地库
 *   - 逆向分析具有自我保护的应用
 *   - 对抗应用对SO文件的完整性检测
 *
 * 使用方法：
 *   1. frida -U -f 目标应用包名 -l 通杀绕过SO完整性校验.js --no-pause
 *   2. 或者 frida -U --attach-pid 目标进程PID -l 通杀绕过SO完整性校验.js
 *   3. 应用将无法检测到SO文件被修改
 *
 * 启动方式说明：
 *   - -U: 使用USB连接的设备
 *   - -f: 指定以spawn方式启动的应用包名
 *   - --attach-pid: 附加到已运行的进程
 *   - --no-pause: 注入后不暂停应用执行
 *
 * 工作原理：
 *   拦截三个常用于SO文件操作的libc函数：
 *   
 *   1. dlopen: 用于动态加载共享库(.so文件)
 *      应用可能会尝试加载指定的.so文件进行校验
 *   
 *   2. stat: 获取文件的状态信息(如大小、修改时间等)
 *      应用可能会检查.so文件的属性是否被修改
 *   
 *   3. fopen: 打开文件读取内容
 *      应用可能会读取.so文件内容进行哈希校验
 *
 *   当这些函数被调用来访问.so文件时，脚本将阻断操作并返回失败结果，
 *   从而防止应用读取真实的SO文件进行校验，达到绕过完整性检测的目的。
 *
 * 注意事项：
 *   - 此脚本主要针对校验单独SO文件完整性的情况，对于内存中已加载库的校验可能无效
 *   - 应用可能使用其他方法校验SO，如mmap、Native内存扫描等
 *   - 建议与通杀绕过APP完整性校验.js配合使用，全面应对自我保护机制
 *   - 脚本可能会影响应用正常加载SO的功能，如遇问题可能需要调整拦截条件
 *   - 对于高度定制的SO校验逻辑，可能需要通过分析确定真正的校验点
 */
// 通杀绕过SO完整性校验
['dlopen', 'stat', 'fopen'].forEach(function (func) {
    try {
        var addr = Module.findExportByName('libc.so', func);
        if (addr) {
            Interceptor.attach(addr, {
                onEnter: function (args) {
                    if (args[0] && args[0].readCString) {
                        var path = args[0].readCString();
                        if (path && path.indexOf('.so') !== -1) {
                            console.log('[*] SO完整性校验拦截: ' + func + ' ' + path + ' (阻断)');
                            this.bypass = true;
                        }
                    }
                },
                onLeave: function (retval) {
                    if (this.bypass) {
                        retval.replace(ptr(0));
                    }
                }
            });
        }
    } catch (e) {}
}); 