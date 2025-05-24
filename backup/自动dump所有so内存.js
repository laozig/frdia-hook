/*
 * 脚本名称：自动dump所有so内存.js
 * 功能描述：遍历并记录进程中加载的所有SO库信息，便于内存提取和分析
 * 
 * 适用场景：
 *   - 提取加固应用中的解密SO库
 *   - 分析动态加载或自解密的原生库
 *   - 研究SO库的内存保护和反调试机制
 *   - 提取内存中修改过的SO库代码
 *   - 辅助逆向分析Native层实现
 *
 * 使用方法：
 *   1. frida -U -f 目标应用包名 -l 自动dump所有so内存.js --no-pause
 *   2. 或者 frida -U --attach-pid 目标进程PID -l 自动dump所有so内存.js
 *   3. 观察控制台输出的SO库信息，包括名称、基址和大小
 *   4. 可以扩展脚本，使用Memory.readByteArray自动提取SO文件
 *
 * 启动方式说明：
 *   - -U: 使用USB连接的设备
 *   - -f: 指定以spawn方式启动的应用包名（推荐，可捕获启动时加载的SO）
 *   - --attach-pid: 附加到已运行的进程
 *   - --no-pause: 注入后不暂停应用执行
 *
 * 工作原理：
 *   脚本使用Process.enumerateModulesSync函数枚举进程中加载的所有模块（包括SO库）。
 *   对于每个模块，提取并打印其名称、基址和大小信息。这些信息可以用于后续的内存提取，
 *   通过Memory.readByteArray(module.base, module.size)可以读取SO库在内存中的完整内容，
 *   特别适用于那些在运行时解密或修改的SO库，可以获取到解密后的版本。
 *
 * 注意事项：
 *   - 需要root权限或Frida服务器具有对应权限
 *   - 直接从内存提取的SO可能缺少正确的ELF头或节信息
 *   - 某些加固应用可能对SO库进行内存保护或混淆
 *   - 建议与监控so加载.js等脚本配合使用，获取动态加载信息
 *   - 可以扩展脚本，将提取的SO保存到文件中，便于后续分析
 *   - 大型应用可能加载大量SO库，注意筛选关注的目标
 */

// 自动dump所有so内存.js
Process.enumerateModulesSync().forEach(function (module) {
    // 仅处理SO库文件
    if (module.name.indexOf('.so') !== -1) {
        console.log('[*] 已加载so: ' + module.name + ' @ ' + module.base + ' size=' + module.size);
        
        // 示例扩展：自动提取SO文件到本地
        /*
        try {
            var fileName = module.name.replace(/\//g, '_');
            var file = new File('/data/local/tmp/' + fileName, 'wb');
            var buffer = Memory.readByteArray(module.base, module.size);
            file.write(buffer);
            file.flush();
            file.close();
            console.log('[+] 已dump so到: /data/local/tmp/' + fileName);
        } catch (e) {
            console.log('[-] dump so失败: ' + e);
        }
        */
    }
}); 