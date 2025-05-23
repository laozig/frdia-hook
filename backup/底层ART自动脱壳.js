/*
 * 脚本名称：底层ART自动脱壳.js
 * 功能：Hook ART底层DexFile::OpenMemory等函数，输出dex内存信息，可配合Memory.readByteArray自动dump
 * 适用场景：高强度加固、壳自定义ClassLoader、壳自定义DEX加载流程
 * 使用方法：
 *   1. frida -U -f 包名 -l 底层ART自动脱壳.js --no-pause
 *   2. 查看控制台输出，配合自动化工具dump
 * 启动方式说明：
 *   - -U 代表USB设备
 *   - -f 代表spawn启动（推荐）
 *   - --no-pause 保证App正常运行
 * 注意事项：
 *   - 需root或frida-server有权限
 *   - 某些壳需配合反检测脚本
 */
// 底层ART自动脱壳.js
// 适配ART环境，Hook OpenMemory等底层函数
Interceptor.attach(Module.findExportByName('libart.so', '_ZN3art6DexFile9OpenMemoryEPKvjS2_jPNS_7MemMapE'), {
    onEnter: function (args) {
        var base = args[0];
        var size = args[1].toInt32();
        console.log('[*] ART底层加载DEX: base=' + base + ' size=' + size);
        // 可结合Memory.readByteArray(base, size)自动dump
    },
    onLeave: function (retval) {}
}); 