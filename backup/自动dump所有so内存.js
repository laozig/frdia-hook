/*
 * 脚本名称：自动dump所有so内存.js
 * 功能：遍历所有已加载so模块，输出so信息，可配合Memory.readByteArray自动dump
 * 适用场景：so加固、so动态解密、反调试so等场景
 * 使用方法：
 *   1. frida -U -f 包名 -l 自动dump所有so内存.js --no-pause
 *   2. 查看控制台输出，配合自动化工具dump
 * 启动方式说明：
 *   - -U 代表USB设备
 *   - -f 代表spawn启动（推荐）
 *   - --no-pause 保证App正常运行
 * 注意事项：
 *   - 需root或frida-server有权限
 *   - 某些so需配合反检测脚本
 */
// 自动dump所有so内存.js
Process.enumerateModulesSync().forEach(function (module) {
    if (module.name.indexOf('.so') !== -1) {
        console.log('[*] 已加载so: ' + module.name + ' @ ' + module.base + ' size=' + module.size);
        // 可结合Memory.readByteArray(module.base, module.size)自动dump
    }
}); 