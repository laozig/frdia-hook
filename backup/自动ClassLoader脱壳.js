/*
 * 脚本名称：自动ClassLoader脱壳.js
 * 功能：遍历所有ClassLoader，输出已加载dex路径，可配合frida-dexdump自动dump
 * 适用场景：动态加载、插件化、热修复、壳自定义ClassLoader等
 * 使用方法：
 *   1. frida -U -f 包名 -l 自动ClassLoader脱壳.js --no-pause
 *   2. 查看控制台输出，配合自动化工具dump
 * 启动方式说明：
 *   - -U 代表USB设备
 *   - -f 代表spawn启动（推荐）
 *   - --no-pause 保证App正常运行
 * 注意事项：
 *   - 需root或frida-server有权限
 *   - 某些壳需配合反检测脚本
 */
// 自动ClassLoader脱壳.js
Java.perform(function () {
    var loaders = [];
    Java.enumerateClassLoaders({
        onMatch: function (loader) {
            loaders.push(loader);
        },
        onComplete: function () {
            loaders.forEach(function (loader) {
                try {
                    var pathList = Java.cast(loader, Java.use('dalvik.system.BaseDexClassLoader')).pathList.value;
                    var dexElements = pathList.dexElements.value;
                    for (var i = 0; i < dexElements.length; i++) {
                        var dexFile = dexElements[i].dexFile.value;
                        if (dexFile) {
                            var dexPath = dexFile.getName();
                            console.log('[*] ClassLoader已加载dex: ' + dexPath);
                            // 可结合frida-dexdump自动dump
                        }
                    }
                } catch (e) {}
            });
        }
    });
}); 