/*
 * 脚本名称：dump_dex文件.js
 * 功能描述：从Android应用内存中提取DEX文件，用于分析加壳或动态加载的代码
 * 
 * 适用场景：
 *   - 脱壳分析加固应用
 *   - 获取运行时动态加载的DEX
 *   - 逆向分析混淆或保护的应用
 *   - 提取内存中的原始代码
 *   - 恢复无法从APK直接获取的类和方法
 *
 * 使用方法：
 *   1. frida -U -f 目标应用包名 -l dump_dex文件.js --no-pause
 *   2. 或者 frida -U --attach-pid 目标进程PID -l dump_dex文件.js
 *   3. 脚本自动搜索内存中的DEX文件并保存到设备存储
 *   4. 使用adb pull /data/data/应用包名/dump_*.dex命令将导出的DEX文件拉取到电脑
 *
 * 启动方式说明：
 *   - -U: 使用USB连接的设备
 *   - -f: 指定以spawn方式启动的应用包名
 *   - --attach-pid: 附加到已运行的进程
 *   - --no-pause: 注入后不暂停应用执行
 *
 * 工作原理：
 *   扫描应用内存空间中的内存段，寻找以"dex"开头的DEX文件特征魔数(magic number)。
 *   找到DEX文件后，读取DEX头部信息确认文件大小，然后将整个DEX文件内容导出到设备
 *   存储空间，供后续分析使用。
 *
 * 注意事项：
 *   - 需要应用具有外部存储写入权限
 *   - 如需提取动态加载的DEX，应在加载完成后使用
 *   - 对于多DEX应用，会生成多个dump_*.dex文件
 *   - 部分加固应用可能需要使用更高级的脱壳方式
 *   - 导出的DEX文件路径为/data/data/应用包名/dump_*.dex
 */

// 导出内存中的 DEX 文件
// 作用：提取应用内存中的 DEX 文件，用于分析动态加载或加密的代码。
Java.perform(function () {
    function dumpDex() {
        console.log("[*] 开始搜索内存中的DEX文件");
        
        var process = Process.enumerateModules()[0];
        var base = process.base;
        var size = process.size;
        
        // 获取应用包名用于保存文件
        var packageName = Java.use("android.app.ActivityThread").currentApplication().getApplicationContext().getPackageName();
        var savePath = "/data/data/" + packageName + "/";
        
        console.log("[*] 进程内存范围: " + base + " - " + ptr(base.toInt32() + size));
        
        var dexCount = 0;
        Memory.scan(base, size, "64 65 78 0a", {
            onMatch: function (address, size) {
                // 找到DEX文件魔数 "dex\n"
                console.log("[*] 找到DEX文件: " + address);
                
                // 读取DEX头部确认文件大小
                var dexHeaderSize = 0x70; // DEX头部大小固定为112字节
                var headerBuffer = Memory.readByteArray(address, dexHeaderSize);
                
                // 从DEX头部中读取文件大小(offset为32的位置存放文件大小)
                var fileSize = Memory.readU32(address.add(32));
                console.log("[*] DEX文件大小: " + fileSize + " 字节");
                
                // 读取整个DEX文件内容
                var dexBuffer = Memory.readByteArray(address, fileSize);
                
                // 保存到文件
                var dexFileName = savePath + "dump_" + dexCount + ".dex";
                var file = new File(dexFileName, "wb");
                file.write(dexBuffer);
                file.flush();
                file.close();
                
                console.log("[+] 已保存DEX文件: " + dexFileName);
                dexCount++;
            },
            onError: function (reason) {
                console.log("[!] 内存扫描错误: " + reason);
            },
            onComplete: function () {
                console.log("[*] 内存扫描完成，共找到 " + dexCount + " 个DEX文件");
                if (dexCount > 0) {
                    console.log("[*] 请使用以下命令提取DEX文件：");
                    console.log("    adb pull " + savePath + "dump_*.dex .");
                }
            }
        });
    }
    
    // 延迟执行，等待应用加载完成
    setTimeout(dumpDex, 2000);
}); 