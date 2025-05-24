/*
 * 脚本名称：阻止文件删除.js
 * 功能描述：监控并阻止应用程序的文件删除操作，保护指定文件不被删除
 * 
 * 适用场景：
 *   - 保护重要数据文件不被应用删除
 *   - 防止应用清理缓存和证据文件
 *   - 分析应用的文件操作行为
 *   - 保留应用运行时生成的临时文件
 *   - 数据取证和安全研究
 *
 * 使用方法：
 *   1. frida -U -f 目标应用包名 -l 阻止文件删除.js --no-pause
 *   2. 或者 frida -U --attach-pid 目标进程PID -l 阻止文件删除.js
 *   3. 观察控制台输出，了解应用尝试删除的文件
 *
 * 启动方式说明：
 *   - -U: 使用USB连接的设备
 *   - -f: 指定以spawn方式启动的应用包名
 *   - --attach-pid: 附加到已运行的进程
 *   - --no-pause: 注入后不暂停应用执行
 *
 * 工作原理：
 *   Hook java.io.File类的delete方法，当应用尝试删除文件时，记录文件路径并返回false，
 *   让应用误认为删除操作失败。通过这种方式可以保留应用正常情况下会删除的文件。
 *
 * 高级用法：
 *   - 可修改脚本，只保护特定路径的文件
 *   - 可根据文件后缀名选择性保护
 *   - 可添加删除操作的调用堆栈记录
 *   - 结合其他文件监控脚本使用，全面分析应用的文件操作
 */

// Hook 文件删除操作，监控和阻止文件删除
Java.perform(function () {
    var File = Java.use('java.io.File');
    
    // 拦截File.delete方法
    File.delete.implementation = function () {
        var path = this.getAbsolutePath();
        console.log("[*] 文件删除操作被拦截: " + path);
        
        // 可选：根据路径做选择性拦截
        // if (path.indexOf("important_data") !== -1 || path.endsWith(".db")) {
        //     console.log("    保护重要文件: " + path);
        //     return false; // 只阻止特定文件的删除
        // }
        // return this.delete(); // 允许删除其他文件
        
        // 当前模式：阻止所有文件删除
        return false;
    };
    
    // 可选：也可以Hook其他删除方法
    // var FileOutputStream = Java.use('java.io.FileOutputStream');
    // FileOutputStream.$init.overload('java.io.File', 'boolean').implementation = function(file, append) {
    //     var path = file.getAbsolutePath();
    //     console.log("[*] 文件写入操作: " + path + ", append: " + append);
    //     return this.$init(file, true); // 强制为追加模式，防止覆盖
    // };
    
    console.log("[*] 文件删除保护已启用");
}); 