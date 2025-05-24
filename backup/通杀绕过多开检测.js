/*
 * 脚本名称：通杀绕过多开检测.js
 * 功能描述：绕过应用对多开环境的检测，让多开应用能够正常运行
 * 
 * 适用场景：
 *   - 在模拟器或分身应用中运行拒绝多开的应用
 *   - 多设备测试和自动化测试场景
 *   - 绕过游戏、社交、金融类应用的多开限制
 *   - 同时运行同一应用的多个实例进行测试
 *   - 分析应用的多开检测机制
 *
 * 使用方法：
 *   1. frida -U -f 目标应用包名 -l 通杀绕过多开检测.js --no-pause
 *   2. 或者 frida -U --attach-pid 目标进程PID -l 通杀绕过多开检测.js
 *   3. 应用将无法识别运行环境为多开/分身环境
 *
 * 启动方式说明：
 *   - -U: 使用USB连接的设备
 *   - -f: 指定以spawn方式启动的应用包名
 *   - --attach-pid: 附加到已运行的进程
 *   - --no-pause: 注入后不暂停应用执行
 *
 * 工作原理：
 *   1. 拦截包名检测：
 *      Hook android.app.Application.getPackageName方法，检测返回的包名是否包含
 *      多开应用特征关键词如"clone"或"multi"，如包含则替换为原始包名。
 *   
 *   2. 拦截进程ID检测：
 *      Hook android.os.Process.myPid方法，记录进程ID但不修改，便于监控应用
 *      对进程ID的使用情况，帮助分析多开检测机制。
 *      
 *   多开检测常依赖于包名特征和多进程特征，通过修改这些信息，可以有效规避检测。
 *
 * 注意事项：
 *   - 脚本中的'com.example.app'需替换为目标应用的真实包名
 *   - 部分应用可能通过文件路径、签名等方式检测多开，可能需要额外处理
 *   - 高级应用可能在Native层实现多开检测，此脚本可能不完全有效
 *   - 可与通杀绕过沙箱检测.js配合使用，提高成功率
 *   - 部分应用可能通过/data/data路径检测多开，需要增加相应Hook
 */
// 通杀绕过多开检测
Java.perform(function () {
    var Application = Java.use('android.app.Application');
    Application.getPackageName.implementation = function () {
        var pkg = this.getPackageName();
        if (pkg && (pkg.indexOf('clone') !== -1 || pkg.indexOf('multi') !== -1)) {
            console.log('[*] 多开检测拦截: ' + pkg + ' (返回主包名)');
            return 'com.example.app';
        }
        return pkg;
    };
    var Process = Java.use('android.os.Process');
    Process.myPid.implementation = function () {
        var pid = this.myPid();
        console.log('[*] 多开检测拦截: myPid = ' + pid);
        return pid;
    };
}); 