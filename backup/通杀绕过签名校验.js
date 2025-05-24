/*
 * 脚本名称：通杀绕过签名校验.js
 * 功能描述：绕过应用对APK签名的验证，适用于修改过的应用或重打包应用
 * 
 * 适用场景：
 *   - 运行重打包或修改后的应用
 *   - 测试应用的安全防护机制
 *   - 绕过应用的自我保护和完整性校验
 *   - 分析具有签名校验机制的应用
 *   - 对修改后的应用进行功能测试和调试
 *
 * 使用方法：
 *   1. frida -U -f 目标应用包名 -l 通杀绕过签名校验.js --no-pause
 *   2. 或者 frida -U --attach-pid 目标进程PID -l 通杀绕过签名校验.js
 *   3. 应用将无法检测到签名被修改或不一致
 *
 * 启动方式说明：
 *   - -U: 使用USB连接的设备
 *   - -f: 指定以spawn方式启动的应用包名
 *   - --attach-pid: 附加到已运行的进程
 *   - --no-pause: 注入后不暂停应用执行
 *
 * 工作原理：
 *   Hook android.app.ApplicationPackageManager类的getPackageInfo方法：
 *   1. 此方法用于获取应用包的信息，包括签名(当flags参数包含GET_SIGNATURES时)
 *   2. 当应用调用此方法检查签名时，脚本会在返回结果中替换真实签名为伪造签名
 *   3. 创建一个固定的"FAKE_SIGNATURE"签名对象替换原有签名
 *   4. 这样应用在验证签名时，总是会获得相同的伪造签名，绕过签名不一致的检测
 *
 * 注意事项：
 *   - 应用可能使用多种方法检查签名，如PackageInfo.signatures、证书指纹比较等
 *   - 某些应用可能在Native层验证签名，此脚本对此类验证无效
 *   - 建议与绕过APP完整性校验.js配合使用，全面应对自我保护机制
 *   - 适用于大多数标准签名验证方式，但定制验证方法可能需要额外处理
 *   - 实际使用时可能需要定制"FAKE_SIGNATURE"为应用期望的有效签名
 */
// 通杀绕过签名校验
Java.perform(function () {
    var PackageManager = Java.use('android.app.ApplicationPackageManager');
    PackageManager.getPackageInfo.overload('java.lang.String', 'int').implementation = function (pkg, flags) {
        var info = this.getPackageInfo(pkg, flags);
        try {
            var sigs = info.signatures;
            if (sigs && sigs.length > 0) {
                for (var i = 0; i < sigs.length; i++) {
                    sigs[i] = Java.use('android.content.pm.Signature').$new('FAKE_SIGNATURE');
                }
            }
        } catch (e) {}
        console.log('[*] 签名校验拦截: ' + pkg + ' (返回伪造签名)');
        return info;
    };
}); 