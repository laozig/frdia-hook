/*
 * 脚本名称：通杀绕过APP完整性校验.js
 * 功能描述：绕过应用对自身文件和资源完整性的校验，使修改后的应用能够正常运行
 * 
 * 适用场景：
 *   - 运行被修改或重打包的应用
 *   - 突破应用的自我保护机制
 *   - 逆向分析具有完整性校验的应用
 *   - 测试应用在修改后的行为
 *   - 分析应用的安全防护机制实现
 *
 * 使用方法：
 *   1. frida -U -f 目标应用包名 -l 通杀绕过APP完整性校验.js --no-pause
 *   2. 或者 frida -U --attach-pid 目标进程PID -l 通杀绕过APP完整性校验.js
 *   3. 应用将无法检测到自身文件被修改
 *
 * 启动方式说明：
 *   - -U: 使用USB连接的设备
 *   - -f: 指定以spawn方式启动的应用包名
 *   - --attach-pid: 附加到已运行的进程
 *   - --no-pause: 注入后不暂停应用执行
 *
 * 工作原理：
 *   应用完整性校验主要通过两种常见的方法：
 *   
 *   1. 拦截MessageDigest.digest方法：
 *      - MessageDigest用于计算哈希值(如MD5、SHA)，是APK完整性校验的常用方法
 *      - 脚本返回一个固定的伪造哈希值，欺骗应用认为文件未被修改
 *   
 *   2. 拦截CRC32.getValue方法：
 *      - CRC32是常用的校验和算法，应用可能用它检查资源文件完整性
 *      - 脚本将返回值固定为0，使校验和验证总是通过
 *
 *   通过这两种拦截，可以绕过大多数常见的完整性校验机制。
 *
 * 注意事项：
 *   - 应用可能使用多种哈希算法或自定义校验方法，可能需要扩展脚本
 *   - 部分应用在Native层实现完整性校验，此脚本可能不完全有效
 *   - 建议与通杀绕过签名校验.js和通杀绕过SO完整性校验.js配合使用
 *   - 伪造的哈希值可能需要针对特定应用进行调整
 *   - 对于高度防护的应用，可能需要通过分析确定真正的校验点
 */
// 通杀绕过APP完整性校验
Java.perform(function () {
    var MessageDigest = Java.use('java.security.MessageDigest');
    MessageDigest.digest.overload().implementation = function () {
        console.log('[*] APP完整性校验拦截: MessageDigest.digest (返回伪造值)');
        var fake = [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15];
        return fake;
    };
    var CRC32 = Java.use('java.util.zip.CRC32');
    CRC32.getValue.implementation = function () {
        console.log('[*] APP完整性校验拦截: CRC32.getValue (返回0)');
        return 0;
    };
}); 