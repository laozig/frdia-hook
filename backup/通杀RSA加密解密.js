/*
 * 脚本名称：通杀RSA加密解密.js
 * 功能：自动监控所有RSA加密、解密、签名、验签操作，辅助算法还原、数据分析
 * 适用场景：RSA逆向、数据还原、协议分析
 * 使用方法：
 *   1. frida -U -f 包名 -l 通杀RSA加密解密.js --no-pause
 *   2. 查看控制台输出，获取RSA输入输出信息
 * 启动方式说明：
 *   - -U 代表使用USB连接的设备
 *   - -f 代表以spawn方式启动目标应用（推荐，可以捕获启动阶段的加密操作）
 *   - --no-pause 指示Frida不要暂停应用执行，保证App正常运行
 *   - 也可使用 -F 以attach方式附加到已运行的进程
 * 参数说明：
 *   - 包名：目标应用的包名，如com.example.app
 * 输出说明：
 *   - 会输出获取Cipher实例的算法名称
 *   - 会输出加密/解密操作的输入数据和结果
 * 注意事项：
 *   - 某些加固应用需配合反检测脚本（如通杀绕过反Frida检测.js）
 *   - 如果目标使用自定义加密库，可能需要额外hook Native层
 *   - 多用于分析网络请求加密、敏感信息加密等场景
 */

// 通杀RSA加密解密
Java.perform(function () {
    // 获取Java标准库中的Cipher类引用，用于加密解密操作
    var Cipher = Java.use('javax.crypto.Cipher');
    
    // Hook Cipher.getInstance方法，监控RSA算法的实例创建
    // 参数transformation格式通常为："算法/模式/填充"，如"RSA/ECB/PKCS1Padding"
    Cipher.getInstance.overload('java.lang.String').implementation = function (transformation) {
        // 检查是否包含RSA字符串，识别RSA相关的加密操作
        if (transformation && transformation.indexOf('RSA') !== -1) {
            console.log('[*] 获取RSA Cipher实例: ' + transformation);
            // 可以在这里添加断点或额外日志来分析调用堆栈
            // console.log(Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()));
        }
        // 调用原始方法，保持正常功能
        return this.getInstance(transformation);
    };
    
    // Hook Cipher.doFinal方法，捕获实际的加密/解密操作
    // 此重载处理单个字节数组输入的情况
    Cipher.doFinal.overload('[B').implementation = function (input) {
        // 获取当前使用的算法
        var algo = this.getAlgorithm();
        // 仅处理RSA相关算法
        if (algo && algo.indexOf('RSA') !== -1) {
            // 将输入字节数组转换为字符串以便查看
            var str = Java.use('java.lang.String').$new(input);
            // 执行原始加密/解密操作
            var result = this.doFinal(input);
            // 输出详细信息，包括输入数据和结果
            console.log('[*] RSA doFinal 输入: ' + str + ' 输出: ' + result);
            // 返回原始结果
            return result;
        }
        // 非RSA算法，直接执行原始方法
        return this.doFinal(input);
    };
    
    // 注：完整实现应该hook其他doFinal重载方法，如带偏移量的版本
    // Cipher.doFinal.overload('[B', 'int', 'int')
    // Cipher.doFinal.overload('[B', 'int', 'int', '[B', 'int')
    // 以及init方法来获取密钥和操作模式(加密/解密)
}); 