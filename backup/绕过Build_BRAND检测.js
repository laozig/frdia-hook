/*
 * 脚本名称：绕过Build_BRAND检测.js
 * 功能描述：绕过Android应用对设备品牌的检测，伪装设备为Google品牌设备
 * 
 * 适用场景：
 *   - 绕过应用的模拟器检测机制
 *   - 伪装设备型号，绕过设备限制
 *   - 对抗基于设备品牌的环境检测
 *   - 测试应用在不同品牌设备上的行为
 *   - 绕过只允许在特定设备上运行的限制
 *
 * 使用方法：
 *   1. frida -U -f 目标应用包名 -l 绕过Build_BRAND检测.js --no-pause
 *   2. 或者 frida -U --attach-pid 目标进程PID -l 绕过Build_BRAND检测.js
 *   3. 应用将会识别设备为Google品牌设备
 *
 * 启动方式说明：
 *   - -U: 使用USB连接的设备
 *   - -f: 指定以spawn方式启动的应用包名
 *   - --attach-pid: 附加到已运行的进程
 *   - --no-pause: 注入后不暂停应用执行
 *
 * 工作原理：
 *   通过JavaScript的Object.defineProperty方法重写android.os.Build类的BRAND静态字段，
 *   当应用读取此字段时返回"google"，使应用误认为当前运行在Google品牌设备上。
 *   这可以绕过针对模拟器或特定品牌设备的检测。
 *
 * 定制化：
 *   - 可以修改返回值为其他品牌，如"samsung"、"xiaomi"等
 *   - 可配合其他Build系列脚本一起使用，全面伪装设备信息
 */

// Hook Build.BRAND，绕过模拟器检测
Java.perform(function () {
    var Build = Java.use('android.os.Build');
    
    // 重定义BRAND静态属性的getter方法
    Object.defineProperty(Build, 'BRAND', {
        get: function () {
            // 输出拦截信息
            console.log("[*] 检测到Build.BRAND读取 (返回伪造值)");
            console.log("    原始值: " + this.BRAND.value);
            
            // 返回伪造的品牌名称，可根据需要修改
            return "google"; // 伪装为Google设备
            
            // 其他常用品牌选项：
            // return "samsung"; // 三星
            // return "xiaomi";  // 小米
            // return "huawei";  // 华为
            // return "oppo";    // OPPO
        }
    });
    
    console.log("[*] Build.BRAND伪装已启用 (伪装为: google)");
}); 