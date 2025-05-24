/*
 * 脚本名称：监控SharedPreferences读写.js
 * 功能描述：监控应用对SharedPreferences的读写操作，捕获键值对数据
 * 
 * 适用场景：
 *   - 分析应用的配置信息存储
 *   - 获取应用保存的用户偏好设置
 *   - 发现应用存储的敏感数据（如token、密码等）
 *   - 追踪应用的状态管理和持久化数据
 *   - 分析应用的缓存策略和本地数据管理
 *
 * 使用方法：
 *   1. frida -U -f 目标应用包名 -l 监控SharedPreferences读写.js --no-pause
 *   2. 或者 frida -U --attach-pid 目标进程PID -l 监控SharedPreferences读写.js
 *   3. 操作应用，观察控制台输出的SharedPreferences读写操作
 *
 * 启动方式说明：
 *   - -U: 使用USB连接的设备
 *   - -f: 指定以spawn方式启动的应用包名
 *   - --attach-pid: 附加到已运行的进程
 *   - --no-pause: 注入后不暂停应用执行
 *
 * 工作原理：
 *   Hook android.app.SharedPreferencesImpl类的getString和putString方法，这些方法是应用存取字符串类型配置的常用API。
 *   当应用读取或写入SharedPreferences数据时，脚本会拦截这些操作并记录键名和对应的值，
 *   从而揭示应用在本地存储的配置信息和可能的敏感数据。
 *
 * 注意事项：
 *   - 此脚本仅监控字符串类型的读写，可以扩展监控其他数据类型（如int、boolean等）
 *   - 某些应用可能使用加密方式存储敏感数据
 *   - SharedPreferences文件通常位于/data/data/包名/shared_prefs/目录下
 *   - 可以结合文件系统监控工具分析所有配置文件
 *   - 对于加密存储的数据，可能需要结合其他脚本分析解密逻辑
 */

// Hook SharedPreferences 的 getString 和 putString 方法，监控配置读写
Java.perform(function () {
    var SharedPreferences = Java.use("android.app.SharedPreferencesImpl");
    SharedPreferences.getString.overload('java.lang.String', 'java.lang.String').implementation = function (key, defValue) {
        var result = this.getString(key, defValue);
        console.log("[*] SharedPreferences.getString key: " + key + ", value: " + result);
        return result;
    };
    SharedPreferences.putString.implementation = function (key, value) {
        console.log("[*] SharedPreferences.putString key: " + key + ", value: " + value);
        return this.putString(key, value);
    };
}); 