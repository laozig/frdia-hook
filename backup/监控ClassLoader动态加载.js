/*
 * 脚本名称：监控ClassLoader动态加载.js
 * 功能描述：监控应用通过ClassLoader动态加载的所有Java类
 * 
 * 适用场景：
 *   - 分析应用动态加载的类和逻辑
 *   - 发现应用运行时加载的隐藏功能模块
 *   - 追踪反射调用的类来源
 *   - 分析框架和插件化应用的类加载行为
 *   - 监控应用在不同阶段加载的类
 *
 * 使用方法：
 *   1. frida -U -f 目标应用包名 -l 监控ClassLoader动态加载.js --no-pause
 *   2. 或者 frida -U --attach-pid 目标进程PID -l 监控ClassLoader动态加载.js
 *   3. 操作应用，观察控制台输出的类加载信息
 *
 * 启动方式说明：
 *   - -U: 使用USB连接的设备
 *   - -f: 指定以spawn方式启动的应用包名
 *   - --attach-pid: 附加到已运行的进程
 *   - --no-pause: 注入后不暂停应用执行
 *
 * 工作原理：
 *   Hook java.lang.ClassLoader类的loadClass方法，该方法是所有类加载器加载Java类时必经的路径。
 *   当应用尝试加载任何类时，都会调用此方法，脚本会拦截这些调用并记录被加载的类名，
 *   从而揭示应用在运行时动态加载的所有类，包括那些可能隐藏的功能模块。
 *
 * 注意事项：
 *   - 类加载非常频繁，输出日志可能会很多，建议针对特定包名进行过滤
 *   - 系统类和常见库类也会被记录，可能会干扰关键信息的识别
 *   - 对于混淆后的应用，类名可能难以理解，需要结合其他信息分析
 *   - 可以修改脚本，添加正则表达式过滤感兴趣的类名
 *   - 与反射监控脚本配合使用效果更佳
 */

// Hook ClassLoader 的 loadClass 方法，监控类的动态加载
Java.perform(function () {
    var ClassLoader = Java.use("java.lang.ClassLoader");
    ClassLoader.loadClass.overload('java.lang.String').implementation = function (name) {
        console.log("[*] ClassLoader.loadClass: " + name);
        return this.loadClass(name);
    };
}); 