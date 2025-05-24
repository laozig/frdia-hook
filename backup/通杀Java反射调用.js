/*
 * 脚本名称：通杀Java反射调用.js
 * 功能：自动监控所有Java反射相关API调用，辅助分析动态调用、反射还原
 * 适用场景：反射壳、动态加载、协议分析、数据还原
 * 使用方法：
 *   1. frida -U -f 包名 -l 通杀Java反射调用.js --no-pause
 *   2. 查看控制台输出，获取反射调用信息
 * 启动方式说明：
 *   - -U 代表使用USB连接的设备
 *   - -f 代表以spawn方式启动目标应用（推荐，可以捕获启动阶段的反射操作）
 *   - --no-pause 指示Frida不要暂停应用执行，保证App正常运行
 *   - 也可使用 -F 以attach方式附加到已运行的进程
 * 参数说明：
 *   - 包名：目标应用的包名，如com.example.app
 * 检测原理：
 *   - Method.invoke：拦截所有通过反射调用的方法
 *   - Constructor.newInstance：拦截所有通过反射创建的对象实例
 * 输出内容：
 *   - 方法名称：被反射调用的目标方法名
 *   - 类名称：被反射构造的目标类名
 *   - 参数信息：传递给反射调用的参数值
 * 适用场景详解：
 *   - 反混淆：还原被混淆代码的实际调用关系
 *   - 加壳分析：分析壳通过反射调用原始程序的过程
 *   - 动态加载：监控动态加载的类和方法的调用情况
 *   - 安全分析：检测是否存在恶意代码通过反射执行敏感操作
 * 注意事项：
 *   - 某些加固应用需配合反检测脚本（如通杀绕过反Frida检测.js）
 *   - 大型应用可能产生大量反射调用，可添加过滤条件减少输出
 *   - 建议与通杀类加载.js和通杀动态加载dex.js配合使用
 */

// 通杀Java反射调用
Java.perform(function () {
    // 获取Java反射API中的Method类引用
    var Method = Java.use('java.lang.reflect.Method');
    
    // Hook Method.invoke方法，监控所有通过反射进行的方法调用
    // invoke方法用于通过反射调用某个具体方法，常用于绕过访问限制或动态调用
    Method.invoke.implementation = function (obj, args) {
        // 获取被调用方法的名称
        var methodName = this.getName();
        
        // 获取所属类的完整名称
        var className = this.getDeclaringClass().getName();
        
        // 输出详细的调用信息
        console.log('[*] 反射调用: ' + className + '.' + methodName);
        
        // 尝试输出调用参数
        if (args && args.length > 0) {
            try {
                for (var i = 0; i < args.length; i++) {
                    if (args[i] !== null) {
                        console.log('    参数[' + i + ']: ' + args[i].toString());
                    } else {
                        console.log('    参数[' + i + ']: null');
                    }
                }
            } catch (e) {
                console.log('    参数解析异常: ' + e);
            }
        }
        
        // 添加调用堆栈跟踪，帮助定位反射调用的来源
        console.log('    调用堆栈: ');
        console.log('    ' + Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()).split('\n').slice(2, 7).join('\n    '));
        
        // 执行原始方法并捕获返回值
        var result = this.invoke(obj, args);
        
        // 尝试输出返回值信息（如果不是null）
        if (result !== null) {
            try {
                console.log('    返回值: ' + result.toString());
            } catch (e) {
                console.log('    返回值: <无法显示>');
            }
        } else {
            console.log('    返回值: null');
        }
        
        // 返回原始结果，保持应用正常功能
        return result;
    };
    
    // 获取Java反射API中的Constructor类引用
    var Constructor = Java.use('java.lang.reflect.Constructor');
    
    // Hook Constructor.newInstance方法，监控所有通过反射创建的对象
    // newInstance方法用于通过反射动态创建对象实例
    Constructor.newInstance.overload('[Ljava.lang.Object;').implementation = function (args) {
        // 获取构造函数所属类的完整名称
        var className = this.getDeclaringClass().getName();
        
        // 输出详细的构造信息
        console.log('[*] 反射构造实例: ' + className);
        
        // 尝试输出构造参数
        if (args && args.length > 0) {
            try {
                for (var i = 0; i < args.length; i++) {
                    if (args[i] !== null) {
                        console.log('    参数[' + i + ']: ' + args[i].toString());
                    } else {
                        console.log('    参数[' + i + ']: null');
                    }
                }
            } catch (e) {
                console.log('    参数解析异常: ' + e);
            }
        }
        
        // 添加调用堆栈跟踪
        console.log('    调用堆栈: ');
        console.log('    ' + Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new()).split('\n').slice(2, 7).join('\n    '));
        
        // 执行原始方法并返回结果
        return this.newInstance(args);
    };
    
    // 注意：更完整的实现可以考虑以下几点：
    // 1. Hook Class.forName方法来监控类的加载
    // 2. Hook Field.get/set方法来监控字段的读写
    // 3. 添加白名单过滤机制，忽略框架内部的反射调用
    // 4. 处理各种重载的invoke和newInstance方法
}); 