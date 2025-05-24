/*
 * 脚本名称：监控HttpURLConnection网络请求.js
 * 功能：自动监控应用中的HTTP/HTTPS网络请求，输出URL、请求头、请求体和响应内容
 * 适用场景：API分析、网络流量监控、协议分析、安全评估、隐私数据检测
 * 使用方法：
 *   1. frida -U -f 包名 -l 监控HttpURLConnection网络请求.js --no-pause
 *   2. 查看控制台输出，获取HTTP请求信息
 * 启动方式说明：
 *   - -U 代表使用USB连接的设备
 *   - -f 代表以spawn方式启动目标应用（推荐，可以捕获启动阶段的网络请求）
 *   - --no-pause 指示Frida不要暂停应用执行，保证App正常运行
 *   - 也可使用 -F 以attach方式附加到已运行的进程
 * 参数说明：
 *   - 包名：目标应用的包名，如com.example.app
 * 监控函数说明：
 *   - URL.openConnection: 创建连接对象
 *   - HttpURLConnection.connect: 建立连接
 *   - HttpURLConnection.getInputStream: 获取响应数据
 *   - HttpURLConnection.getOutputStream: 发送请求数据
 *   - HttpURLConnection.setRequestMethod: 设置请求方法(GET/POST等)
 *   - HttpURLConnection.setRequestProperty: 设置请求头
 * 网络请求流程：
 *   1. 创建URL对象
 *   2. 调用openConnection()获取HttpURLConnection
 *   3. 配置连接参数(超时、方法、请求头等)
 *   4. 建立连接connect()
 *   5. 发送数据(如果是POST等方法)
 *   6. 读取响应
 *   7. 关闭连接
 * 输出内容：
 *   - URL: 完整的请求地址
 *   - 请求方法: GET/POST/PUT/DELETE等
 *   - 请求头: 所有HTTP头部信息
 *   - 请求体: POST等方法的请求数据
 *   - 响应码: HTTP状态码
 *   - 响应头: 服务器返回的头部信息
 *   - 响应体: 服务器返回的内容(可能很长会截断)
 *   - 调用位置: 发起请求的代码位置
 * 实际应用场景：
 *   - 分析应用API调用流程
 *   - 查看敏感数据传输
 *   - 检测隐私信息泄露
 *   - 识别加密通信模式
 * 注意事项：
 *   - 某些加固应用需配合反检测脚本
 *   - HTTPS请求可能需要配合SSL Pinning绕过脚本
 *   - 大型应用可能产生大量网络请求日志
 *   - 响应体过大时会进行截断显示
 */

// 监控HttpURLConnection网络请求
Java.perform(function () {
    // 辅助函数：获取简短调用堆栈
    function getStackShort() {
        return Java.use("android.util.Log").getStackTraceString(
            Java.use("java.lang.Exception").$new()).split('\n').slice(2, 5).join('\n    ');
    }
    
    // 辅助函数：读取输入流内容
    function readStreamContent(inputStream) {
        try {
            // 创建BufferedReader读取流内容
            var BufferedReader = Java.use('java.io.BufferedReader');
            var InputStreamReader = Java.use('java.io.InputStreamReader');
            var reader = BufferedReader.$new(InputStreamReader.$new(inputStream));
            
            // 读取全部内容
            var StringBuilder = Java.use('java.lang.StringBuilder');
            var sb = StringBuilder.$new();
            var line;
            while ((line = reader.readLine()) !== null) {
                sb.append(line);
                sb.append('\n');
            }
            var content = sb.toString();
            
            // 如果内容太长，只返回前面一部分
            var maxLen = 2000;
            if (content.length > maxLen) {
                return content.substring(0, maxLen) + "... (省略 " + (content.length - maxLen) + " 字符)";
            }
            return content;
        } catch (e) {
            return "<读取内容失败: " + e + ">";
        }
    }
    
    // 辅助函数：复制输入流
    function cloneInputStream(inputStream) {
        try {
            var ByteArrayOutputStream = Java.use('java.io.ByteArrayOutputStream');
            var ByteArrayInputStream = Java.use('java.io.ByteArrayInputStream');
            
            var buffer = Java.array('byte', new Array(1024));
            var baos = ByteArrayOutputStream.$new();
            var read = 0;
            
            while ((read = inputStream.read(buffer)) !== -1) {
                baos.write(buffer, 0, read);
            }
            
            inputStream.close();
            var bytes = baos.toByteArray();
            var newStream = ByteArrayInputStream.$new(bytes);
            
            return newStream;
        } catch (e) {
            console.log("复制输入流失败: " + e);
            return null;
        }
    }
    
    // 辅助函数：检测敏感信息
    function checkSensitiveInfo(content) {
        if (!content) return [];
        
        var findings = [];
        
        // 检测常见敏感信息模式
        var patterns = [
            { name: "JWT Token", regex: /eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+/g },
            { name: "API Key", regex: /['"](api[_-]?key|apikey|api[_-]?token)['"]\s*[:=]\s*['"]([^'"]+)['"]/gi },
            { name: "密码字段", regex: /["'](password|passwd|pwd)["']\s*[:=]\s*["']([^"']+)["']/gi },
            { name: "手机号", regex: /1[3-9]\d{9}/g },
            { name: "邮箱地址", regex: /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g },
            { name: "身份证号", regex: /[1-9]\d{5}(19|20)\d{2}(0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])\d{3}[\dXx]/g },
            { name: "GPS坐标", regex: /["'](latitude|longitude)["']\s*[:=]\s*["']?(\d+\.\d+)["']?/gi }
        ];
        
        for (var i = 0; i < patterns.length; i++) {
            var matches = content.match(patterns[i].regex);
            if (matches) {
                findings.push(patterns[i].name + ": " + matches.join(", "));
            }
        }
        
        return findings;
    }
    
    // 存储HttpURLConnection对象的配置信息
    var connectionInfo = {};
    
    //===== 监控URL类 =====
    var URL = Java.use('java.net.URL');
    
    // 监控URL.openConnection创建连接
    URL.openConnection.overload().implementation = function() {
        var url = this.toString();
        var conn = this.openConnection();
        
        console.log('\n[*] URL.openConnection: ' + url);
        console.log('    调用堆栈: \n    ' + getStackShort());
        
        // 保存连接信息
        connectionInfo[conn.$handle] = {
            url: url,
            requestMethod: "GET", // 默认方法
            requestHeaders: {},
            requestBody: null
        };
        
        return conn;
    };
    
    //===== 监控HttpURLConnection类 =====
    var HttpURLConnection = Java.use('java.net.HttpURLConnection');
    
    // 监控设置请求方法
    HttpURLConnection.setRequestMethod.implementation = function(method) {
        if (this.$handle in connectionInfo) {
            connectionInfo[this.$handle].requestMethod = method;
        }
        console.log('[*] HttpURLConnection.setRequestMethod: ' + method);
        return this.setRequestMethod(method);
    };
    
    // 监控设置请求头
    HttpURLConnection.setRequestProperty.implementation = function(key, value) {
        console.log('[*] HttpURLConnection.setRequestProperty: ' + key + ' = ' + value);
        
        // 保存请求头
        if (this.$handle in connectionInfo) {
            connectionInfo[this.$handle].requestHeaders[key] = value;
        }
        
        return this.setRequestProperty(key, value);
    };
    
    // 监控setDoOutput方法，通常意味着要发送POST数据
    HttpURLConnection.setDoOutput.implementation = function(dooutput) {
        console.log('[*] HttpURLConnection.setDoOutput: ' + dooutput);
        return this.setDoOutput(dooutput);
    };
    
    // 监控getOutputStream方法，通常用于写入POST数据
    HttpURLConnection.getOutputStream.implementation = function() {
        var url = this.getURL().toString();
        console.log('[*] HttpURLConnection.getOutputStream: ' + url);
        console.log('    请求方法: ' + this.getRequestMethod());
        
        // 创建代理OutputStream来捕获写入的数据
        var realOutputStream = this.getOutputStream();
        var outputStream = realOutputStream;
        
        try {
            var ByteArrayOutputStream = Java.use('java.io.ByteArrayOutputStream');
            var ProxyOutputStream = Java.registerClass({
                name: 'com.proxy.ProxyOutputStream',
                superClass: Java.use('java.io.OutputStream'),
                fields: {
                    'target': 'java.io.OutputStream',
                    'buffer': 'java.io.ByteArrayOutputStream'
                },
                methods: {
                    '<init>': [{
                        returnType: 'void',
                        argumentTypes: ['java.io.OutputStream'],
                        implementation: function(target) {
                            this.target.value = target;
                            this.buffer.value = ByteArrayOutputStream.$new();
                        }
                    }],
                    'write': [{
                        returnType: 'void',
                        argumentTypes: ['int'],
                        implementation: function(oneByte) {
                            this.target.value.write(oneByte);
                            this.buffer.value.write(oneByte);
                        }
                    }, {
                        returnType: 'void',
                        argumentTypes: ['[B'],
                        implementation: function(bytes) {
                            this.target.value.write(bytes);
                            this.buffer.value.write(bytes);
                        }
                    }, {
                        returnType: 'void',
                        argumentTypes: ['[B', 'int', 'int'],
                        implementation: function(bytes, offset, length) {
                            this.target.value.write(bytes, offset, length);
                            this.buffer.value.write(bytes, offset, length);
                        }
                    }],
                    'flush': [{
                        returnType: 'void',
                        argumentTypes: [],
                        implementation: function() {
                            this.target.value.flush();
                        }
                    }],
                    'close': [{
                        returnType: 'void',
                        argumentTypes: [],
                        implementation: function() {
                            // 在关闭时，打印捕获的数据
                            var data = this.buffer.value.toByteArray();
                            var requestBody = Java.use('java.lang.String').$new(data);
                            console.log('[*] 请求体:');
                            console.log(requestBody);
                            
                            // 保存请求体
                            var connHandle = this.target.value.hashCode();
                            if (connHandle in connectionInfo) {
                                connectionInfo[connHandle].requestBody = requestBody;
                            }
                            
                            // 检测敏感信息
                            var findings = checkSensitiveInfo(requestBody);
                            if (findings.length > 0) {
                                console.log('    [!] 检测到敏感信息:');
                                for (var i = 0; i < findings.length; i++) {
                                    console.log('    - ' + findings[i]);
                                }
                            }
                            
                            this.target.value.close();
                        }
                    }]
                }
            });
            
            // 创建代理流
            outputStream = ProxyOutputStream.$new(realOutputStream);
        } catch (e) {
            console.log('    [!] 创建代理OutputStream失败: ' + e);
        }
        
        return outputStream;
    };
    
    // 监控connect方法，表示开始建立连接
    HttpURLConnection.connect.implementation = function () {
        var url = this.getURL().toString();
        console.log('\n[*] HttpURLConnection.connect: ' + url);
        console.log('    请求方法: ' + this.getRequestMethod());
        
        // 打印保存的请求头
        if (this.$handle in connectionInfo) {
            var headers = connectionInfo[this.$handle].requestHeaders;
            if (Object.keys(headers).length > 0) {
                console.log('    请求头:');
                for (var key in headers) {
                    console.log('    - ' + key + ': ' + headers[key]);
                }
            }
        }
        
        return this.connect();
    };
    
    // 监控getResponseCode方法，获取响应状态
    HttpURLConnection.getResponseCode.implementation = function() {
        var code = this.getResponseCode();
        var url = this.getURL().toString();
        console.log('[*] HttpURLConnection.getResponseCode: ' + code + ' (' + url + ')');
        return code;
    };
    
    // 监控getInputStream方法，获取响应体
    HttpURLConnection.getInputStream.implementation = function () {
        var url = this.getURL().toString();
        console.log('\n[*] HttpURLConnection.getInputStream: ' + url);
        
        var statusCode = -1;
        try {
            statusCode = this.getResponseCode();
            console.log('    响应码: ' + statusCode);
        } catch (e) {
            console.log('    获取响应码失败: ' + e);
        }
        
        // 打印响应头
        try {
            var headerFields = this.getHeaderFields();
            if (headerFields) {
                var keyIterator = headerFields.keySet().iterator();
                if (keyIterator.hasNext()) {
                    console.log('    响应头:');
                    while(keyIterator.hasNext()) {
                        var key = keyIterator.next();
                        var values = headerFields.get(key);
                        var valueIterator = values.iterator();
                        var valueStr = "";
                        while(valueIterator.hasNext()) {
                            valueStr += valueIterator.next() + "; ";
                        }
                        console.log('    - ' + (key || "null") + ': ' + valueStr);
                    }
                }
            }
        } catch (e) {
            console.log('    获取响应头失败: ' + e);
        }
        
        // 获取原始输入流并读取内容
        var originalInputStream = this.getInputStream();
        
        // 尝试读取响应内容(会消耗输入流，需要先复制)
        try {
            var streamCopy = cloneInputStream(originalInputStream);
            if (streamCopy !== null) {
                var content = readStreamContent(streamCopy);
                console.log('    响应体:');
                console.log(content);
                
                // 检测敏感信息
                var findings = checkSensitiveInfo(content);
                if (findings.length > 0) {
                    console.log('    [!] 检测到敏感信息:');
                    for (var i = 0; i < findings.length; i++) {
                        console.log('    - ' + findings[i]);
                    }
                }
                
                // 再创建一个流返回给应用使用
                originalInputStream = cloneInputStream(streamCopy);
            }
        } catch (e) {
            console.log('    读取响应内容失败: ' + e);
        }
        
        // 记录调用堆栈
        console.log('    调用堆栈: \n    ' + getStackShort());
        
        return originalInputStream;
    };
    
    // 监控错误流获取，通常在HTTP错误时使用
    HttpURLConnection.getErrorStream.implementation = function() {
        var url = this.getURL().toString();
        console.log('\n[*] HttpURLConnection.getErrorStream: ' + url);
        
        try {
            var statusCode = this.getResponseCode();
            console.log('    错误码: ' + statusCode);
        } catch (e) {}
        
        var errorStream = this.getErrorStream();
        if (errorStream) {
            // 尝试读取错误内容
            try {
                var streamCopy = cloneInputStream(errorStream);
                if (streamCopy !== null) {
                    var content = readStreamContent(streamCopy);
                    console.log('    错误响应内容:');
                    console.log(content);
                    
                    // 再创建一个流返回给应用使用
                    errorStream = cloneInputStream(streamCopy);
                }
            } catch (e) {
                console.log('    读取错误内容失败: ' + e);
            }
        }
        
        return errorStream;
    };
    
    // 监控disconnect方法，连接关闭
    HttpURLConnection.disconnect.implementation = function() {
        var url = this.getURL().toString();
        console.log('[*] HttpURLConnection.disconnect: ' + url);
        
        // 清理连接信息
        if (this.$handle in connectionInfo) {
            delete connectionInfo[this.$handle];
        }
        
        return this.disconnect();
    };
    
    console.log("[*] HttpURLConnection网络请求监控已启动");
    console.log("[*] 监控范围: URL.openConnection、请求配置、数据传输和响应处理");
}); 