/**
 * 网络请求拦截脚本
 * 
 * 功能：拦截Android应用中的网络请求和响应
 * 作用：分析应用的API调用、数据传输和服务器交互
 * 适用：API分析、数据抓取、协议分析
 */

// 等待Java虚拟机加载完成
Java.perform(function() {
    console.log("[*] 网络请求拦截脚本已启动");

    // 全局配置
    var config = {
        // 是否显示详细日志
        verbose: true,
        // 是否打印调用堆栈
        printStack: true,
        // 是否打印请求体和响应体
        printBody: true,
        // 是否打印请求头和响应头
        printHeaders: true,
        // 最大打印长度
        maxPrintLength: 2048,
        // 是否保存响应到文件
        saveToFile: false,
        // 保存文件的路径
        savePath: "/data/local/tmp/"
    };

    /**
     * 工具函数：获取调用堆栈
     */
    function getStackTrace() {
        var Exception = Java.use("java.lang.Exception");
        var exception = Exception.$new();
        var stackTrace = exception.getStackTrace();
        exception.$dispose();
        
        var stack = [];
        for (var i = 0; i < stackTrace.length; i++) {
            var element = stackTrace[i];
            var className = element.getClassName();
            var methodName = element.getMethodName();
            var fileName = element.getFileName();
            var lineNumber = element.getLineNumber();
            
            // 过滤掉Frida相关的堆栈
            if (className.indexOf("com.frida") === -1) {
                stack.push(className + "." + methodName + "(" + fileName + ":" + lineNumber + ")");
            }
            
            // 只获取前10个堆栈元素
            if (stack.length >= 10) break;
        }
        
        return stack.join("\n    ");
    }

    /**
     * 工具函数：将字节数组转换为字符串
     */
    function bytesToString(bytes) {
        if (bytes === null) return "null";
        if (bytes === undefined) return "undefined";
        
        try {
            var String = Java.use("java.lang.String");
            var result = String.$new(bytes, "UTF-8");
            
            // 限制长度
            if (result.length() > config.maxPrintLength) {
                result = result.substring(0, config.maxPrintLength) + "... (截断，共 " + result.length() + " 字符)";
            }
            
            return result;
        } catch (e) {
            return "<字符串转换失败: " + e + ">";
        }
    }

    /**
     * 工具函数：将输入流转换为字节数组
     */
    function inputStreamToBytes(inputStream) {
        if (inputStream === null) return null;
        
        try {
            var ByteArrayOutputStream = Java.use("java.io.ByteArrayOutputStream");
            var baos = ByteArrayOutputStream.$new();
            var buffer = Java.array('byte', new Array(1024).fill(0));
            var len;
            
            while ((len = inputStream.read(buffer)) !== -1) {
                baos.write(buffer, 0, len);
            }
            
            return baos.toByteArray();
        } catch (e) {
            console.log("[-] 输入流转换失败: " + e);
            return null;
        }
    }

    /**
     * 工具函数：保存数据到文件
     */
    function saveToFile(data, url) {
        if (!config.saveToFile || data === null) return;
        
        try {
            // 生成文件名
            var fileName = url.replace(/[^a-zA-Z0-9]/g, "_").substring(0, 50);
            var timestamp = new Date().getTime();
            var filePath = config.savePath + fileName + "_" + timestamp;
            
            // 保存文件
            var FileOutputStream = Java.use("java.io.FileOutputStream");
            var file = FileOutputStream.$new(filePath);
            file.write(data);
            file.close();
            
            console.log("[+] 已保存响应到文件: " + filePath);
        } catch (e) {
            console.log("[-] 保存文件失败: " + e);
        }
    }

    /**
     * 工具函数：格式化请求头和响应头
     */
    function formatHeaders(headers) {
        if (!headers) return "无";
        
        var result = "";
        var keys = headers.keySet().toArray();
        
        for (var i = 0; i < keys.length; i++) {
            var key = keys[i];
            var value = headers.get(key);
            result += "      " + key + ": " + value + "\n";
        }
        
        return result.trim();
    }

    /**
     * 一、拦截HttpURLConnection
     */
    try {
        var URL = Java.use("java.net.URL");
        var HttpURLConnection = Java.use("java.net.HttpURLConnection");
        var HttpsURLConnection = Java.use("javax.net.ssl.HttpsURLConnection");
        
        // 拦截URL.openConnection方法
        URL.openConnection.overload().implementation = function() {
            var connection = this.openConnection();
            var url = this.toString();
            
            if (config.verbose) {
                console.log("\n[+] URL.openConnection: " + url);
                
                if (config.printStack) {
                    console.log("    调用堆栈:\n    " + getStackTrace());
                }
            }
            
            return connection;
        };
        
        // 拦截HttpURLConnection.setRequestMethod方法
        HttpURLConnection.setRequestMethod.implementation = function(method) {
            var url = this.getURL().toString();
            
            if (config.verbose) {
                console.log("\n[+] HttpURLConnection.setRequestMethod: " + method);
                console.log("    URL: " + url);
                
                if (config.printStack) {
                    console.log("    调用堆栈:\n    " + getStackTrace());
                }
            }
            
            return this.setRequestMethod(method);
        };
        
        // 拦截HttpURLConnection.getInputStream方法
        HttpURLConnection.getInputStream.overload().implementation = function() {
            var url = this.getURL().toString();
            var method = this.getRequestMethod();
            var responseCode = this.getResponseCode();
            
            console.log("\n[+] HTTP请求: " + method + " " + url);
            console.log("    响应码: " + responseCode);
            
            if (config.printHeaders) {
                // 打印请求头
                console.log("    请求头:");
                var requestHeaders = this.getRequestProperties();
                console.log("      " + formatHeaders(requestHeaders));
                
                // 打印响应头
                console.log("    响应头:");
                var headerFields = this.getHeaderFields();
                var keys = headerFields.keySet().toArray();
                for (var i = 0; i < keys.length; i++) {
                    var key = keys[i];
                    if (key !== null) {
                        var values = headerFields.get(key).toArray();
                        console.log("      " + key + ": " + values.join(", "));
                    }
                }
            }
            
            // 获取输入流
            var inputStream = this.getInputStream();
            
            if (config.printBody) {
                try {
                    // 保存原始输入流
                    var originalBytes = inputStreamToBytes(inputStream);
                    
                    // 打印响应体
                    var responseBody = bytesToString(originalBytes);
                    console.log("    响应体:\n" + responseBody);
                    
                    // 保存到文件
                    if (config.saveToFile) {
                        saveToFile(originalBytes, url);
                    }
                    
                    // 创建新的输入流返回
                    var ByteArrayInputStream = Java.use("java.io.ByteArrayInputStream");
                    return ByteArrayInputStream.$new(originalBytes);
                } catch (e) {
                    console.log("[-] 处理响应体失败: " + e);
                    // 如果失败，返回原始输入流
                    return inputStream;
                }
            } else {
                return inputStream;
            }
        };
        
        // 拦截HttpURLConnection.getOutputStream方法
        HttpURLConnection.getOutputStream.overload().implementation = function() {
            var url = this.getURL().toString();
            var method = this.getRequestMethod();
            
            if (config.verbose) {
                console.log("\n[+] HttpURLConnection.getOutputStream");
                console.log("    " + method + " " + url);
                
                if (config.printStack) {
                    console.log("    调用堆栈:\n    " + getStackTrace());
                }
            }
            
            // 获取原始输出流
            var originalOutputStream = this.getOutputStream();
            
            if (config.printBody) {
                // 创建一个代理输出流来捕获写入的数据
                var ByteArrayOutputStream = Java.use("java.io.ByteArrayOutputStream");
                var proxyOutputStream = ByteArrayOutputStream.$new();
                
                // 创建一个代理类
                var OutputStreamProxy = Java.registerClass({
                    name: "com.frida.OutputStreamProxy",
                    superClass: Java.use("java.io.OutputStream"),
                    fields: {
                        target: "java.io.OutputStream",
                        buffer: "java.io.ByteArrayOutputStream",
                        url: "java.lang.String"
                    },
                    methods: {
                        $init: [{
                            returnType: "void",
                            argumentTypes: ["java.io.OutputStream", "java.io.ByteArrayOutputStream", "java.lang.String"],
                            implementation: function(target, buffer, url) {
                                this.target.value = target;
                                this.buffer.value = buffer;
                                this.url.value = url;
                            }
                        }],
                        write: [{
                            returnType: "void",
                            argumentTypes: ["int"],
                            implementation: function(oneByte) {
                                // 写入到原始流和缓冲区
                                this.target.value.write(oneByte);
                                this.buffer.value.write(oneByte);
                            }
                        }, {
                            returnType: "void",
                            argumentTypes: ["[B"],
                            implementation: function(bytes) {
                                // 写入到原始流和缓冲区
                                this.target.value.write(bytes);
                                this.buffer.value.write(bytes);
                            }
                        }, {
                            returnType: "void",
                            argumentTypes: ["[B", "int", "int"],
                            implementation: function(bytes, offset, length) {
                                // 写入到原始流和缓冲区
                                this.target.value.write(bytes, offset, length);
                                this.buffer.value.write(bytes, offset, length);
                            }
                        }],
                        flush: {
                            returnType: "void",
                            implementation: function() {
                                this.target.value.flush();
                            }
                        },
                        close: {
                            returnType: "void",
                            implementation: function() {
                                this.target.value.close();
                                
                                // 打印请求体
                                var requestBody = bytesToString(this.buffer.value.toByteArray());
                                console.log("\n[+] HTTP请求体: " + this.url.value);
                                console.log("    " + requestBody);
                            }
                        }
                    }
                });
                
                // 创建并返回代理输出流
                return OutputStreamProxy.$new(originalOutputStream, proxyOutputStream, url);
            } else {
                return originalOutputStream;
            }
        };
        
        console.log("[+] HttpURLConnection拦截设置完成");
    } catch (e) {
        console.log("[-] HttpURLConnection拦截设置失败: " + e);
    }

    /**
     * 二、拦截OkHttp
     */
    try {
        // 尝试加载OkHttp3类
        var OkHttpClient = null;
        var Request = null;
        var RequestBody = null;
        var Response = null;
        var ResponseBody = null;
        
        try {
            OkHttpClient = Java.use("okhttp3.OkHttpClient");
            Request = Java.use("okhttp3.Request");
            RequestBody = Java.use("okhttp3.RequestBody");
            Response = Java.use("okhttp3.Response");
            ResponseBody = Java.use("okhttp3.ResponseBody");
            
            console.log("[+] 检测到OkHttp3库");
        } catch (e) {
            console.log("[-] OkHttp3库未被使用: " + e);
        }
        
        // 如果找到OkHttp3，拦截相关方法
        if (OkHttpClient !== null) {
            // 拦截OkHttpClient.newCall方法
            OkHttpClient.newCall.implementation = function(request) {
                var url = request.url().toString();
                var method = request.method();
                
                console.log("\n[+] OkHttp请求: " + method + " " + url);
                
                if (config.printHeaders) {
                    // 打印请求头
                    console.log("    请求头:");
                    var headers = request.headers();
                    var headerSize = headers.size();
                    for (var i = 0; i < headerSize; i++) {
                        var name = headers.name(i);
                        var value = headers.value(i);
                        console.log("      " + name + ": " + value);
                    }
                }
                
                if (config.printBody && request.body()) {
                    try {
                        // 获取请求体类型
                        var contentType = request.body().contentType();
                        console.log("    请求体类型: " + contentType);
                        
                        // 尝试获取请求体内容
                        var Buffer = Java.use("okio.Buffer");
                        var buffer = Buffer.$new();
                        request.body().writeTo(buffer);
                        var requestBody = buffer.readUtf8();
                        
                        // 限制长度
                        if (requestBody.length() > config.maxPrintLength) {
                            requestBody = requestBody.substring(0, config.maxPrintLength) + "... (截断，共 " + requestBody.length() + " 字符)";
                        }
                        
                        console.log("    请求体:\n" + requestBody);
                    } catch (e) {
                        console.log("    无法获取请求体: " + e);
                    }
                }
                
                if (config.printStack) {
                    console.log("    调用堆栈:\n    " + getStackTrace());
                }
                
                // 拦截响应
                var call = this.newCall(request);
                
                // 替换execute方法
                if (call.execute) {
                    var originalExecute = call.execute;
                    call.execute = function() {
                        var response = originalExecute.call(this);
                        
                        if (config.printBody) {
                            try {
                                var responseBody = response.body();
                                var contentType = responseBody.contentType();
                                var contentLength = responseBody.contentLength();
                                
                                console.log("\n[+] OkHttp响应: " + response.code() + " " + url);
                                console.log("    响应体类型: " + contentType);
                                console.log("    响应体长度: " + contentLength);
                                
                                if (config.printHeaders) {
                                    // 打印响应头
                                    console.log("    响应头:");
                                    var headers = response.headers();
                                    var headerSize = headers.size();
                                    for (var i = 0; i < headerSize; i++) {
                                        var name = headers.name(i);
                                        var value = headers.value(i);
                                        console.log("      " + name + ": " + value);
                                    }
                                }
                                
                                // 获取响应体内容
                                var bodyString = responseBody.string();
                                
                                // 限制长度
                                if (bodyString.length() > config.maxPrintLength) {
                                    bodyString = bodyString.substring(0, config.maxPrintLength) + "... (截断，共 " + bodyString.length() + " 字符)";
                                }
                                
                                console.log("    响应体:\n" + bodyString);
                                
                                // 保存到文件
                                if (config.saveToFile) {
                                    saveToFile(bodyString.getBytes(), url);
                                }
                                
                                // 创建新的响应体
                                var MediaType = Java.use("okhttp3.MediaType");
                                var newResponseBody = ResponseBody.create(contentType, bodyString);
                                
                                // 创建新的响应
                                var ResponseBuilder = Java.use("okhttp3.Response$Builder");
                                var newResponse = ResponseBuilder.$new()
                                    .code(response.code())
                                    .message(response.message())
                                    .request(response.request())
                                    .protocol(response.protocol())
                                    .headers(response.headers())
                                    .body(newResponseBody)
                                    .build();
                                
                                return newResponse;
                            } catch (e) {
                                console.log("[-] 处理OkHttp响应失败: " + e);
                                return response;
                            }
                        } else {
                            return response;
                        }
                    };
                }
                
                return call;
            };
            
            console.log("[+] OkHttp拦截设置完成");
        }
    } catch (e) {
        console.log("[-] OkHttp拦截设置失败: " + e);
    }

    /**
     * 三、拦截Volley
     */
    try {
        // 尝试加载Volley类
        var Volley = Java.use("com.android.volley.toolbox.Volley");
        var JsonRequest = Java.use("com.android.volley.toolbox.JsonRequest");
        var StringRequest = Java.use("com.android.volley.toolbox.StringRequest");
        
        if (JsonRequest !== null) {
            // 拦截JsonRequest构造函数
            JsonRequest.$init.overload('int', 'java.lang.String', 'java.lang.String', 'com.android.volley.Response$Listener', 'com.android.volley.Response$ErrorListener').implementation = function(method, url, requestBody, listener, errorListener) {
                var methodStr = method === 0 ? "GET" : (method === 1 ? "POST" : method.toString());
                
                console.log("\n[+] Volley JsonRequest: " + methodStr + " " + url);
                
                if (requestBody !== null && config.printBody) {
                    console.log("    请求体:\n" + requestBody);
                }
                
                if (config.printStack) {
                    console.log("    调用堆栈:\n    " + getStackTrace());
                }
                
                return this.$init(method, url, requestBody, listener, errorListener);
            };
            
            // 拦截JsonRequest.deliverResponse方法
            JsonRequest.deliverResponse.implementation = function(response) {
                if (config.printBody) {
                    console.log("\n[+] Volley JsonRequest响应:");
                    console.log("    响应体:\n" + response);
                }
                
                return this.deliverResponse(response);
            };
            
            console.log("[+] Volley JsonRequest拦截设置完成");
        }
        
        if (StringRequest !== null) {
            // 拦截StringRequest构造函数
            StringRequest.$init.overload('int', 'java.lang.String', 'com.android.volley.Response$Listener', 'com.android.volley.Response$ErrorListener').implementation = function(method, url, listener, errorListener) {
                var methodStr = method === 0 ? "GET" : (method === 1 ? "POST" : method.toString());
                
                console.log("\n[+] Volley StringRequest: " + methodStr + " " + url);
                
                if (config.printStack) {
                    console.log("    调用堆栈:\n    " + getStackTrace());
                }
                
                return this.$init(method, url, listener, errorListener);
            };
            
            // 拦截StringRequest.deliverResponse方法
            StringRequest.deliverResponse.implementation = function(response) {
                if (config.printBody) {
                    console.log("\n[+] Volley StringRequest响应:");
                    console.log("    响应体:\n" + response);
                }
                
                return this.deliverResponse(response);
            };
            
            console.log("[+] Volley StringRequest拦截设置完成");
        }
    } catch (e) {
        console.log("[-] Volley拦截设置失败: " + e);
    }

    /**
     * 四、拦截Retrofit
     */
    try {
        // 尝试加载Retrofit类
        var Retrofit = Java.use("retrofit2.Retrofit");
        var Call = Java.use("retrofit2.Call");
        var Response = Java.use("retrofit2.Response");
        
        if (Retrofit !== null) {
            // 拦截Retrofit.create方法
            Retrofit.create.implementation = function(service) {
                console.log("\n[+] Retrofit.create: " + service.getName());
                
                if (config.printStack) {
                    console.log("    调用堆栈:\n    " + getStackTrace());
                }
                
                return this.create(service);
            };
            
            console.log("[+] Retrofit拦截设置完成");
        }
        
        // 尝试拦截OkHttp的Interceptor，这是Retrofit内部使用的
        try {
            var Interceptor = Java.use("okhttp3.Interceptor");
            var Chain = Java.use("okhttp3.Interceptor$Chain");
            
            // 创建自定义拦截器
            var CustomInterceptor = Java.registerClass({
                name: "com.frida.CustomInterceptor",
                implements: [Interceptor],
                methods: {
                    intercept: function(chain) {
                        var request = chain.request();
                        var url = request.url().toString();
                        var method = request.method();
                        
                        console.log("\n[+] Retrofit请求: " + method + " " + url);
                        
                        if (config.printHeaders) {
                            // 打印请求头
                            console.log("    请求头:");
                            var headers = request.headers();
                            var headerSize = headers.size();
                            for (var i = 0; i < headerSize; i++) {
                                var name = headers.name(i);
                                var value = headers.value(i);
                                console.log("      " + name + ": " + value);
                            }
                        }
                        
                        if (config.printBody && request.body()) {
                            try {
                                // 获取请求体类型
                                var contentType = request.body().contentType();
                                console.log("    请求体类型: " + contentType);
                                
                                // 尝试获取请求体内容
                                var Buffer = Java.use("okio.Buffer");
                                var buffer = Buffer.$new();
                                request.body().writeTo(buffer);
                                var requestBody = buffer.readUtf8();
                                
                                // 限制长度
                                if (requestBody.length() > config.maxPrintLength) {
                                    requestBody = requestBody.substring(0, config.maxPrintLength) + "... (截断，共 " + requestBody.length() + " 字符)";
                                }
                                
                                console.log("    请求体:\n" + requestBody);
                            } catch (e) {
                                console.log("    无法获取请求体: " + e);
                            }
                        }
                        
                        // 执行请求
                        var response = chain.proceed(request);
                        
                        if (config.printBody) {
                            try {
                                var responseBody = response.body();
                                var contentType = responseBody.contentType();
                                var contentLength = responseBody.contentLength();
                                
                                console.log("\n[+] Retrofit响应: " + response.code() + " " + url);
                                console.log("    响应体类型: " + contentType);
                                console.log("    响应体长度: " + contentLength);
                                
                                if (config.printHeaders) {
                                    // 打印响应头
                                    console.log("    响应头:");
                                    var headers = response.headers();
                                    var headerSize = headers.size();
                                    for (var i = 0; i < headerSize; i++) {
                                        var name = headers.name(i);
                                        var value = headers.value(i);
                                        console.log("      " + name + ": " + value);
                                    }
                                }
                                
                                // 获取响应体内容
                                var source = responseBody.source();
                                source.request(Long.MAX_VALUE.value); // 请求整个内容
                                var buffer = source.buffer();
                                var charset = contentType != null ? contentType.charset(Charset.forName("UTF-8")) : Charset.forName("UTF-8");
                                var bodyString = buffer.clone().readString(charset);
                                
                                // 限制长度
                                if (bodyString.length() > config.maxPrintLength) {
                                    bodyString = bodyString.substring(0, config.maxPrintLength) + "... (截断，共 " + bodyString.length() + " 字符)";
                                }
                                
                                console.log("    响应体:\n" + bodyString);
                                
                                // 保存到文件
                                if (config.saveToFile) {
                                    saveToFile(bodyString.getBytes(), url);
                                }
                            } catch (e) {
                                console.log("[-] 处理Retrofit响应失败: " + e);
                            }
                        }
                        
                        return response;
                    }
                }
            });
            
            // 将自定义拦截器添加到OkHttpClient
            var OkHttpClient = Java.use("okhttp3.OkHttpClient$Builder");
            var originalAddInterceptor = OkHttpClient.addInterceptor;
            
            OkHttpClient.addInterceptor.implementation = function(interceptor) {
                // 添加我们的自定义拦截器
                this.addInterceptor(CustomInterceptor.$new());
                
                // 调用原始方法
                return originalAddInterceptor.call(this, interceptor);
            };
            
            console.log("[+] Retrofit OkHttp拦截器设置完成");
        } catch (e) {
            console.log("[-] Retrofit OkHttp拦截器设置失败: " + e);
        }
    } catch (e) {
        console.log("[-] Retrofit拦截设置失败: " + e);
    }

    /**
     * 修改配置的函数
     */
    global.setNetworkConfig = function(newConfig) {
        for (var key in newConfig) {
            if (config.hasOwnProperty(key)) {
                config[key] = newConfig[key];
                console.log("[+] 网络配置已更新: " + key + " = " + newConfig[key]);
            }
        }
    };

    console.log("[*] 网络请求拦截脚本已加载");
    console.log("[*] 使用方法:");
    console.log("    setNetworkConfig({key: value}) - 修改配置");
    console.log("    例如: setNetworkConfig({printBody: false}) - 关闭请求体和响应体打印");
}); 