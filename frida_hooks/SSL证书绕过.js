/**
 * SSL证书绕过脚本
 * 
 * 功能：绕过Android应用的SSL证书验证
 * 作用：使应用接受任何SSL证书，方便抓包分析HTTPS流量
 * 适用：HTTPS抓包分析、安全测试
 */

// 等待Java虚拟机加载完成
Java.perform(function() {
    console.log("[*] SSL证书绕过脚本已启动");

    // 全局配置
    var config = {
        // 是否显示详细日志
        verbose: true,
        // 是否打印调用堆栈
        printStack: true,
        // 是否打印证书信息
        printCert: true
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
     * 一、绕过X509TrustManager
     */
    try {
        var TrustManager = Java.use('javax.net.ssl.X509TrustManager');
        var SSLContext = Java.use('javax.net.ssl.SSLContext');
        
        // 创建一个空的TrustManager
        var TrustManagerImpl = Java.registerClass({
            name: 'com.frida.TrustManager',
            implements: [TrustManager],
            methods: {
                checkClientTrusted: function(chain, authType) {
                    if (config.verbose) {
                        console.log('[+] 拦截 checkClientTrusted: ' + authType);
                        
                        if (config.printCert && chain && chain.length > 0) {
                            try {
                                var cert = chain[0];
                                console.log("    证书信息: " + cert.getSubjectDN());
                                console.log("    发行者: " + cert.getIssuerDN());
                                console.log("    序列号: " + cert.getSerialNumber());
                                console.log("    有效期: " + cert.getNotBefore() + " - " + cert.getNotAfter());
                            } catch (e) {
                                console.log("    无法获取证书信息: " + e);
                            }
                        }
                        
                        if (config.printStack) {
                            console.log("    调用堆栈:\n    " + getStackTrace());
                        }
                    }
                },
                checkServerTrusted: function(chain, authType) {
                    if (config.verbose) {
                        console.log('[+] 拦截 checkServerTrusted: ' + authType);
                        
                        if (config.printCert && chain && chain.length > 0) {
                            try {
                                var cert = chain[0];
                                console.log("    证书信息: " + cert.getSubjectDN());
                                console.log("    发行者: " + cert.getIssuerDN());
                                console.log("    序列号: " + cert.getSerialNumber());
                                console.log("    有效期: " + cert.getNotBefore() + " - " + cert.getNotAfter());
                            } catch (e) {
                                console.log("    无法获取证书信息: " + e);
                            }
                        }
                        
                        if (config.printStack) {
                            console.log("    调用堆栈:\n    " + getStackTrace());
                        }
                    }
                },
                getAcceptedIssuers: function() {
                    if (config.verbose) {
                        console.log('[+] 拦截 getAcceptedIssuers');
                    }
                    return [];
                }
            }
        });
        
        // 创建空的TrustManager数组
        var TrustManagers = [TrustManagerImpl.$new()];
        
        // 替换默认的SSLContext
        var SSLContextInit = SSLContext.init.overload(
            '[Ljavax.net.ssl.KeyManager;', 
            '[Ljavax.net.ssl.TrustManager;', 
            'java.security.SecureRandom'
        );
        
        SSLContextInit.implementation = function(keyManager, trustManager, secureRandom) {
            if (config.verbose) {
                console.log('[+] 拦截 SSLContext.init()');
                
                if (config.printStack) {
                    console.log("    调用堆栈:\n    " + getStackTrace());
                }
            }
            
            SSLContextInit.call(this, keyManager, TrustManagers, secureRandom);
        };
        
        console.log("[+] X509TrustManager绕过设置完成");
    } catch (e) {
        console.log("[-] X509TrustManager绕过设置失败: " + e);
    }

    /**
     * 二、绕过OkHttp证书验证
     */
    try {
        var CertificatePinner = Java.use('okhttp3.CertificatePinner');
        
        if (CertificatePinner) {
            // 绕过证书固定
            CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function(hostname, peerCertificates) {
                if (config.verbose) {
                    console.log('[+] 拦截 OkHttp CertificatePinner.check()');
                    console.log('    主机名: ' + hostname);
                    
                    if (config.printStack) {
                        console.log("    调用堆栈:\n    " + getStackTrace());
                    }
                }
                
                // 不执行检查
                return;
            };
            
            // 绕过证书固定 (旧版本OkHttp)
            CertificatePinner.check.overload('java.lang.String', '[Ljava.security.cert.Certificate;').implementation = function(hostname, peerCertificates) {
                if (config.verbose) {
                    console.log('[+] 拦截 OkHttp CertificatePinner.check() (旧版本)');
                    console.log('    主机名: ' + hostname);
                    
                    if (config.printStack) {
                        console.log("    调用堆栈:\n    " + getStackTrace());
                    }
                }
                
                // 不执行检查
                return;
            };
            
            console.log("[+] OkHttp证书固定绕过设置完成");
        }
    } catch (e) {
        console.log("[-] OkHttp证书固定绕过设置失败: " + e);
    }

    /**
     * 三、绕过WebView证书验证
     */
    try {
        var WebViewClient = Java.use('android.webkit.WebViewClient');
        
        // 绕过WebView证书验证
        WebViewClient.onReceivedSslError.overload('android.webkit.WebView', 'android.webkit.SslErrorHandler', 'android.net.http.SslError').implementation = function(webView, handler, error) {
            if (config.verbose) {
                console.log('[+] 拦截 WebViewClient.onReceivedSslError()');
                console.log('    URL: ' + webView.getUrl());
                console.log('    错误: ' + error.toString());
                
                if (config.printStack) {
                    console.log("    调用堆栈:\n    " + getStackTrace());
                }
            }
            
            // 继续加载
            handler.proceed();
        };
        
        console.log("[+] WebView证书验证绕过设置完成");
    } catch (e) {
        console.log("[-] WebView证书验证绕过设置失败: " + e);
    }

    /**
     * 四、绕过Conscrypt证书验证
     */
    try {
        var Conscrypt = Java.use('com.android.org.conscrypt.TrustManagerImpl');
        
        if (Conscrypt) {
            // 绕过证书验证
            Conscrypt.verifyChain.implementation = function(untrustedChain, trustAnchorChain, host, clientAuth, ocspData, tlsSctData) {
                if (config.verbose) {
                    console.log('[+] 拦截 Conscrypt.verifyChain()');
                    console.log('    主机名: ' + host);
                    
                    if (config.printCert && untrustedChain && untrustedChain.length > 0) {
                        try {
                            var cert = untrustedChain[0];
                            console.log("    证书信息: " + cert.getSubjectDN());
                            console.log("    发行者: " + cert.getIssuerDN());
                        } catch (e) {
                            console.log("    无法获取证书信息: " + e);
                        }
                    }
                    
                    if (config.printStack) {
                        console.log("    调用堆栈:\n    " + getStackTrace());
                    }
                }
                
                // 直接返回传入的证书链
                return untrustedChain;
            };
            
            console.log("[+] Conscrypt证书验证绕过设置完成");
        }
    } catch (e) {
        console.log("[-] Conscrypt证书验证绕过设置失败: " + e);
    }

    /**
     * 五、绕过Apache HTTP客户端证书验证
     */
    try {
        var ApacheHTTPClient = Java.use('org.apache.http.conn.ssl.SSLSocketFactory');
        
        if (ApacheHTTPClient) {
            ApacheHTTPClient.isSecure.implementation = function(socket) {
                if (config.verbose) {
                    console.log('[+] 拦截 Apache HTTP Client SSLSocketFactory.isSecure()');
                    
                    if (config.printStack) {
                        console.log("    调用堆栈:\n    " + getStackTrace());
                    }
                }
                
                // 总是返回true
                return true;
            };
            
            console.log("[+] Apache HTTP客户端证书验证绕过设置完成");
        }
    } catch (e) {
        console.log("[-] Apache HTTP客户端证书验证绕过设置失败: " + e);
    }

    /**
     * 六、绕过主机名验证
     */
    try {
        var HostnameVerifier = Java.use('javax.net.ssl.HostnameVerifier');
        var AllowAllHostnameVerifier = Java.registerClass({
            name: 'com.frida.AllowAllHostnameVerifier',
            implements: [HostnameVerifier],
            methods: {
                verify: function(hostname, session) {
                    if (config.verbose) {
                        console.log('[+] 拦截 HostnameVerifier.verify()');
                        console.log('    主机名: ' + hostname);
                        
                        if (config.printStack) {
                            console.log("    调用堆栈:\n    " + getStackTrace());
                        }
                    }
                    
                    // 总是返回true
                    return true;
                }
            }
        });
        
        // 替换默认的HostnameVerifier
        var HttpsURLConnection = Java.use('javax.net.ssl.HttpsURLConnection');
        HttpsURLConnection.setDefaultHostnameVerifier.implementation = function(hostnameVerifier) {
            if (config.verbose) {
                console.log('[+] 拦截 HttpsURLConnection.setDefaultHostnameVerifier()');
                
                if (config.printStack) {
                    console.log("    调用堆栈:\n    " + getStackTrace());
                }
            }
            
            // 使用我们自己的HostnameVerifier
            this.setDefaultHostnameVerifier(AllowAllHostnameVerifier.$new());
        };
        
        // 替换实例的HostnameVerifier
        HttpsURLConnection.setHostnameVerifier.implementation = function(hostnameVerifier) {
            if (config.verbose) {
                console.log('[+] 拦截 HttpsURLConnection.setHostnameVerifier()');
                
                if (config.printStack) {
                    console.log("    调用堆栈:\n    " + getStackTrace());
                }
            }
            
            // 使用我们自己的HostnameVerifier
            this.setHostnameVerifier(AllowAllHostnameVerifier.$new());
        };
        
        console.log("[+] 主机名验证绕过设置完成");
    } catch (e) {
        console.log("[-] 主机名验证绕过设置失败: " + e);
    }

    /**
     * 七、绕过Volley证书验证
     */
    try {
        var HurlStack = Java.use('com.android.volley.toolbox.HurlStack');
        
        if (HurlStack) {
            HurlStack.$init.overload('com.android.volley.toolbox.HurlStack$UrlRewriter', 'javax.net.ssl.SSLSocketFactory').implementation = function(urlRewriter, sslSocketFactory) {
                if (config.verbose) {
                    console.log('[+] 拦截 Volley HurlStack构造函数');
                    
                    if (config.printStack) {
                        console.log("    调用堆栈:\n    " + getStackTrace());
                    }
                }
                
                // 使用null作为SSLSocketFactory，这将使用默认的，我们已经修改过的SSLSocketFactory
                return this.$init(urlRewriter, null);
            };
            
            console.log("[+] Volley证书验证绕过设置完成");
        }
    } catch (e) {
        console.log("[-] Volley证书验证绕过设置失败: " + e);
    }

    /**
     * 八、绕过自定义证书固定实现
     * 这些是一些常见的自定义证书固定检查方法
     */
    try {
        // 常见的证书哈希比较方法
        var MessageDigest = Java.use('java.security.MessageDigest');
        MessageDigest.isEqual.implementation = function(digestA, digestB) {
            if (config.verbose) {
                console.log('[+] 拦截 MessageDigest.isEqual()');
                
                if (config.printStack) {
                    console.log("    调用堆栈:\n    " + getStackTrace());
                }
            }
            
            // 如果是证书哈希比较，总是返回true
            var stack = getStackTrace();
            if (stack.indexOf("Certificate") !== -1 || stack.indexOf("X509") !== -1) {
                console.log("    [!] 可能是证书哈希比较，返回true");
                return true;
            }
            
            // 否则使用原始实现
            return this.isEqual(digestA, digestB);
        };
        
        console.log("[+] 自定义证书固定检查绕过设置完成");
    } catch (e) {
        console.log("[-] 自定义证书固定检查绕过设置失败: " + e);
    }

    /**
     * 修改配置的函数
     */
    global.setSSLConfig = function(newConfig) {
        for (var key in newConfig) {
            if (config.hasOwnProperty(key)) {
                config[key] = newConfig[key];
                console.log("[+] SSL配置已更新: " + key + " = " + newConfig[key]);
            }
        }
    };

    console.log("[*] SSL证书绕过脚本已加载");
    console.log("[*] 使用方法:");
    console.log("    setSSLConfig({key: value}) - 修改配置");
    console.log("    例如: setSSLConfig({verbose: false}) - 关闭详细日志");
}); 