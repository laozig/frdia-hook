/**
 * 应用保护机制绕过脚本
 * 
 * 功能：绕过Android应用中的各种保护机制
 * 作用：突破应用的安全限制，方便分析和测试
 * 适用：安全研究、漏洞挖掘、功能测试
 */

// 等待Java虚拟机加载完成
Java.perform(function() {
    console.log("[*] 应用保护机制绕过脚本已启动");

    // 全局配置
    var config = {
        // 是否显示详细日志
        verbose: true,
        // 是否打印调用堆栈
        printStack: true,
        // 是否绕过签名验证
        bypassSignature: true,
        // 是否绕过界面限制
        bypassUIRestrictions: true,
        // 是否绕过权限检查
        bypassPermissionChecks: true,
        // 是否绕过加密检查
        bypassEncryptionChecks: true,
        // 是否绕过证书固定
        bypassCertificatePinning: true
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
     * 一、绕过签名验证
     * 许多应用会验证自身的签名，以防止被修改或重新打包
     */
    if (config.bypassSignature) {
        try {
            // 绕过PackageManager的签名验证
            var PackageManager = Java.use("android.content.pm.PackageManager");
            var Signature = Java.use("android.content.pm.Signature");
            
            // 拦截getPackageInfo方法
            PackageManager.getPackageInfo.overload('java.lang.String', 'int').implementation = function(packageName, flags) {
                var packageInfo = this.getPackageInfo(packageName, flags);
                
                // 如果请求的是签名信息
                if ((flags & 0x40) !== 0) { // PackageManager.GET_SIGNATURES
                    if (config.verbose) {
                        console.log("[+] 拦截 PackageManager.getPackageInfo 获取签名");
                        console.log("    包名: " + packageName);
                        
                        if (config.printStack) {
                            console.log("    调用堆栈:\n    " + getStackTrace());
                        }
                    }
                    
                    // 如果是检查自己的签名
                    var currentPackage = Java.use("android.app.ActivityThread").currentApplication().getApplicationContext().getPackageName();
                    if (packageName === currentPackage) {
                        console.log("    [!] 应用正在验证自己的签名，返回原始签名");
                    }
                }
                
                return packageInfo;
            };
            
            // 拦截Signature.equals方法
            Signature.equals.implementation = function(obj) {
                if (config.verbose) {
                    console.log("[+] 拦截 Signature.equals");
                    
                    if (config.printStack) {
                        console.log("    调用堆栈:\n    " + getStackTrace());
                    }
                }
                
                // 如果是签名比较，总是返回true
                return true;
            };
            
            // 拦截Signature.hashCode方法
            Signature.hashCode.implementation = function() {
                if (config.verbose) {
                    console.log("[+] 拦截 Signature.hashCode");
                    
                    if (config.printStack) {
                        console.log("    调用堆栈:\n    " + getStackTrace());
                    }
                }
                
                // 返回一个固定的哈希值
                return 0;
            };
            
            console.log("[+] 签名验证绕过设置完成");
        } catch (e) {
            console.log("[-] 签名验证绕过设置失败: " + e);
        }
    }

    /**
     * 二、绕过界面限制
     * 许多应用会限制某些UI操作，如禁用按钮、隐藏视图等
     */
    if (config.bypassUIRestrictions) {
        try {
            // 绕过View的setEnabled方法
            var View = Java.use("android.view.View");
            View.setEnabled.implementation = function(enabled) {
                if (!enabled) {
                    if (config.verbose) {
                        console.log("[+] 拦截 View.setEnabled(false)");
                        console.log("    视图ID: " + this.getId());
                        
                        if (config.printStack) {
                            console.log("    调用堆栈:\n    " + getStackTrace());
                        }
                    }
                    
                    // 总是启用视图
                    return this.setEnabled(true);
                }
                
                return this.setEnabled(enabled);
            };
            
            // 绕过View的setVisibility方法
            View.setVisibility.implementation = function(visibility) {
                if (visibility === 8 || visibility === 4) { // GONE or INVISIBLE
                    if (config.verbose) {
                        console.log("[+] 拦截 View.setVisibility(" + visibility + ")");
                        console.log("    视图ID: " + this.getId());
                        
                        if (config.printStack) {
                            console.log("    调用堆栈:\n    " + getStackTrace());
                        }
                    }
                    
                    // 可以选择性地使视图可见
                    // return this.setVisibility(0); // VISIBLE
                }
                
                return this.setVisibility(visibility);
            };
            
            // 绕过Button的setClickable方法
            var Button = Java.use("android.widget.Button");
            Button.setClickable.implementation = function(clickable) {
                if (!clickable) {
                    if (config.verbose) {
                        console.log("[+] 拦截 Button.setClickable(false)");
                        console.log("    按钮文本: " + this.getText());
                        
                        if (config.printStack) {
                            console.log("    调用堆栈:\n    " + getStackTrace());
                        }
                    }
                    
                    // 总是使按钮可点击
                    return this.setClickable(true);
                }
                
                return this.setClickable(clickable);
            };
            
            // 绕过EditText的setEnabled方法
            var EditText = Java.use("android.widget.EditText");
            EditText.setEnabled.implementation = function(enabled) {
                if (!enabled) {
                    if (config.verbose) {
                        console.log("[+] 拦截 EditText.setEnabled(false)");
                        console.log("    文本框内容: " + this.getText());
                        
                        if (config.printStack) {
                            console.log("    调用堆栈:\n    " + getStackTrace());
                        }
                    }
                    
                    // 总是启用文本框
                    return this.setEnabled(true);
                }
                
                return this.setEnabled(enabled);
            };
            
            console.log("[+] 界面限制绕过设置完成");
        } catch (e) {
            console.log("[-] 界面限制绕过设置失败: " + e);
        }
    }

    /**
     * 三、绕过权限检查
     * 许多应用会检查权限状态，拒绝某些功能
     */
    if (config.bypassPermissionChecks) {
        try {
            // 绕过ContextCompat.checkSelfPermission方法
            var ContextCompat = Java.use("androidx.core.content.ContextCompat");
            if (ContextCompat) {
                ContextCompat.checkSelfPermission.implementation = function(context, permission) {
                    if (config.verbose) {
                        console.log("[+] 拦截 ContextCompat.checkSelfPermission");
                        console.log("    权限: " + permission);
                        
                        if (config.printStack) {
                            console.log("    调用堆栈:\n    " + getStackTrace());
                        }
                    }
                    
                    // 总是返回已授权 (PackageManager.PERMISSION_GRANTED = 0)
                    return 0;
                };
            }
            
            // 绕过Context.checkSelfPermission方法
            var Context = Java.use("android.content.Context");
            Context.checkSelfPermission.implementation = function(permission) {
                if (config.verbose) {
                    console.log("[+] 拦截 Context.checkSelfPermission");
                    console.log("    权限: " + permission);
                    
                    if (config.printStack) {
                        console.log("    调用堆栈:\n    " + getStackTrace());
                    }
                }
                
                // 总是返回已授权 (PackageManager.PERMISSION_GRANTED = 0)
                return 0;
            };
            
            // 绕过ActivityCompat.requestPermissions方法
            try {
                var ActivityCompat = Java.use("androidx.core.app.ActivityCompat");
                ActivityCompat.requestPermissions.overload('android.app.Activity', '[Ljava.lang.String;', 'int').implementation = function(activity, permissions, requestCode) {
                    if (config.verbose) {
                        console.log("[+] 拦截 ActivityCompat.requestPermissions");
                        console.log("    权限: " + permissions);
                        console.log("    请求码: " + requestCode);
                        
                        if (config.printStack) {
                            console.log("    调用堆栈:\n    " + getStackTrace());
                        }
                    }
                    
                    // 不请求权限，直接模拟权限已授权的回调
                    try {
                        var grantResults = Java.array('int', permissions.length);
                        for (var i = 0; i < grantResults.length; i++) {
                            grantResults[i] = 0; // PERMISSION_GRANTED
                        }
                        
                        // 调用onRequestPermissionsResult方法
                        activity.onRequestPermissionsResult(requestCode, permissions, grantResults);
                    } catch (e) {
                        console.log("    [-] 模拟权限回调失败: " + e);
                    }
                };
            } catch (e) {
                console.log("    [-] ActivityCompat类不可用: " + e);
            }
            
            console.log("[+] 权限检查绕过设置完成");
        } catch (e) {
            console.log("[-] 权限检查绕过设置失败: " + e);
        }
    }

    /**
     * 四、绕过加密检查
     * 许多应用会使用加密来保护数据或验证完整性
     */
    if (config.bypassEncryptionChecks) {
        try {
            // 绕过常见的加密验证方法
            var MessageDigest = Java.use("java.security.MessageDigest");
            MessageDigest.isEqual.implementation = function(digestA, digestB) {
                if (config.verbose) {
                    console.log("[+] 拦截 MessageDigest.isEqual");
                    
                    if (config.printStack) {
                        console.log("    调用堆栈:\n    " + getStackTrace());
                    }
                }
                
                // 检查堆栈，如果是验证相关的调用，则返回true
                var stack = getStackTrace();
                if (stack.indexOf("verify") !== -1 || 
                    stack.indexOf("check") !== -1 || 
                    stack.indexOf("validate") !== -1) {
                    console.log("    [!] 检测到可能的验证操作，返回true");
                    return true;
                }
                
                // 否则使用原始实现
                return this.isEqual(digestA, digestB);
            };
            
            // 绕过常见的哈希比较
            var Arrays = Java.use("java.util.Arrays");
            Arrays.equals.overload('[B', '[B').implementation = function(a, b) {
                if (config.verbose) {
                    console.log("[+] 拦截 Arrays.equals (字节数组)");
                    
                    if (config.printStack) {
                        console.log("    调用堆栈:\n    " + getStackTrace());
                    }
                }
                
                // 检查堆栈，如果是验证相关的调用，则返回true
                var stack = getStackTrace();
                if (stack.indexOf("verify") !== -1 || 
                    stack.indexOf("check") !== -1 || 
                    stack.indexOf("validate") !== -1) {
                    console.log("    [!] 检测到可能的验证操作，返回true");
                    return true;
                }
                
                // 否则使用原始实现
                return this.equals(a, b);
            };
            
            console.log("[+] 加密检查绕过设置完成");
        } catch (e) {
            console.log("[-] 加密检查绕过设置失败: " + e);
        }
    }

    /**
     * 五、绕过证书固定
     * 许多应用使用证书固定来防止中间人攻击
     */
    if (config.bypassCertificatePinning) {
        try {
            // 绕过OkHttp证书固定
            try {
                var CertificatePinner = Java.use("okhttp3.CertificatePinner");
                
                if (CertificatePinner) {
                    CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function(hostname, peerCertificates) {
                        if (config.verbose) {
                            console.log("[+] 拦截 OkHttp CertificatePinner.check");
                            console.log("    主机名: " + hostname);
                            
                            if (config.printStack) {
                                console.log("    调用堆栈:\n    " + getStackTrace());
                            }
                        }
                        
                        // 不执行检查
                        return;
                    };
                    
                    CertificatePinner.check.overload('java.lang.String', '[Ljava.security.cert.Certificate;').implementation = function(hostname, peerCertificates) {
                        if (config.verbose) {
                            console.log("[+] 拦截 OkHttp CertificatePinner.check (旧版本)");
                            console.log("    主机名: " + hostname);
                            
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
            
            // 绕过TrustManagerImpl验证
            try {
                var TrustManagerImpl = Java.use("com.android.org.conscrypt.TrustManagerImpl");
                
                if (TrustManagerImpl) {
                    TrustManagerImpl.verifyChain.implementation = function(untrustedChain, trustAnchorChain, host, clientAuth, ocspData, tlsSctData) {
                        if (config.verbose) {
                            console.log("[+] 拦截 TrustManagerImpl.verifyChain");
                            console.log("    主机名: " + host);
                            
                            if (config.printStack) {
                                console.log("    调用堆栈:\n    " + getStackTrace());
                            }
                        }
                        
                        // 直接返回传入的证书链
                        return untrustedChain;
                    };
                    
                    console.log("[+] TrustManagerImpl证书验证绕过设置完成");
                }
            } catch (e) {
                console.log("[-] TrustManagerImpl证书验证绕过设置失败: " + e);
            }
            
            // 绕过X509TrustManager
            try {
                var X509TrustManager = Java.use("javax.net.ssl.X509TrustManager");
                var SSLContext = Java.use("javax.net.ssl.SSLContext");
                
                // 创建一个空的TrustManager
                var TrustManagerImpl = Java.registerClass({
                    name: "com.frida.TrustManager",
                    implements: [X509TrustManager],
                    methods: {
                        checkClientTrusted: function(chain, authType) {
                            if (config.verbose) {
                                console.log("[+] 拦截 X509TrustManager.checkClientTrusted");
                                
                                if (config.printStack) {
                                    console.log("    调用堆栈:\n    " + getStackTrace());
                                }
                            }
                        },
                        checkServerTrusted: function(chain, authType) {
                            if (config.verbose) {
                                console.log("[+] 拦截 X509TrustManager.checkServerTrusted");
                                
                                if (config.printStack) {
                                    console.log("    调用堆栈:\n    " + getStackTrace());
                                }
                            }
                        },
                        getAcceptedIssuers: function() {
                            return [];
                        }
                    }
                });
                
                // 创建空的TrustManager数组
                var TrustManagers = [TrustManagerImpl.$new()];
                
                // 拦截SSLContext.init方法
                SSLContext.init.implementation = function(keyManager, trustManager, secureRandom) {
                    if (config.verbose) {
                        console.log("[+] 拦截 SSLContext.init");
                        
                        if (config.printStack) {
                            console.log("    调用堆栈:\n    " + getStackTrace());
                        }
                    }
                    
                    // 使用我们的TrustManager
                    this.init(keyManager, TrustManagers, secureRandom);
                };
                
                console.log("[+] X509TrustManager绕过设置完成");
            } catch (e) {
                console.log("[-] X509TrustManager绕过设置失败: " + e);
            }
        } catch (e) {
            console.log("[-] 证书固定绕过设置失败: " + e);
        }
    }

    /**
     * 六、绕过应用完整性检查
     * 许多应用会检查自身的完整性，以防止被修改
     */
    try {
        // 绕过常见的文件完整性检查
        var File = Java.use("java.io.File");
        var FileInputStream = Java.use("java.io.FileInputStream");
        
        // 拦截文件读取操作
        FileInputStream.read.overload('[B').implementation = function(buffer) {
            var result = this.read(buffer);
            
            try {
                var fileName = this.getFD().toString();
                
                // 检查是否在读取APK文件或DEX文件
                if (fileName.indexOf(".apk") !== -1 || fileName.indexOf(".dex") !== -1) {
                    if (config.verbose) {
                        console.log("[+] 拦截对APK/DEX文件的读取: " + fileName);
                        
                        if (config.printStack) {
                            console.log("    调用堆栈:\n    " + getStackTrace());
                        }
                    }
                }
            } catch (e) {
                // 忽略错误
            }
            
            return result;
        };
        
        console.log("[+] 应用完整性检查绕过设置完成");
    } catch (e) {
        console.log("[-] 应用完整性检查绕过设置失败: " + e);
    }

    /**
     * 七、绕过界面劫持检测
     * 一些应用会检测是否有其他窗口覆盖在其上面
     */
    try {
        var WindowManager = Java.use("android.view.WindowManager");
        var LayoutParams = Java.use("android.view.WindowManager$LayoutParams");
        
        // 拦截addView方法
        WindowManager.addView.implementation = function(view, params) {
            if (params.type >= 2000 && params.type <= 2999) { // TYPE_APPLICATION_OVERLAY
                if (config.verbose) {
                    console.log("[+] 拦截添加悬浮窗口");
                    console.log("    窗口类型: " + params.type);
                    
                    if (config.printStack) {
                        console.log("    调用堆栈:\n    " + getStackTrace());
                    }
                }
            }
            
            return this.addView(view, params);
        };
        
        console.log("[+] 界面劫持检测绕过设置完成");
    } catch (e) {
        console.log("[-] 界面劫持检测绕过设置失败: " + e);
    }

    /**
     * 八、绕过截屏限制
     * 许多应用会禁止截屏
     */
    try {
        var Activity = Java.use("android.app.Activity");
        
        // 拦截setFlags方法
        Activity.setFlags.implementation = function(flags) {
            // 移除FLAG_SECURE标志 (0x00002000)
            if ((flags & 0x00002000) !== 0) {
                if (config.verbose) {
                    console.log("[+] 拦截设置FLAG_SECURE标志");
                    
                    if (config.printStack) {
                        console.log("    调用堆栈:\n    " + getStackTrace());
                    }
                }
                
                // 移除FLAG_SECURE标志
                flags &= ~0x00002000;
            }
            
            return this.setFlags(flags);
        };
        
        // 拦截getWindow().setFlags方法
        var Window = Java.use("android.view.Window");
        Window.setFlags.implementation = function(flags, mask) {
            // 如果尝试设置FLAG_SECURE标志
            if ((flags & 0x00002000) !== 0) {
                if (config.verbose) {
                    console.log("[+] 拦截Window.setFlags设置FLAG_SECURE标志");
                    
                    if (config.printStack) {
                        console.log("    调用堆栈:\n    " + getStackTrace());
                    }
                }
                
                // 移除FLAG_SECURE标志
                flags &= ~0x00002000;
            }
            
            return this.setFlags(flags, mask);
        };
        
        console.log("[+] 截屏限制绕过设置完成");
    } catch (e) {
        console.log("[-] 截屏限制绕过设置失败: " + e);
    }

    /**
     * 修改配置的函数
     */
    global.setProtectionConfig = function(newConfig) {
        for (var key in newConfig) {
            if (config.hasOwnProperty(key)) {
                config[key] = newConfig[key];
                console.log("[+] 保护配置已更新: " + key + " = " + newConfig[key]);
            }
        }
    };

    console.log("[*] 应用保护机制绕过脚本已加载");
    console.log("[*] 使用方法:");
    console.log("    setProtectionConfig({key: value}) - 修改配置");
    console.log("    例如: setProtectionConfig({bypassSignature: false}) - 关闭签名验证绕过");
}); 