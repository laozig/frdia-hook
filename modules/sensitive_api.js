/*
 * 脚本名称：sensitive_api.js
 * 功能描述：监控Android应用对敏感API的调用，追踪隐私数据访问和敏感操作
 * 
 * 适用场景：
 *   - 隐私合规测试：检查应用对用户隐私数据的访问情况
 *   - 安全审计：识别敏感API调用的上下文和频率
 *   - 行为分析：了解应用如何处理敏感信息
 *   - 权限使用监控：验证应用是否滥用权限
 *   - 调试敏感功能：如文件访问、定位服务等
 *   - 监控数据存储：如SharedPreferences、文件读写等
 *   - 设备信息获取：监控应用获取设备标识符等操作
 *
 * 使用方法：
 *   1. 可通过frida_master.js主入口文件加载(推荐)
 *   2. 也可单独使用: frida -U -f 目标应用包名 -l sensitive_api.js --no-pause
 *   3. 或者 frida -U --attach-pid 目标进程PID -l sensitive_api.js
 *
 * 启动方式说明：
 *   - -U: 使用USB连接的设备
 *   - -f: 指定以spawn方式启动的应用包名
 *   - --attach-pid: 附加到已运行的进程
 *   - --no-pause: 注入后不暂停应用执行
 *
 * 工作原理：
 *   本脚本监控多个敏感API类别：
 *
 *   1. 文件操作监控：
 *      - 拦截FileInputStream/FileOutputStream操作
 *      - 监控File对象的创建、删除等操作
 *      - 记录访问的文件路径和内容
 *
 *   2. SharedPreferences监控：
 *      - 跟踪键值存储的读写操作
 *      - 记录存储的键名和值
 *
 *   3. 剪贴板监控：
 *      - 监控数据复制和粘贴操作
 *      - 记录剪贴板内容
 *
 *   4. 位置服务监控：
 *      - 跟踪位置信息获取
 *      - 监控位置更新请求
 *
 *   5. 相机和麦克风监控：
 *      - 检测相机开启和预览
 *      - 监控录音操作
 *
 *   6. 内容提供者监控：
 *      - 追踪对联系人、通话记录等内容提供者的查询
 *      - 记录查询参数和结果
 *
 *   7. 设备信息监控：
 *      - 监控设备ID、IMEI、手机号等敏感信息的获取
 *      - 记录设备标识符请求
 *
 * 注意事项：
 *   - 所有API调用会记录调用方法、参数和返回值
 *   - 可获取调用栈以分析API调用上下文
 *   - 对敏感API的监控不会改变应用行为，只记录调用信息
 *   - 推荐与其他监控模块结合使用以获得更全面的应用行为视图
 */

module.exports = function(config, logger, utils) {
    var tag = "SENSITIVE";
    logger.info(tag, "敏感API监控模块初始化");
    
    // 存储敏感API调用记录
    var apiCalls = {
        count: 0,
        calls: {},
        addCall: function(type, method, params, returnValue) {
            this.count++;
            var id = "call_" + this.count;
            
            this.calls[id] = {
                type: type,
                method: method,
                params: params,
                returnValue: returnValue,
                timestamp: new Date(),
                stackTrace: utils.getStackTrace()
            };
            
            logger.info(tag, "检测到敏感API调用: " + type + "." + method);
            logger.debug(tag, "参数: " + JSON.stringify(params));
            if (returnValue !== undefined) {
                logger.debug(tag, "返回值: " + returnValue);
            }
        }
    };
    
    // 开始Hook敏感API
    Java.perform(function() {
        // 1. 文件操作
        hookFileOperations();
        
        // 2. SharedPreferences
        hookSharedPreferences();
        
        // 3. 剪贴板
        hookClipboard();
        
        // 4. 位置服务
        hookLocation();
        
        // 5. 相机/麦克风
        hookCameraAndMicrophone();
        
        // 6. ContentProvider
        hookContentProviders();
        
        // 7. 设备信息
        hookDeviceInfo();
    });
    
    // Hook文件操作
    function hookFileOperations() {
        try {
            // 文件读写操作
            var FileInputStream = Java.use("java.io.FileInputStream");
            var FileOutputStream = Java.use("java.io.FileOutputStream");
            var File = Java.use("java.io.File");
            
            // FileInputStream构造函数
            FileInputStream.$init.overload('java.io.File').implementation = function(file) {
                var filePath = file.getAbsolutePath();
                apiCalls.addCall("文件读取", "FileInputStream", { path: filePath }, undefined);
                return this.$init(file);
            };
            
            FileInputStream.$init.overload('java.lang.String').implementation = function(path) {
                apiCalls.addCall("文件读取", "FileInputStream", { path: path }, undefined);
                return this.$init(path);
            };
            
            // FileOutputStream构造函数
            FileOutputStream.$init.overload('java.io.File').implementation = function(file) {
                var filePath = file.getAbsolutePath();
                apiCalls.addCall("文件写入", "FileOutputStream", { path: filePath }, undefined);
                return this.$init(file);
            };
            
            FileOutputStream.$init.overload('java.lang.String').implementation = function(path) {
                apiCalls.addCall("文件写入", "FileOutputStream", { path: path }, undefined);
                return this.$init(path);
            };
            
            // File操作
            File.delete.implementation = function() {
                var filePath = this.getAbsolutePath();
                var result = this.delete();
                apiCalls.addCall("文件删除", "File.delete", { path: filePath }, result);
                return result;
            };
            
            logger.info(tag, "文件操作监控已设置");
        } catch (e) {
            logger.error(tag, "Hook文件操作失败: " + e);
        }
    }
    
    // Hook SharedPreferences
    function hookSharedPreferences() {
        try {
            var SharedPreferencesEditor = Java.use("android.content.SharedPreferences$Editor");
            
            // 监控put操作
            SharedPreferencesEditor.putString.implementation = function(key, value) {
                apiCalls.addCall("SharedPreferences", "putString", { key: key, value: value }, undefined);
                return this.putString(key, value);
            };
            
            SharedPreferencesEditor.putInt.implementation = function(key, value) {
                apiCalls.addCall("SharedPreferences", "putInt", { key: key, value: value }, undefined);
                return this.putInt(key, value);
            };
            
            SharedPreferencesEditor.putBoolean.implementation = function(key, value) {
                apiCalls.addCall("SharedPreferences", "putBoolean", { key: key, value: value }, undefined);
                return this.putBoolean(key, value);
            };
            
            SharedPreferencesEditor.remove.implementation = function(key) {
                apiCalls.addCall("SharedPreferences", "remove", { key: key }, undefined);
                return this.remove(key);
            };
            
            // 监控读取操作
            var SharedPreferences = Java.use("android.content.SharedPreferences");
            
            SharedPreferences.getString.implementation = function(key, defValue) {
                var value = this.getString(key, defValue);
                apiCalls.addCall("SharedPreferences", "getString", { key: key, defaultValue: defValue }, value);
                return value;
            };
            
            SharedPreferences.getInt.implementation = function(key, defValue) {
                var value = this.getInt(key, defValue);
                apiCalls.addCall("SharedPreferences", "getInt", { key: key, defaultValue: defValue }, value);
                return value;
            };
            
            SharedPreferences.getBoolean.implementation = function(key, defValue) {
                var value = this.getBoolean(key, defValue);
                apiCalls.addCall("SharedPreferences", "getBoolean", { key: key, defaultValue: defValue }, value);
                return value;
            };
            
            logger.info(tag, "SharedPreferences监控已设置");
        } catch (e) {
            logger.error(tag, "Hook SharedPreferences失败: " + e);
        }
    }
    
    // Hook剪贴板
    function hookClipboard() {
        try {
            var ClipboardManager = Java.use("android.content.ClipboardManager");
            
            // 监控setText操作
            ClipboardManager.setPrimaryClip.implementation = function(clip) {
                var clipText = "";
                try {
                    clipText = clip.getItemAt(0).getText().toString();
                } catch (e) {
                    clipText = "<无法获取剪贴板内容>";
                }
                
                apiCalls.addCall("剪贴板", "setPrimaryClip", { text: clipText }, undefined);
                return this.setPrimaryClip(clip);
            };
            
            // 监控getText操作
            ClipboardManager.getPrimaryClip.implementation = function() {
                var clip = this.getPrimaryClip();
                var clipText = "";
                
                try {
                    if (clip) {
                        clipText = clip.getItemAt(0).getText().toString();
                    }
                } catch (e) {
                    clipText = "<无法获取剪贴板内容>";
                }
                
                apiCalls.addCall("剪贴板", "getPrimaryClip", {}, clipText);
                return clip;
            };
            
            logger.info(tag, "剪贴板监控已设置");
        } catch (e) {
            logger.error(tag, "Hook剪贴板失败: " + e);
        }
    }
    
    // Hook位置服务
    function hookLocation() {
        try {
            var LocationManager = Java.use("android.location.LocationManager");
            
            // 监控获取位置
            LocationManager.getLastKnownLocation.implementation = function(provider) {
                var location = this.getLastKnownLocation(provider);
                
                var locationInfo = {};
                if (location) {
                    locationInfo = {
                        latitude: location.getLatitude(),
                        longitude: location.getLongitude(),
                        accuracy: location.getAccuracy()
                    };
                }
                
                apiCalls.addCall("位置", "getLastKnownLocation", { provider: provider }, locationInfo);
                return location;
            };
            
            // 监控位置监听器
            LocationManager.requestLocationUpdates.overload('java.lang.String', 'long', 'float', 'android.location.LocationListener').implementation = function(provider, minTime, minDistance, listener) {
                apiCalls.addCall("位置", "requestLocationUpdates", { 
                    provider: provider, 
                    minTime: minTime, 
                    minDistance: minDistance 
                }, undefined);
                
                return this.requestLocationUpdates(provider, minTime, minDistance, listener);
            };
            
            logger.info(tag, "位置服务监控已设置");
        } catch (e) {
            logger.error(tag, "Hook位置服务失败: " + e);
        }
    }
    
    // Hook相机和麦克风
    function hookCameraAndMicrophone() {
        try {
            // 相机
            var Camera = Java.use("android.hardware.Camera");
            if (Camera) {
                Camera.open.overload('int').implementation = function(id) {
                    apiCalls.addCall("相机", "Camera.open", { cameraId: id }, undefined);
                    return this.open(id);
                };
                
                Camera.startPreview.implementation = function() {
                    apiCalls.addCall("相机", "Camera.startPreview", {}, undefined);
                    return this.startPreview();
                };
                
                Camera.takePicture.implementation = function() {
                    apiCalls.addCall("相机", "Camera.takePicture", {}, undefined);
                    return this.takePicture.apply(this, arguments);
                };
            }
            
            // Camera2 API
            try {
                var CameraManager = Java.use("android.hardware.camera2.CameraManager");
                if (CameraManager) {
                    CameraManager.openCamera.implementation = function(cameraId, callback, handler) {
                        apiCalls.addCall("相机", "CameraManager.openCamera", { cameraId: cameraId }, undefined);
                        return this.openCamera(cameraId, callback, handler);
                    };
                }
            } catch (e) {
                logger.debug(tag, "Hook Camera2 API失败: " + e);
            }
            
            // 麦克风
            var MediaRecorder = Java.use("android.media.MediaRecorder");
            if (MediaRecorder) {
                MediaRecorder.start.implementation = function() {
                    apiCalls.addCall("麦克风", "MediaRecorder.start", {}, undefined);
                    return this.start();
                };
                
                MediaRecorder.stop.implementation = function() {
                    apiCalls.addCall("麦克风", "MediaRecorder.stop", {}, undefined);
                    return this.stop();
                };
            }
            
            // AudioRecord
            var AudioRecord = Java.use("android.media.AudioRecord");
            if (AudioRecord) {
                AudioRecord.startRecording.implementation = function() {
                    apiCalls.addCall("麦克风", "AudioRecord.startRecording", {}, undefined);
                    return this.startRecording();
                };
                
                AudioRecord.stop.implementation = function() {
                    apiCalls.addCall("麦克风", "AudioRecord.stop", {}, undefined);
                    return this.stop();
                };
            }
            
            logger.info(tag, "相机和麦克风监控已设置");
        } catch (e) {
            logger.error(tag, "Hook相机和麦克风失败: " + e);
        }
    }
    
    // Hook ContentProvider
    function hookContentProviders() {
        try {
            var ContentResolver = Java.use("android.content.ContentResolver");
            
            // 监控查询操作
            ContentResolver.query.overload('android.net.Uri', '[Ljava.lang.String;', 'java.lang.String', '[Ljava.lang.String;', 'java.lang.String').implementation = function(uri, projection, selection, selectionArgs, sortOrder) {
                var cursor = this.query(uri, projection, selection, selectionArgs, sortOrder);
                
                apiCalls.addCall("ContentProvider", "query", { 
                    uri: uri.toString(), 
                    selection: selection 
                }, cursor ? cursor.getCount() + " 条记录" : "0 条记录");
                
                return cursor;
            };
            
            // 监控插入操作
            ContentResolver.insert.implementation = function(uri, values) {
                var valuesMap = {};
                if (values) {
                    var keySet = values.keySet();
                    var keys = keySet.toArray();
                    for (var i = 0; i < keys.length; i++) {
                        var key = keys[i];
                        valuesMap[key] = values.get(key) ? values.get(key).toString() : null;
                    }
                }
                
                var result = this.insert(uri, values);
                apiCalls.addCall("ContentProvider", "insert", { 
                    uri: uri.toString(),
                    values: valuesMap
                }, result ? result.toString() : null);
                
                return result;
            };
            
            // 监控更新操作
            ContentResolver.update.implementation = function(uri, values, selection, selectionArgs) {
                var valuesMap = {};
                if (values) {
                    var keySet = values.keySet();
                    var keys = keySet.toArray();
                    for (var i = 0; i < keys.length; i++) {
                        var key = keys[i];
                        valuesMap[key] = values.get(key) ? values.get(key).toString() : null;
                    }
                }
                
                var count = this.update(uri, values, selection, selectionArgs);
                apiCalls.addCall("ContentProvider", "update", { 
                    uri: uri.toString(),
                    values: valuesMap,
                    selection: selection 
                }, count + " 条记录已更新");
                
                return count;
            };
            
            // 监控删除操作
            ContentResolver.delete.implementation = function(uri, selection, selectionArgs) {
                var count = this.delete(uri, selection, selectionArgs);
                apiCalls.addCall("ContentProvider", "delete", { 
                    uri: uri.toString(),
                    selection: selection 
                }, count + " 条记录已删除");
                
                return count;
            };
            
            logger.info(tag, "ContentProvider监控已设置");
        } catch (e) {
            logger.error(tag, "Hook ContentProvider失败: " + e);
        }
    }
    
    // Hook设备信息
    function hookDeviceInfo() {
        try {
            // IMEI
            var TelephonyManager = Java.use("android.telephony.TelephonyManager");
            
            // getDeviceId (IMEI)
            TelephonyManager.getDeviceId.overloads.forEach(function(overload) {
                overload.implementation = function() {
                    var imei = this.getDeviceId.apply(this, arguments);
                    apiCalls.addCall("设备信息", "getDeviceId", {}, imei);
                    return imei;
                };
            });
            
            // 更多敏感API...
            TelephonyManager.getSubscriberId.overloads.forEach(function(overload) {
                overload.implementation = function() {
                    var imsi = this.getSubscriberId.apply(this, arguments);
                    apiCalls.addCall("设备信息", "getSubscriberId", {}, imsi);
                    return imsi;
                };
            });
            
            TelephonyManager.getLine1Number.overloads.forEach(function(overload) {
                overload.implementation = function() {
                    var phoneNumber = this.getLine1Number.apply(this, arguments);
                    apiCalls.addCall("设备信息", "getLine1Number", {}, phoneNumber);
                    return phoneNumber;
                };
            });
            
            // Android ID
            var Secure = Java.use("android.provider.Settings$Secure");
            var originalGetString = Secure.getString;
            
            Secure.getString.implementation = function(resolver, name) {
                var value = originalGetString.call(this, resolver, name);
                
                if (name === "android_id") {
                    apiCalls.addCall("设备信息", "Settings.Secure.getString", { name: name }, value);
                }
                
                return value;
            };
            
            logger.info(tag, "设备信息监控已设置");
        } catch (e) {
            logger.error(tag, "Hook设备信息失败: " + e);
        }
    }
    
    logger.info(tag, "敏感API监控模块加载完成");
    return {
        apiCalls: apiCalls
    };
}; 