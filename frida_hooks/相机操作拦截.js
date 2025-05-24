/**
 * 相机操作拦截脚本
 * 
 * 功能：拦截Android应用中的相机相关操作
 * 作用：监控应用对相机的使用，可选择性地阻止或修改相机行为
 * 适用：分析应用相机使用行为，保护隐私，防止恶意拍照
 */

// 等待Java虚拟机加载完成
Java.perform(function() {
    console.log("[*] 相机操作拦截脚本已启动");

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
     * 一、拦截Camera类（旧版API）
     */
    var Camera = Java.use("android.hardware.Camera");
    
    // 拦截打开相机
    Camera.open.overload().implementation = function() {
        console.log("\n[+] Camera.open()");
        console.log("    调用堆栈:\n    " + getStackTrace());
        
        return this.open();
    };
    
    Camera.open.overload("int").implementation = function(cameraId) {
        console.log("\n[+] Camera.open(" + cameraId + ")");
        console.log("    相机ID: " + cameraId);
        console.log("    调用堆栈:\n    " + getStackTrace());
        
        return this.open(cameraId);
    };
    
    // 拦截拍照
    Camera.takePicture.overload(
        "android.hardware.Camera$ShutterCallback",
        "android.hardware.Camera$PictureCallback",
        "android.hardware.Camera$PictureCallback"
    ).implementation = function(shutter, raw, jpeg) {
        console.log("\n[+] Camera.takePicture");
        console.log("    调用堆栈:\n    " + getStackTrace());
        
        return this.takePicture(shutter, raw, jpeg);
    };
    
    // 拦截开始预览
    Camera.startPreview.implementation = function() {
        console.log("\n[+] Camera.startPreview");
        console.log("    调用堆栈:\n    " + getStackTrace());
        
        return this.startPreview();
    };
    
    // 拦截停止预览
    Camera.stopPreview.implementation = function() {
        console.log("\n[+] Camera.stopPreview");
        console.log("    调用堆栈:\n    " + getStackTrace());
        
        return this.stopPreview();
    };
    
    // 拦截释放相机
    Camera.release.implementation = function() {
        console.log("\n[+] Camera.release");
        console.log("    调用堆栈:\n    " + getStackTrace());
        
        return this.release();
    };
    
    // 拦截设置预览回调
    Camera.setPreviewCallback.implementation = function(callback) {
        console.log("\n[+] Camera.setPreviewCallback");
        console.log("    调用堆栈:\n    " + getStackTrace());
        
        return this.setPreviewCallback(callback);
    };
    
    // 拦截设置参数
    Camera.setParameters.implementation = function(params) {
        console.log("\n[+] Camera.setParameters");
        
        // 打印相机参数
        if (params) {
            var pictureSize = params.getPictureSize();
            if (pictureSize) {
                console.log("    图片尺寸: " + pictureSize.width + "x" + pictureSize.height);
            }
            
            var previewSize = params.getPreviewSize();
            if (previewSize) {
                console.log("    预览尺寸: " + previewSize.width + "x" + previewSize.height);
            }
            
            var flashMode = params.getFlashMode();
            if (flashMode) {
                console.log("    闪光灯模式: " + flashMode);
            }
            
            var focusMode = params.getFocusMode();
            if (focusMode) {
                console.log("    对焦模式: " + focusMode);
            }
        }
        
        console.log("    调用堆栈:\n    " + getStackTrace());
        
        return this.setParameters(params);
    };

    /**
     * 二、拦截Camera2类（新版API）
     */
    try {
        var CameraManager = Java.use("android.hardware.camera2.CameraManager");
        
        // 拦截打开相机
        CameraManager.openCamera.overload(
            "java.lang.String", 
            "android.hardware.camera2.CameraDevice$StateCallback", 
            "android.os.Handler"
        ).implementation = function(cameraId, callback, handler) {
            console.log("\n[+] CameraManager.openCamera");
            console.log("    相机ID: " + cameraId);
            console.log("    调用堆栈:\n    " + getStackTrace());
            
            return this.openCamera(cameraId, callback, handler);
        };
        
        // 拦截获取相机ID列表
        CameraManager.getCameraIdList.implementation = function() {
            var ids = this.getCameraIdList();
            console.log("\n[+] CameraManager.getCameraIdList");
            console.log("    相机ID列表: " + JSON.stringify(ids));
            console.log("    调用堆栈:\n    " + getStackTrace());
            
            return ids;
        };
        
        // 拦截获取相机特性
        CameraManager.getCameraCharacteristics.implementation = function(cameraId) {
            var characteristics = this.getCameraCharacteristics(cameraId);
            console.log("\n[+] CameraManager.getCameraCharacteristics");
            console.log("    相机ID: " + cameraId);
            console.log("    调用堆栈:\n    " + getStackTrace());
            
            return characteristics;
        };
        
        console.log("[+] Camera2 API拦截设置完成");
    } catch (e) {
        console.log("[-] Camera2 API可能不可用: " + e);
    }

    /**
     * 三、拦截CameraDevice（Camera2 API的相机设备）
     */
    try {
        var CameraDevice = Java.use("android.hardware.camera2.CameraDevice");
        
        // 拦截创建捕获会话
        CameraDevice.createCaptureSession.overload(
            "[Landroid.view.Surface;", 
            "android.hardware.camera2.CameraCaptureSession$StateCallback", 
            "android.os.Handler"
        ).implementation = function(outputs, callback, handler) {
            console.log("\n[+] CameraDevice.createCaptureSession");
            console.log("    输出Surface数量: " + outputs.length);
            console.log("    调用堆栈:\n    " + getStackTrace());
            
            return this.createCaptureSession(outputs, callback, handler);
        };
        
        // 拦截创建捕获请求
        CameraDevice.createCaptureRequest.implementation = function(templateType) {
            console.log("\n[+] CameraDevice.createCaptureRequest");
            console.log("    模板类型: " + templateType);
            
            // 打印模板类型
            var templateNames = {
                1: "TEMPLATE_PREVIEW",
                2: "TEMPLATE_STILL_CAPTURE",
                3: "TEMPLATE_RECORD",
                4: "TEMPLATE_VIDEO_SNAPSHOT",
                5: "TEMPLATE_ZERO_SHUTTER_LAG",
                6: "TEMPLATE_MANUAL"
            };
            console.log("    模板名称: " + (templateNames[templateType] || "未知"));
            console.log("    调用堆栈:\n    " + getStackTrace());
            
            return this.createCaptureRequest(templateType);
        };
        
        // 拦截关闭相机
        CameraDevice.close.implementation = function() {
            console.log("\n[+] CameraDevice.close");
            console.log("    相机ID: " + this.getId());
            console.log("    调用堆栈:\n    " + getStackTrace());
            
            return this.close();
        };
        
        console.log("[+] CameraDevice拦截设置完成");
    } catch (e) {
        console.log("[-] CameraDevice可能不可用: " + e);
    }

    /**
     * 四、拦截CameraCaptureSession（Camera2 API的捕获会话）
     */
    try {
        var CameraCaptureSession = Java.use("android.hardware.camera2.CameraCaptureSession");
        
        // 拦截捕获图像
        CameraCaptureSession.capture.overload(
            "android.hardware.camera2.CaptureRequest", 
            "android.hardware.camera2.CameraCaptureSession$CaptureCallback", 
            "android.os.Handler"
        ).implementation = function(request, callback, handler) {
            console.log("\n[+] CameraCaptureSession.capture");
            console.log("    调用堆栈:\n    " + getStackTrace());
            
            return this.capture(request, callback, handler);
        };
        
        // 拦截设置重复请求
        CameraCaptureSession.setRepeatingRequest.overload(
            "android.hardware.camera2.CaptureRequest", 
            "android.hardware.camera2.CameraCaptureSession$CaptureCallback", 
            "android.os.Handler"
        ).implementation = function(request, callback, handler) {
            console.log("\n[+] CameraCaptureSession.setRepeatingRequest");
            console.log("    调用堆栈:\n    " + getStackTrace());
            
            return this.setRepeatingRequest(request, callback, handler);
        };
        
        // 拦截停止重复请求
        CameraCaptureSession.stopRepeating.implementation = function() {
            console.log("\n[+] CameraCaptureSession.stopRepeating");
            console.log("    调用堆栈:\n    " + getStackTrace());
            
            return this.stopRepeating();
        };
        
        // 拦截关闭会话
        CameraCaptureSession.close.implementation = function() {
            console.log("\n[+] CameraCaptureSession.close");
            console.log("    调用堆栈:\n    " + getStackTrace());
            
            return this.close();
        };
        
        console.log("[+] CameraCaptureSession拦截设置完成");
    } catch (e) {
        console.log("[-] CameraCaptureSession可能不可用: " + e);
    }

    /**
     * 五、拦截CameraX API（Jetpack库）
     */
    try {
        var ProcessCameraProvider = Java.use("androidx.camera.lifecycle.ProcessCameraProvider");
        
        // 拦截获取实例
        ProcessCameraProvider.getInstance.implementation = function(context) {
            console.log("\n[+] ProcessCameraProvider.getInstance");
            console.log("    调用堆栈:\n    " + getStackTrace());
            
            return this.getInstance(context);
        };
        
        // 拦截绑定生命周期
        ProcessCameraProvider.bindToLifecycle.overload(
            "androidx.lifecycle.LifecycleOwner", 
            "[Landroidx.camera.core.CameraSelector;", 
            "[Landroidx.camera.core.UseCase;"
        ).implementation = function(lifecycleOwner, selectors, useCases) {
            console.log("\n[+] ProcessCameraProvider.bindToLifecycle");
            console.log("    相机选择器数量: " + selectors.length);
            console.log("    用例数量: " + useCases.length);
            
            // 打印用例类型
            for (var i = 0; i < useCases.length; i++) {
                var useCase = useCases[i];
                console.log("    用例 #" + i + ": " + useCase.$className);
            }
            
            console.log("    调用堆栈:\n    " + getStackTrace());
            
            return this.bindToLifecycle(lifecycleOwner, selectors, useCases);
        };
        
        console.log("[+] CameraX API拦截设置完成");
    } catch (e) {
        console.log("[-] CameraX API可能不可用: " + e);
    }

    /**
     * 六、拦截ImageReader（用于处理相机图像）
     */
    try {
        var ImageReader = Java.use("android.media.ImageReader");
        
        // 拦截创建ImageReader
        ImageReader.newInstance.overload(
            "int", "int", "int", "int"
        ).implementation = function(width, height, format, maxImages) {
            console.log("\n[+] ImageReader.newInstance");
            console.log("    宽度: " + width);
            console.log("    高度: " + height);
            console.log("    格式: " + format);
            console.log("    最大图像数: " + maxImages);
            console.log("    调用堆栈:\n    " + getStackTrace());
            
            return this.newInstance(width, height, format, maxImages);
        };
        
        // 拦截获取图像
        ImageReader.acquireLatestImage.implementation = function() {
            console.log("\n[+] ImageReader.acquireLatestImage");
            console.log("    调用堆栈:\n    " + getStackTrace());
            
            return this.acquireLatestImage();
        };
        
        ImageReader.acquireNextImage.implementation = function() {
            console.log("\n[+] ImageReader.acquireNextImage");
            console.log("    调用堆栈:\n    " + getStackTrace());
            
            return this.acquireNextImage();
        };
        
        console.log("[+] ImageReader拦截设置完成");
    } catch (e) {
        console.log("[-] ImageReader可能不可用: " + e);
    }

    /**
     * 七、拦截Image（相机捕获的图像）
     */
    try {
        var Image = Java.use("android.media.Image");
        
        // 拦截获取图像平面
        Image.getPlanes.implementation = function() {
            console.log("\n[+] Image.getPlanes");
            console.log("    宽度: " + this.getWidth());
            console.log("    高度: " + this.getHeight());
            console.log("    格式: " + this.getFormat());
            console.log("    时间戳: " + this.getTimestamp());
            console.log("    调用堆栈:\n    " + getStackTrace());
            
            return this.getPlanes();
        };
        
        // 拦截关闭图像
        Image.close.implementation = function() {
            console.log("\n[+] Image.close");
            console.log("    调用堆栈:\n    " + getStackTrace());
            
            return this.close();
        };
        
        console.log("[+] Image拦截设置完成");
    } catch (e) {
        console.log("[-] Image可能不可用: " + e);
    }

    console.log("[*] 相机操作拦截设置完成");
}); 