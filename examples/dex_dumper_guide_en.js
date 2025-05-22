/**
 * Frida DEX Dumper Module Usage Guide
 * This file demonstrates advanced usage and practical scenarios for the dex_dumper.js module
 */

// Basic Usage: Unpacking common protection mechanisms
function basicUnpacking() {
    // Load the module
    var dexDumper = require('../modules/dex_dumper.js')({
        // Configure log level
        logLevel: 'info',
        // Enable file logging
        fileLogging: true,
        logFilePath: '/sdcard/frida_dex_dumper.log'
    }, console, null);

    // Set output directory
    dexDumper.setOutputDirectory('/sdcard/frida_dex_dumps/');
    
    console.log("[*] DEX dumper module initialized");
    
    // Show statistics after 30 seconds
    setTimeout(function() {
        dexDumper.showStats();
    }, 30000);
}

// Memory Optimization: For low-memory devices, reduces memory pressure
function memoryOptimizedUnpacking() {
    var dexDumper = require('../modules/dex_dumper.js')({
        logLevel: 'info'
    }, console, null);
    
    // Optimize memory usage
    dexDumper.setFilterSystemClasses(true);  // Filter system classes
    dexDumper.setScanInterval(15000);        // Increase scan interval to 15 seconds
    dexDumper.setDexSizeLimit(10240, 15 * 1024 * 1024); // Limit DEX size
    
    console.log("[*] Memory-optimized DEX dumper module initialized");
}

// Specialized configuration for Huawei HMS applications
function huaweiHmsUnpacking() {
    var dexDumper = require('../modules/dex_dumper.js')({
        logLevel: 'debug'
    }, console, null);
    
    // Only enable Huawei-related protection handling
    dexDumper.enableProtection('Huawei HMS', true);
    dexDumper.enableProtection('Huawei Security', true);
    dexDumper.enableProtection('HiSilicon', true);
    
    // Disable other protection types
    const disabledProtections = ['Bangcle', 'ijiami', '360', 'Tencent'];
    disabledProtections.forEach(p => dexDumper.enableProtection(p, false));
    
    // Set specialized output directory
    dexDumper.setOutputDirectory('/sdcard/hms_dumps/');
    
    // Periodic scanning
    var count = 0;
    var scanTimer = setInterval(function() {
        console.log(`[*] Executing scan #${++count}`);
        dexDumper.scanNow();
        
        if (count >= 10) {
            clearInterval(scanTimer);
            dexDumper.showStats();
        }
    }, 10000);
    
    console.log("[*] HMS application dumper module initialized");
}

// ByteDance application unpacking configuration
function bytedanceUnpacking() {
    var dexDumper = require('../modules/dex_dumper.js')({
        logLevel: 'debug'
    }, console, null);
    
    // Focus only on ByteDance protection
    dexDumper.enableProtection('ByteDance', true);
    
    // Disable other protection handling to improve performance
    const allProtections = ['Bangcle', 'ijiami', '360', 'Tencent', 'Ali Security', 
                           'Baidu', 'Nagapt', 'Shenda', 'NetQin', 'Kiwisec', 
                           'Tongfudun', 'Rising', 'APKProtect', 'TopJohnson', 'Coral', 
                           'Canary', 'Huawei HMS', 'Huawei Security', 'HiSilicon', 'New ijiami',
                           'Ctrip', 'WeChat Mini-program', 'Cheetah Mobile', 'OPPO', 'vivo'];
    
    allProtections.forEach(p => {
        if (p !== 'ByteDance') {
            dexDumper.enableProtection(p, false);
        }
    });
    
    // Add application behavior monitoring, dump at key Activity creation
    Java.perform(function() {
        try {
            // Target main Activities for TikTok and other ByteDance apps
            const mainActivityClasses = [
                "com.ss.android.ugc.aweme.main.MainActivity",
                "com.ss.android.article.news.activity.MainActivity",
                "com.ss.android.lark.main.app.MainActivity"
            ];
            
            mainActivityClasses.forEach(className => {
                try {
                    const activityClass = Java.use(className);
                    activityClass.onCreate.overload('android.os.Bundle').implementation = function(bundle) {
                        const result = this.onCreate(bundle);
                        console.log(`[*] Detected ${className} creation, triggering dump`);
                        
                        // Force class loading and memory scanning
                        dexDumper.forceLoadClasses();
                        dexDumper.scanNow();
                        
                        return result;
                    };
                    console.log(`[+] Hooked ${className}`);
                } catch (e) {
                    // Ignore classes not found
                }
            });
        } catch (e) {
            console.log(`[-] Failed to set up Activity monitoring: ${e}`);
        }
    });
    
    console.log("[*] ByteDance application dumper module initialized");
}

// Batch processing of extracted DEX files
function processDexFiles() {
    // This function demonstrates how to process files after DEX extraction
    Java.perform(function() {
        try {
            const File = Java.use("java.io.File");
            const dumpDir = new File("/sdcard/frida_dumps/");
            
            if (!dumpDir.exists() || !dumpDir.isDirectory()) {
                console.log("[-] Extraction directory not found");
                return;
            }
            
            const files = dumpDir.listFiles();
            console.log(`[*] Found ${files.length} files`);
            
            let dexCount = 0;
            for (let i = 0; i < files.length; i++) {
                const file = files[i];
                const fileName = file.getName();
                
                if (fileName.endsWith(".dex")) {
                    dexCount++;
                    const fileSize = file.length();
                    console.log(`[+] DEX file: ${fileName}, Size: ${Math.floor(fileSize / 1024)}KB`);
                    
                    // You can add other processing logic here
                    // For example: Validate DEX header, repair damaged DEX, etc.
                }
            }
            
            console.log(`[*] Total of ${dexCount} DEX files`);
        } catch (e) {
            console.log(`[-] Failed to process DEX files: ${e}`);
        }
    });
}

// Advanced unpacking: Combining anti-debug bypass and custom hooks
function advancedUnpacking() {
    // 1. First bypass anti-debugging protection
    Java.perform(function() {
        try {
            // Common anti-debug checks
            const Debug = Java.use("android.os.Debug");
            Debug.isDebuggerConnected.implementation = function() {
                return false;
            };
            
            // Bypass common anti-debug detection classes
            const antiDebugClasses = [
                "com.secure.check.EmulatorDetector",
                "com.xxlib.utils.SecurityCheckUtil",
                "com.bangcle.safebox.SafeBox"
            ];
            
            antiDebugClasses.forEach(className => {
                try {
                    const clazz = Java.use(className);
                    
                    // Try to intercept all methods returning boolean
                    for (const methodName in clazz) {
                        try {
                            if (methodName.startsWith("check") || methodName.startsWith("detect") || 
                                methodName.startsWith("is")) {
                                const method = clazz[methodName];
                                if (method && method.returnType && 
                                    method.returnType.className === "boolean") {
                                    method.implementation = function() {
                                        console.log(`[*] Bypassing anti-debug check: ${className}.${methodName}`);
                                        return false;
                                    };
                                }
                            }
                        } catch (e) {
                            // Ignore errors for individual methods
                        }
                    }
                } catch (e) {
                    // Ignore classes not found
                }
            });
            
            console.log("[+] Anti-debug bypass set up completed");
        } catch (e) {
            console.log(`[-] Failed to set up anti-debug bypass: ${e}`);
        }
    });
    
    // 2. Then load the DEX dumper module
    var dexDumper = require('../modules/dex_dumper.js')({
        logLevel: 'info'
    }, console, null);
    
    console.log("[*] Advanced unpacking setup complete");
}

// Choose a method to execute and start
function main() {
    // Select an unpacking method to execute
    // Uncomment the corresponding method call based on the target application type
    
    basicUnpacking();
    //memoryOptimizedUnpacking();
    //huaweiHmsUnpacking();
    //bytedanceUnpacking();
    //advancedUnpacking();
    
    // Process extracted DEX files (can be executed after unpacking is complete)
    //setTimeout(processDexFiles, 60000);
}

// Execute the main function at the right time
setTimeout(main, 1000); 