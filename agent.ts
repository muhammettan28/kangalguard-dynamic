import Java from "frida-java-bridge";

// ─── Feature Sayaçları ───────────────────────────────────────────────────────

const counters: Record<string, number> = {
    // Java API Calls (8)
    reflection_invoke_count: 0,
    dex_class_loader_count: 0,
    runtime_exec_count: 0,
    dynamic_class_load_count: 0,
    getPackageInfo_count: 0,
    sendTextMessage_count: 0,
    getDeviceId_count: 0,
    getSubscriberId_count: 0,

    // Crypto (5)
    cipher_init_count: 0,
    cipher_aes_count: 0,
    cipher_des_count: 0,
    secret_key_gen_count: 0,
    base64_encode_count: 0,

    // Anti-Analysis (7)
    system_exit_attempt: 0,
    debugger_check_count: 0,
    emulator_check_count: 0,
    root_check_count: 0,
    sleep_call_count: 0,
    stack_trace_inspect_count: 0,
    secure_random_count: 0,

    // Genel Davranış (3)
    verify_attempt_count: 0,
    string_decrypt_count: 0,
    native_lib_load_count: 0,

    // Intent & IPC (6)
    implicit_intent_count: 0,
    startActivity_count: 0,
    sendBroadcast_count: 0,
    bindService_count: 0,
    content_resolver_query_count: 0,
    content_resolver_insert_count: 0,

    // File System (6)
    file_write_count: 0,
    file_read_sensitive_count: 0,
    shared_prefs_write_count: 0,
    openFileOutput_count: 0,
    deleteFile_count: 0,
    getExternalStorageDirectory_count: 0,

    // Network & Socket (5)
    socket_create_count: 0,
    url_connection_count: 0,
    ssl_bypass_attempt: 0,
    dns_lookup_count: 0,
    setRequestProperty_count: 0,

    // Persistence & Privilege (5)
    alarm_manager_set_count: 0,
    job_scheduler_count: 0,
    register_receiver_count: 0,
    requestPermission_count: 0,
    setComponentEnabled_count: 0,

    // Process & Memory (5)
    thread_create_count: 0,
    process_list_query_count: 0,
    memory_alloc_large_count: 0,
    class_loader_parent_count: 0,
    native_method_register_count: 0,

    // Accessibility, Overlay & Clipboard (4)
    accessibility_query_count: 0,
    overlay_window_count: 0,
    clipboard_read_count: 0,
    clipboard_write_count: 0,
};

// ─── Temporal Tracking ───────────────────────────────────────────────────────
// Her kategori için ilk tetiklenme zamanını ms cinsinden saklar.
// -1 = henüz tetiklenmedi

const SESSION_START: number = Date.now();

const timings: Record<string, number> = {
    first_network_ms:       -1,   // İlk ağ çağrısı (socket/url/dns)
    first_crypto_ms:        -1,   // İlk şifreleme çağrısı
    first_anti_analysis_ms: -1,   // İlk anti-analysis çağrısı
    first_file_write_ms:    -1,   // İlk dosya yazma
    first_reflection_ms:    -1,   // İlk reflection çağrısı
    first_exec_ms:          -1,   // İlk Runtime.exec çağrısı
    first_sms_ms:           -1,   // İlk SMS gönderme
    first_dynamic_load_ms:  -1,   // İlk DexClassLoader / Class.forName
};

// Burst tracking: 5 saniyelik pencerede en yüksek event sayısı
const BURST_WINDOW_MS = 5000;
const eventTimestamps: number[] = [];
let burstPeakCount: number = 0;

function recordTime(key: string): void {
    if (key in timings && timings[key] === -1) {
        timings[key] = Date.now() - SESSION_START;
    }
}

function recordBurst(): void {
    const now = Date.now();
    eventTimestamps.push(now);
    const cutoff = now - BURST_WINDOW_MS;
    while (eventTimestamps.length > 0 && eventTimestamps[0] < cutoff) {
        eventTimestamps.shift();
    }
    if (eventTimestamps.length > burstPeakCount) {
        burstPeakCount = eventTimestamps.length;
    }
}

// ─── Sequence Tracking ───────────────────────────────────────────────────────
// Her önemli event'i {tag, ms} olarak sırayla kaydeder.
// Python tarafı bu listeyi analiz ederek zincirleri tespit eder.
// MAX_SEQ_EVENTS: bellek taşmasını önlemek için hard limit.

interface SeqEvent {
    tag: string;   // kısa olay etiketi (örn: "REFLECT", "EXEC", "CRYPTO")
    ms:  number;   // oturum başından itibaren ms
}

const seqLog: SeqEvent[] = [];

// Sequence tag'leri — Python'daki analiz bu string'leri arar
const SEQ = {
    REFLECT:      "REFLECT",      // reflection invoke
    DEX_LOAD:     "DEX_LOAD",     // DexClassLoader init
    EXEC:         "EXEC",         // Runtime.exec
    DYNAMIC_CLS:  "DYNAMIC_CLS",  // Class.forName
    CRYPTO:       "CRYPTO",       // Cipher.init / KeyGenerator
    NETWORK:      "NETWORK",      // Socket / URL / DNS
    FILE_WRITE:   "FILE_WRITE",   // FileOutputStream
    ROOT_CHECK:   "ROOT_CHECK",   // File.exists (root path)
    ANTI:         "ANTI",         // system_exit / debugger / emulator
    SMS:          "SMS",          // sendTextMessage
    CONTACT_READ: "CONTACT_READ", // ContentResolver.query
    NATIVE_LOAD:  "NATIVE_LOAD",  // System.loadLibrary
    PERSIST:      "PERSIST",      // AlarmManager / registerReceiver / JobScheduler
    SURVEIL:      "SURVEIL",      // getDeviceId / getSubscriberId
    IPC:          "IPC",          // sendBroadcast / bindService
    CLIPBOARD:    "CLIPBOARD",    // clipboard read / write
    OVERLAY:      "OVERLAY",      // overlay window (TYPE_APPLICATION_OVERLAY)
    ACCESSIBILITY:"ACCESSIBILITY",// AccessibilityManager query
};

// Per-tag throttle — yüksek frekanslı tag'ler (REFLECT, DYNAMIC_CLS) seqLog'u
// doldurmasın; nadir ama kritik tag'ler (CLIPBOARD, OVERLAY) kayıp vermesin.
const SEQ_TAG_MAX: Record<string, number> = {
    REFLECT:      15,
    DYNAMIC_CLS:  15,
    NETWORK:      30,
    CRYPTO:       20,
    FILE_WRITE:   20,
    ANTI:         20,
    ROOT_CHECK:   10,
    CONTACT_READ: 10,
    DEX_LOAD:     20,
    EXEC:         20,
    SMS:          20,
    NATIVE_LOAD:  20,
    PERSIST:      15,
    SURVEIL:      10,
    IPC:          15,
    CLIPBOARD:    20,
    OVERLAY:      10,
    ACCESSIBILITY:10,
};
const seqTagCount: Record<string, number> = {};

function seqPush(tag: string): void {
    const max: number = SEQ_TAG_MAX[tag] !== undefined ? SEQ_TAG_MAX[tag] : 10;
    const cur: number = seqTagCount[tag] !== undefined ? seqTagCount[tag] : 0;
    if (cur >= max) return;
    seqTagCount[tag] = cur + 1;
    seqLog.push({ tag, ms: Date.now() - SESSION_START });
}

function inc(key: string): void {
    if (key in counters) {
        counters[key]++;
        recordBurst();
    }
}

function flushCounters(): void {
    send({
        type: "COUNTERS",
        payload: {
            ...counters,
            _timings: { ...timings },
            _burst_peak: burstPeakCount,
            _session_duration_ms: Date.now() - SESSION_START,
            _seq_log: seqLog.slice(), // shallow copy, orijinali koru
        }
    });
}

function tryHook(label: string, fn: () => void): void {
    try {
        fn();
        console.log(`[+] ${label}`);
    } catch (e) {
        console.log(`[-] FAIL: ${label} -> ${e}`);
    }
}

// ─── Hook'lar ────────────────────────────────────────────────────────────────

Java.perform(() => {
    console.log("=== KangalGuard Agent Başladı ===");

    // ── 1. Java API Calls ────────────────────────────────────────────────────

    tryHook("Method.invoke (reflection)", () => {
        const Method = Java.use("java.lang.reflect.Method");
        Method.invoke.implementation = function (obj: any, args: any) {
            inc("reflection_invoke_count");
            recordTime("first_reflection_ms");
            seqPush(SEQ.REFLECT);
            return this.invoke(obj, args);
        };
    });

    tryHook("DexClassLoader.$init", () => {
        const DexClassLoader = Java.use("dalvik.system.DexClassLoader");
        DexClassLoader.$init.implementation = function (
            dexPath: string, optimizedDir: string, libraryPath: string, parent: any
        ) {
            inc("dex_class_loader_count");
            recordTime("first_dynamic_load_ms");
            seqPush(SEQ.DEX_LOAD);
            console.log(`[DEX] ${dexPath}`);
            return this.$init(dexPath, optimizedDir, libraryPath, parent);
        };
    });

    tryHook("Runtime.exec", () => {
        const Runtime = Java.use("java.lang.Runtime");
        Runtime.exec.overload("java.lang.String").implementation = function (cmd: string) {
            inc("runtime_exec_count");
            recordTime("first_exec_ms");
            seqPush(SEQ.EXEC);
            console.log(`[EXEC] ${cmd}`);
            return this.exec(cmd);
        };
        Runtime.exec.overload("[Ljava.lang.String;").implementation = function (cmds: string[]) {
            inc("runtime_exec_count");
            recordTime("first_exec_ms");
            seqPush(SEQ.EXEC);
            console.log(`[EXEC] ${cmds}`);
            return this.exec(cmds);
        };
    });

    tryHook("Class.forName", () => {
        const Class = Java.use("java.lang.Class");
        Class.forName.overload("java.lang.String").implementation = function (name: string) {
            inc("dynamic_class_load_count");
            recordTime("first_dynamic_load_ms");
            seqPush(SEQ.DYNAMIC_CLS);
            return this.forName(name);
        };
    });

    tryHook("PackageManager.getPackageInfo", () => {
        const PackageManager = Java.use("android.app.ApplicationPackageManager");
        PackageManager.getPackageInfo.overload(
            "java.lang.String", "int"
        ).implementation = function (pkg: string, flags: number) {
            inc("getPackageInfo_count");
            return this.getPackageInfo(pkg, flags);
        };
    });

    tryHook("SmsManager.sendTextMessage", () => {
        const SmsManager = Java.use("android.telephony.SmsManager");
        // Android 12'de 3 overload var, hepsini hook'luyoruz
        SmsManager.sendTextMessage.overload(
            "java.lang.String", "java.lang.String", "java.lang.String",
            "android.app.PendingIntent", "android.app.PendingIntent"
        ).implementation = function (dest: string, src: any, text: string, sent: any, delivery: any) {
            inc("sendTextMessage_count");
            recordTime("first_sms_ms");
            seqPush(SEQ.SMS);
            console.log(`[SMS] ${dest}: ${text}`);
            return this.sendTextMessage(dest, src, text, sent, delivery);
        };
        SmsManager.sendTextMessage.overload(
            "java.lang.String", "java.lang.String", "java.lang.String",
            "android.app.PendingIntent", "android.app.PendingIntent", "long"
        ).implementation = function (dest: string, src: any, text: string, sent: any, delivery: any, messageId: number) {
            inc("sendTextMessage_count");
            recordTime("first_sms_ms");
            seqPush(SEQ.SMS);
            console.log(`[SMS] ${dest}: ${text}`);
            return this.sendTextMessage(dest, src, text, sent, delivery, messageId);
        };
    });

    tryHook("TelephonyManager.getDeviceId", () => {
        const TelephonyManager = Java.use("android.telephony.TelephonyManager");
        TelephonyManager.getDeviceId.overload().implementation = function () {
            inc("getDeviceId_count");
            seqPush(SEQ.SURVEIL);
            return this.getDeviceId();
        };
    });

    tryHook("TelephonyManager.getSubscriberId", () => {
        const TelephonyManager = Java.use("android.telephony.TelephonyManager");
        TelephonyManager.getSubscriberId.overload().implementation = function () {
            inc("getSubscriberId_count");
            seqPush(SEQ.SURVEIL);
            return this.getSubscriberId();
        };
    });

    // ── 2. Crypto ────────────────────────────────────────────────────────────

    tryHook("Cipher.init", () => {
        const Cipher = Java.use("javax.crypto.Cipher");
        Cipher.init.overload("int", "java.security.Key").implementation = function (
            opmode: number, key: any
        ) {
            inc("cipher_init_count");
            const algo: string = this.getAlgorithm();
            if (algo.toUpperCase().includes("AES")) inc("cipher_aes_count");
            if (algo.toUpperCase().includes("DES")) inc("cipher_des_count");
            recordTime("first_crypto_ms");
            seqPush(SEQ.CRYPTO);
            console.log(`[CRYPTO] Cipher: ${algo}`);
            return this.init(opmode, key);
        };
    });

    tryHook("KeyGenerator.generateKey", () => {
        const KeyGenerator = Java.use("javax.crypto.KeyGenerator");
        KeyGenerator.generateKey.implementation = function () {
            inc("secret_key_gen_count");
            return this.generateKey();
        };
    });

    tryHook("Base64.encode/encodeToString", () => {
        const Base64 = Java.use("android.util.Base64");
        // Android 12: encode([B, int) ve encode([B, int, int, int) overload'ları var
        Base64.encode.overload("[B", "int").implementation = function (input: any, flags: number) {
            inc("base64_encode_count");
            return this.encode(input, flags);
        };
        Base64.encodeToString.overload("[B", "int").implementation = function (input: any, flags: number) {
            inc("base64_encode_count");
            return this.encodeToString(input, flags);
        };
    });

    tryHook("SecureRandom.$init", () => {
        const SecureRandom = Java.use("java.security.SecureRandom");
        SecureRandom.$init.overload().implementation = function () {
            inc("secure_random_count");
            return this.$init();
        };
    });

    // ── 3. Anti-Analysis ─────────────────────────────────────────────────────

    tryHook("System.exit (bypass)", () => {
        const System = Java.use("java.lang.System");
        System.exit.implementation = function (code: number) {
            inc("system_exit_attempt");
            recordTime("first_anti_analysis_ms");
            seqPush(SEQ.ANTI);
            console.log(`[ANTI] System.exit(${code}) engellendi`);
            // bypass — çağrılmıyor
        };
    });

    tryHook("Process.killProcess (bypass)", () => {
        const Process = Java.use("android.os.Process");
        Process.killProcess.implementation = function (pid: number) {
            const myPid: number = Process.myPid();
            if (pid === myPid) {
                inc("system_exit_attempt");
                recordTime("first_anti_analysis_ms");
                seqPush(SEQ.ANTI);
                console.log(`[ANTI] Process.killProcess(self) engellendi`);
                // bypass — kendini öldürmeye izin verme
            } else {
                console.log(`[ANTI] Process.killProcess(${pid}) — izin verildi`);
                this.killProcess(pid);
            }
        };
    });

    tryHook("Runtime.halt (bypass)", () => {
        const Runtime = Java.use("java.lang.Runtime");
        Runtime.halt.implementation = function (code: number) {
            inc("system_exit_attempt");
            recordTime("first_anti_analysis_ms");
            seqPush(SEQ.ANTI);
            console.log(`[ANTI] Runtime.halt(${code}) engellendi`);
            // bypass — çağrılmıyor
        };
    });

    tryHook("Debug.isDebuggerConnected (bypass)", () => {
        const Debug = Java.use("android.os.Debug");
        Debug.isDebuggerConnected.implementation = function () {
            inc("debugger_check_count");
            recordTime("first_anti_analysis_ms");
            seqPush(SEQ.ANTI);
            return false;
        };
    });

    tryHook("SystemProperties.get (emulator check)", () => {
        const SystemProperties = Java.use("android.os.SystemProperties");
        SystemProperties.get.overload("java.lang.String").implementation = function (key: string) {
            const emulatorKeys = ["ro.product.model", "ro.build.fingerprint", "ro.hardware", "ro.product.device"];
            if (emulatorKeys.includes(key)) inc("emulator_check_count");
            return this.get(key);
        };
    });

    tryHook("File.exists (root path check)", () => {
        const File = Java.use("java.io.File");
        const rootPaths = [
            "/system/app/Superuser.apk", "/sbin/su", "/system/bin/su",
            "/system/xbin/su", "/data/local/xbin/su", "/data/local/bin/su",
            "/system/sd/xbin/su", "/system/bin/failsafe/su", "/data/local/su"
        ];
        File.exists.implementation = function () {
            const path: string = this.getAbsolutePath();
            if (rootPaths.some(p => path.includes(p))) {
                inc("root_check_count");
                recordTime("first_anti_analysis_ms");
                seqPush(SEQ.ROOT_CHECK);
                console.log(`[ANTI] Root check: ${path}`);
                return false; // bypass
            }
            return this.exists();
        };
    });

    tryHook("Thread.sleep (timing attack)", () => {
        const Thread = Java.use("java.lang.Thread");
        Thread.sleep.overload("long").implementation = function (ms: number) {
            if (ms > 1000) {
                inc("sleep_call_count");
                console.log(`[ANTI] Thread.sleep(${ms}ms)`);
            }
            return this.sleep(ms);
        };
    });

    tryHook("Thread.getStackTrace", () => {
        const Thread = Java.use("java.lang.Thread");
        Thread.getStackTrace.implementation = function () {
            inc("stack_trace_inspect_count");
            return this.getStackTrace();
        };
    });

    tryHook("System.loadLibrary", () => {
        const System = Java.use("java.lang.System");
        System.loadLibrary.implementation = function (name: string) {
            inc("native_lib_load_count");
            seqPush(SEQ.NATIVE_LOAD);
            console.log(`[NATIVE] loadLibrary: ${name}`);
            return this.loadLibrary(name);
        };
    });

    // ── 4. Intent & IPC ──────────────────────────────────────────────────────

    tryHook("Intent.setAction (implicit)", () => {
        const Intent = Java.use("android.content.Intent");
        Intent.setAction.implementation = function (action: string) {
            inc("implicit_intent_count");
            return this.setAction(action);
        };
    });

    tryHook("Activity.startActivity", () => {
        const Activity = Java.use("android.app.Activity");
        Activity.startActivity.overload(
            "android.content.Intent"
        ).implementation = function (intent: any) {
            inc("startActivity_count");
            return this.startActivity(intent);
        };
    });

    tryHook("ContextWrapper.sendBroadcast", () => {
        const ContextWrapper = Java.use("android.content.ContextWrapper");
        ContextWrapper.sendBroadcast.overload(
            "android.content.Intent"
        ).implementation = function (intent: any) {
            inc("sendBroadcast_count");
            seqPush(SEQ.IPC);
            return this.sendBroadcast(intent);
        };
    });

    tryHook("ContextWrapper.bindService", () => {
        const ContextWrapper = Java.use("android.content.ContextWrapper");
        // Android 12: iki overload var, yaygın olanı hook'luyoruz
        ContextWrapper.bindService.overload(
            "android.content.Intent",
            "android.content.ServiceConnection",
            "int"
        ).implementation = function (intent: any, conn: any, flags: number) {
            inc("bindService_count");
            seqPush(SEQ.IPC);
            return this.bindService(intent, conn, flags);
        };
    });

    tryHook("ContentResolver.query", () => {
        const ContentResolver = Java.use("android.content.ContentResolver");
        ContentResolver.query.overload(
            "android.net.Uri",
            "[Ljava.lang.String;",
            "java.lang.String",
            "[Ljava.lang.String;",
            "java.lang.String"
        ).implementation = function (
            uri: any, proj: any, sel: any, selArgs: any, sort: any
        ) {
            inc("content_resolver_query_count");
            seqPush(SEQ.CONTACT_READ);
            return this.query(uri, proj, sel, selArgs, sort);
        };
    });

    tryHook("ContentResolver.insert", () => {
        const ContentResolver = Java.use("android.content.ContentResolver");
        // Android 12: iki overload var
        ContentResolver.insert.overload(
            "android.net.Uri",
            "android.content.ContentValues"
        ).implementation = function (uri: any, values: any) {
            inc("content_resolver_insert_count");
            return this.insert(uri, values);
        };
    });

    // ── 5. File System ───────────────────────────────────────────────────────

    tryHook("FileOutputStream.$init (write)", () => {
        const FileOutputStream = Java.use("java.io.FileOutputStream");
        FileOutputStream.$init.overload("java.lang.String").implementation = function (
            path: string
        ) {
            inc("file_write_count");
            recordTime("first_file_write_ms");
            seqPush(SEQ.FILE_WRITE);
            const sensitivePaths = ["/proc/", "/sys/", "/data/"];
            if (sensitivePaths.some(p => path.startsWith(p))) {
                inc("file_read_sensitive_count");
                console.log(`[FILE] Sensitive write: ${path}`);
            }
            return this.$init(path);
        };
    });

    tryHook("SharedPreferences.putString", () => {
        const Editor = Java.use("android.app.SharedPreferencesImpl$EditorImpl");
        Editor.putString.implementation = function (key: string, value: string) {
            inc("shared_prefs_write_count");
            return this.putString(key, value);
        };
    });

    tryHook("ContextWrapper.openFileOutput", () => {
        const ContextWrapper = Java.use("android.content.ContextWrapper");
        ContextWrapper.openFileOutput.implementation = function (
            name: string, mode: number
        ) {
            inc("openFileOutput_count");
            console.log(`[FILE] openFileOutput: ${name}`);
            return this.openFileOutput(name, mode);
        };
    });

    tryHook("File.delete", () => {
        const File = Java.use("java.io.File");
        File.delete.implementation = function () {
            inc("deleteFile_count");
            return this.delete();
        };
    });

    tryHook("Environment.getExternalStorageDirectory", () => {
        const Environment = Java.use("android.os.Environment");
        Environment.getExternalStorageDirectory.implementation = function () {
            inc("getExternalStorageDirectory_count");
            return this.getExternalStorageDirectory();
        };
    });

    // ── 6. Network & Socket ──────────────────────────────────────────────────

    tryHook("Socket.$init (raw socket)", () => {
        const Socket = Java.use("java.net.Socket");
        Socket.$init.overload("java.lang.String", "int").implementation = function (
            host: string, port: number
        ) {
            inc("socket_create_count");
            recordTime("first_network_ms");
            seqPush(SEQ.NETWORK);
            console.log(`[NET] Socket: ${host}:${port}`);
            return this.$init(host, port);
        };
    });

    tryHook("URL.openConnection", () => {
        const URL = Java.use("java.net.URL");
        URL.openConnection.overload().implementation = function () {
            inc("url_connection_count");
            recordTime("first_network_ms");
            seqPush(SEQ.NETWORK);
            console.log(`[NET] URL: ${this.toString()}`);
            return this.openConnection();
        };
    });

    tryHook("SSLContext.init (TrustManager bypass)", () => {
        const SSLContext = Java.use("javax.net.ssl.SSLContext");
        SSLContext.init.implementation = function (km: any, tm: any, sr: any) {
            if (tm !== null) {
                inc("ssl_bypass_attempt");
                console.log("[NET] Custom TrustManager!");
            }
            return this.init(km, tm, sr);
        };
    });

    tryHook("InetAddress.getByName (DNS)", () => {
        const InetAddress = Java.use("java.net.InetAddress");
        InetAddress.getByName.implementation = function (host: string) {
            inc("dns_lookup_count");
            recordTime("first_network_ms");
            seqPush(SEQ.NETWORK);
            console.log(`[NET] DNS: ${host}`);
            return this.getByName(host);
        };
    });

    tryHook("URLConnection.setRequestProperty", () => {
        const URLConnection = Java.use("java.net.URLConnection");
        URLConnection.setRequestProperty.implementation = function (
            key: string, value: string
        ) {
            inc("setRequestProperty_count");
            console.log(`[NET] Header: ${key}: ${value}`);
            return this.setRequestProperty(key, value);
        };
    });

    // ── 7. Persistence & Privilege ───────────────────────────────────────────

    tryHook("AlarmManager.set", () => {
        const AlarmManager = Java.use("android.app.AlarmManager");
        // Android 12'de 5 overload var, en yaygın ikisini hook'luyoruz
        AlarmManager.set.overload(
            "int", "long", "android.app.PendingIntent"
        ).implementation = function (type: number, triggerAtMillis: number, operation: any) {
            inc("alarm_manager_set_count");
            seqPush(SEQ.PERSIST);
            console.log(`[PERSIST] AlarmManager: ${triggerAtMillis}ms`);
            return this.set(type, triggerAtMillis, operation);
        };
        AlarmManager.set.overload(
            "int", "long", "java.lang.String",
            "android.app.AlarmManager$OnAlarmListener", "android.os.Handler"
        ).implementation = function (type: number, triggerAtMillis: number, tag: string, listener: any, handler: any) {
            inc("alarm_manager_set_count");
            seqPush(SEQ.PERSIST);
            console.log(`[PERSIST] AlarmManager (listener): ${triggerAtMillis}ms`);
            return this.set(type, triggerAtMillis, tag, listener, handler);
        };
    });

    tryHook("JobScheduler.schedule", () => {
        const JobScheduler = Java.use("android.app.job.JobScheduler");
        JobScheduler.schedule.implementation = function (jobInfo: any) {
            inc("job_scheduler_count");
            seqPush(SEQ.PERSIST);
            return this.schedule(jobInfo);
        };
    });

    tryHook("ContextWrapper.registerReceiver", () => {
        const ContextWrapper = Java.use("android.content.ContextWrapper");
        ContextWrapper.registerReceiver.overload(
            "android.content.BroadcastReceiver",
            "android.content.IntentFilter"
        ).implementation = function (receiver: any, filter: any) {
            inc("register_receiver_count");
            seqPush(SEQ.PERSIST);
            return this.registerReceiver(receiver, filter);
        };
    });

    tryHook("Activity.requestPermissions", () => {
        const Activity = Java.use("android.app.Activity");
        Activity.requestPermissions.implementation = function (
            perms: string[], reqCode: number
        ) {
            inc("requestPermission_count");
            console.log(`[PRIV] requestPermissions: ${perms}`);
            return this.requestPermissions(perms, reqCode);
        };
    });

    tryHook("PackageManager.setComponentEnabledSetting", () => {
        const PackageManager = Java.use("android.app.ApplicationPackageManager");
        PackageManager.setComponentEnabledSetting.implementation = function (
            comp: any, newState: number, flags: number
        ) {
            inc("setComponentEnabled_count");
            console.log(`[PRIV] setComponentEnabled: ${comp} -> ${newState}`);
            return this.setComponentEnabledSetting(comp, newState, flags);
        };
    });

    // ── 8. Process & Memory ──────────────────────────────────────────────────

    tryHook("Thread.$init (thread create)", () => {
        const Thread = Java.use("java.lang.Thread");
        Thread.$init.overload("java.lang.Runnable").implementation = function (r: any) {
            inc("thread_create_count");
            return this.$init(r);
        };
    });

    tryHook("ActivityManager.getRunningAppProcesses", () => {
        const ActivityManager = Java.use("android.app.ActivityManager");
        ActivityManager.getRunningAppProcesses.implementation = function () {
            inc("process_list_query_count");
            return this.getRunningAppProcesses();
        };
    });

    tryHook("ByteBuffer.allocate (>5MB)", () => {
        const ByteBuffer = Java.use("java.nio.ByteBuffer");
        ByteBuffer.allocate.implementation = function (capacity: number) {
            if (capacity > 5 * 1024 * 1024) {
                inc("memory_alloc_large_count");
                console.log(`[MEM] Large alloc: ${capacity} bytes`);
            }
            return this.allocate(capacity);
        };
    });

    tryHook("ClassLoader.getParent", () => {
        const ClassLoader = Java.use("java.lang.ClassLoader");
        ClassLoader.getParent.implementation = function () {
            inc("class_loader_parent_count");
            return this.getParent();
        };
    });

    // native_method_register_count — JNI registerNatives native tarafta olduğu için
    // burada ClassLoader üzerinden .so yüklemesini proxy olarak kullanıyoruz
    // (native_lib_load_count ile örtüşüyor, ayrı sinyal olarak korunuyor)

    // ── 9. Clipboard ─────────────────────────────────────────────────────────

    tryHook("ClipboardManager.getPrimaryClip (read)", () => {
        const ClipboardManager = Java.use("android.content.ClipboardManager");
        ClipboardManager.getPrimaryClip.implementation = function () {
            inc("clipboard_read_count");
            seqPush(SEQ.CLIPBOARD);
            return this.getPrimaryClip();
        };
    });

    tryHook("ClipboardManager.setPrimaryClip (write)", () => {
        const ClipboardManager = Java.use("android.content.ClipboardManager");
        ClipboardManager.setPrimaryClip.implementation = function (clip: any) {
            inc("clipboard_write_count");
            seqPush(SEQ.CLIPBOARD);
            console.log("[CLIP] setPrimaryClip — clipboard hijack?");
            return this.setPrimaryClip(clip);
        };
    });

    // ── 10. Accessibility ────────────────────────────────────────────────────

    tryHook("AccessibilityManager.isEnabled", () => {
        const AccessibilityManager = Java.use("android.view.accessibility.AccessibilityManager");
        AccessibilityManager.isEnabled.implementation = function () {
            inc("accessibility_query_count");
            seqPush(SEQ.ACCESSIBILITY);
            return this.isEnabled();
        };
    });

    tryHook("AccessibilityManager.getEnabledAccessibilityServiceList", () => {
        const AccessibilityManager = Java.use("android.view.accessibility.AccessibilityManager");
        AccessibilityManager.getEnabledAccessibilityServiceList.implementation = function (feedbackType: number) {
            inc("accessibility_query_count");
            seqPush(SEQ.ACCESSIBILITY);
            return this.getEnabledAccessibilityServiceList(feedbackType);
        };
    });

    // ── 11. Overlay Window ───────────────────────────────────────────────────

    tryHook("WindowManagerImpl.addView (overlay)", () => {
        const WindowManagerImpl = Java.use("android.view.WindowManagerImpl");
        // TYPE_APPLICATION_OVERLAY=2038, TYPE_SYSTEM_OVERLAY=2006, TYPE_SYSTEM_ALERT=2003
        const OVERLAY_TYPES = new Set<number>([2038, 2006, 2003]);
        WindowManagerImpl.addView.overload(
            "android.view.View",
            "android.view.ViewGroup$LayoutParams"
        ).implementation = function (view: any, params: any) {
            if (OVERLAY_TYPES.has(params.type.value as number)) {
                inc("overlay_window_count");
                seqPush(SEQ.OVERLAY);
                console.log(`[OVERLAY] addView type=${params.type.value}`);
            }
            return this.addView(view, params);
        };
    });

    console.log("=== 54 Feature Hook Hazır ===");
});

// ── Otomatik Flush — Java.perform DIŞINDA ────────────────────────────────────
// setInterval Frida'nın kendi event loop'unda çalışır; Java.perform içinde
// kayıt edilirse ART thread'e bağlı kalır ve güvenilir şekilde tetiklenmez.
setInterval(flushCounters, 20000);

// Python'dan "flush" mesajı gelince anlık snapshot
recv("flush", () => {
    flushCounters();
});

// ─── RPC Export — send/recv'e alternatif, doğrudan veri okuma ────────────────
// script.post("flush") + on_message yetersiz kaldığında Python
// script.exports.get_counters() ile anlık veriyi güvenilir şekilde alır.
rpc.exports = {
    getCounters: (): object => ({
        ...counters,
        _timings: { ...timings },
        _burst_peak: burstPeakCount,
        _session_duration_ms: Date.now() - SESSION_START,
        _seq_log: seqLog.slice(),
    }),
};