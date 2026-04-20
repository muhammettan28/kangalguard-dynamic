import Java from "frida-java-bridge";

// ─── Feature Sayaçları ───────────────────────────────────────────────────────

const counters: Record<string, number> = {
    // Java API Calls (8) — mevcut
    reflection_invoke_count: 0,
    dex_class_loader_count: 0,
    runtime_exec_count: 0,
    dynamic_class_load_count: 0,
    getPackageInfo_count: 0,
    sendTextMessage_count: 0,
    getDeviceId_count: 0,
    getSubscriberId_count: 0,

    // Crypto (5) — mevcut
    cipher_init_count: 0,
    cipher_aes_count: 0,
    cipher_des_count: 0,
    secret_key_gen_count: 0,
    base64_encode_count: 0,

    // Anti-Analysis (7) — mevcut
    system_exit_attempt: 0,
    debugger_check_count: 0,
    emulator_check_count: 0,
    root_check_count: 0,
    sleep_call_count: 0,
    stack_trace_inspect_count: 0,
    secure_random_count: 0,

    // Genel Davranış (3) — mevcut
    verify_attempt_count: 0,
    string_decrypt_count: 0,
    native_lib_load_count: 0,

    // Intent & IPC (6) — mevcut
    implicit_intent_count: 0,
    startActivity_count: 0,
    sendBroadcast_count: 0,
    bindService_count: 0,
    content_resolver_query_count: 0,
    content_resolver_insert_count: 0,

    // File System (6) — mevcut
    file_write_count: 0,
    file_read_sensitive_count: 0,
    shared_prefs_write_count: 0,
    openFileOutput_count: 0,
    deleteFile_count: 0,
    getExternalStorageDirectory_count: 0,

    // Network & Socket (5) — mevcut
    socket_create_count: 0,
    url_connection_count: 0,
    ssl_bypass_attempt: 0,
    dns_lookup_count: 0,
    setRequestProperty_count: 0,

    // Persistence & Privilege (5) — mevcut
    alarm_manager_set_count: 0,
    job_scheduler_count: 0,
    register_receiver_count: 0,
    requestPermission_count: 0,
    setComponentEnabled_count: 0,

    // Process & Memory (5) — mevcut
    thread_create_count: 0,
    process_list_query_count: 0,
    memory_alloc_large_count: 0,
    class_loader_parent_count: 0,
    native_method_register_count: 0,

    // Accessibility, Overlay & Clipboard (4) — mevcut
    accessibility_query_count: 0,
    overlay_window_count: 0,
    clipboard_read_count: 0,
    clipboard_write_count: 0,

    // ── Yeni Ham Sayaçlar v4 (25 adet) ──────────────────────────────────────
    http_get_count: 0,
    http_post_count: 0,
    websocket_count: 0,
    ssl_bypass_count: 0,
    aes_encrypt_count: 0,
    rsa_count: 0,
    hash_md5_count: 0,
    hash_sha_count: 0,
    base64_enc_count: 0,
    base64_dec_count: 0,
    location_gps_count: 0,
    location_net_count: 0,
    camera_open_count: 0,
    mic_record_count: 0,
    sms_read_count: 0,
    call_log_count: 0,
    file_delete_count: 0,
    pkg_install_count: 0,
    pkg_enum_count: 0,
    notif_listen_count: 0,
    screen_capture_count: 0,
    input_inject_count: 0,
    acc_action_count: 0,
    acc_window_count: 0,
    foreground_service_count: 0,
};

// ─── Temporal Tracking ───────────────────────────────────────────────────────

const SESSION_START: number = Date.now();

const timings: Record<string, number> = {
    first_network_ms:       -1,
    first_crypto_ms:        -1,
    first_anti_analysis_ms: -1,
    first_file_write_ms:    -1,
    first_reflection_ms:    -1,
    first_exec_ms:          -1,
    first_sms_ms:           -1,
    first_dynamic_load_ms:  -1,
};

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

// ─── Sequence Tracking — 87 granüler tag ─────────────────────────────────────

interface SeqEvent {
    tag:    string;
    ms:     number;
    burst?: number;
}

const seqLog: SeqEvent[] = [];

// Per-tag session limitleri (Section 5a'dan)
const SEQ_TAG_MAX: Record<string, number> = {
    ACC_SERVICE_BIND:   1,
    ACC_ACTION:         20,
    ACC_WINDOW_ACCESS:  10,
    ANALYTICS_LOG:      10,
    NET_HTTP_GET:       30,
    NET_HTTP_POST:      30,
    CRYPTO_AES:         20,
    CRYPTO_BASE64_ENC:  20,
    CRYPTO_BASE64_DEC:  20,
    REFLECT_INVOKE:     15,
    REFLECT_CLASS_LOAD: 15,
    NET_DNS_LOOKUP:     30,
    NET_SOCKET_TCP:     20,
    IPC_SEND_BROADCAST: 15,
    FILE_WRITE_INTERNAL:20,
    FILE_WRITE_EXTERNAL:20,
    SURV_CONTACT_READ:  10,
    PERSIST_ALARM_REP:  15,
};
const SEQ_DEFAULT_MAX = 15;

let seqLastTag: string = "";
let seqLastCount: number = 0;
const seqTagCount: Record<string, number> = {};

function seqPush(tag: string): void {
    const max: number = SEQ_TAG_MAX[tag] !== undefined ? SEQ_TAG_MAX[tag] : SEQ_DEFAULT_MAX;
    const cur: number = seqTagCount[tag] !== undefined ? seqTagCount[tag] : 0;
    if (cur >= max) return;
    seqTagCount[tag] = cur + 1;

    const ms = Date.now() - SESSION_START;

    // Burst tespiti: aynı tag 5+ arka arkaya
    if (seqLastTag === tag) {
        seqLastCount++;
        if (seqLastCount >= 5 && seqLog.length > 0) {
            const last = seqLog[seqLog.length - 1];
            if (last.burst === undefined) last.burst = 4;
            else last.burst++;
            last.ms = ms;
            return;
        }
    } else {
        seqLastTag  = tag;
        seqLastCount = 1;
    }

    seqLog.push({ tag, ms });
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
            _seq_log: seqLog.slice(),
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
    console.log("=== KangalGuard Agent v4 Başladı (87 tag) ===");

    // ── REFLECTION & LOADING ─────────────────────────────────────────────────

    tryHook("Method.invoke (REFLECT_INVOKE)", () => {
        const Method = Java.use("java.lang.reflect.Method");
        Method.invoke.implementation = function (obj: any, args: any) {
            inc("reflection_invoke_count");
            recordTime("first_reflection_ms");
            seqPush("REFLECT_INVOKE");
            return this.invoke(obj, args);
        };
    });

    tryHook("Field.get/set (REFLECT_FIELD_ACCESS + ANTI_EMULATOR via Build)", () => {
        const Field = Java.use("java.lang.reflect.Field");
        Field.get.implementation = function (obj: any) {
            seqPush("REFLECT_FIELD_ACCESS");
            // android.os.SystemProperties @hide fail workaround:
            // Build field reads via reflection = emulator/VM detection pattern
            try {
                if (this.getDeclaringClass().getName() === "android.os.Build") {
                    _vmPropsRead.add(this.getName());
                    if (_vmPropsRead.size >= 3) seqPush("ANTI_VM_PROPS");
                    seqPush("ANTI_EMULATOR");
                }
            } catch (_) {}
            return this.get(obj);
        };
        Field.set.implementation = function (obj: any, value: any) {
            seqPush("REFLECT_FIELD_ACCESS");
            return this.set(obj, value);
        };
    });

    tryHook("Class.forName (REFLECT_CLASS_LOAD)", () => {
        const Class = Java.use("java.lang.Class");
        Class.forName.overload("java.lang.String").implementation = function (name: string) {
            inc("dynamic_class_load_count");
            recordTime("first_dynamic_load_ms");
            seqPush("REFLECT_CLASS_LOAD");
            return this.forName(name);
        };
    });

    tryHook("ClassLoader.loadClass (REFLECT_CLASS_LOAD)", () => {
        const ClassLoader = Java.use("java.lang.ClassLoader");
        ClassLoader.loadClass.overload("java.lang.String").implementation = function (name: string) {
            seqPush("REFLECT_CLASS_LOAD");
            return this.loadClass(name);
        };
    });

    tryHook("DexClassLoader.$init (DEX_LOAD_FILE)", () => {
        const DexClassLoader = Java.use("dalvik.system.DexClassLoader");
        DexClassLoader.$init.implementation = function (
            dexPath: string, optimizedDir: string, libraryPath: string, parent: any
        ) {
            inc("dex_class_loader_count");
            recordTime("first_dynamic_load_ms");
            seqPush("DEX_LOAD_FILE");
            console.log(`[DEX] ${dexPath}`);
            return this.$init(dexPath, optimizedDir, libraryPath, parent);
        };
    });

    tryHook("InMemoryDexClassLoader.$init (DEX_LOAD_MEMORY)", () => {
        const InMemDex = Java.use("dalvik.system.InMemoryDexClassLoader");
        InMemDex.$init.overload("java.nio.ByteBuffer", "java.lang.ClassLoader")
            .implementation = function (dexBuffer: any, parent: any) {
            inc("dex_class_loader_count");
            recordTime("first_dynamic_load_ms");
            seqPush("DEX_LOAD_MEMORY");
            console.log("[DEX] InMemoryDexClassLoader");
            return this.$init(dexBuffer, parent);
        };
    });

    tryHook("System.loadLibrary (NATIVE_LIB_LOAD)", () => {
        const System = Java.use("java.lang.System");
        System.loadLibrary.implementation = function (name: string) {
            inc("native_lib_load_count");
            seqPush("NATIVE_LIB_LOAD");
            console.log(`[NATIVE] loadLibrary: ${name}`);
            return this.loadLibrary(name);
        };
    });

    tryHook("System.load (NATIVE_LIB_LOAD)", () => {
        const System = Java.use("java.lang.System");
        System.load.implementation = function (path: string) {
            inc("native_lib_load_count");
            seqPush("NATIVE_LIB_LOAD");
            console.log(`[NATIVE] load: ${path}`);
            return this.load(path);
        };
    });

    // ── NETWORK ───────────────────────────────────────────────────────────────

    tryHook("HttpURLConnection.setRequestMethod (NET_HTTP_GET/POST)", () => {
        const HttpURLConnection = Java.use("java.net.HttpURLConnection");
        HttpURLConnection.setRequestMethod.implementation = function (method: string) {
            if (method === "GET") {
                inc("http_get_count");
                seqPush("NET_HTTP_GET");
            } else if (method === "POST") {
                inc("http_post_count");
                seqPush("NET_HTTP_POST");
            }
            recordTime("first_network_ms");
            return this.setRequestMethod(method);
        };
    });

    tryHook("URL.openConnection (NET_HTTP_GET)", () => {
        const URL = Java.use("java.net.URL");
        URL.openConnection.overload().implementation = function () {
            inc("url_connection_count");
            recordTime("first_network_ms");
            seqPush("NET_HTTP_GET");
            console.log(`[NET] URL: ${this.toString()}`);
            return this.openConnection();
        };
    });

    tryHook("Socket.$init (NET_SOCKET_TCP)", () => {
        const Socket = Java.use("java.net.Socket");
        Socket.$init.overload("java.lang.String", "int").implementation = function (
            host: string, port: number
        ) {
            inc("socket_create_count");
            recordTime("first_network_ms");
            seqPush("NET_SOCKET_TCP");
            console.log(`[NET] Socket: ${host}:${port}`);
            return this.$init(host, port);
        };
    });

    // new Socket() + socket.connect(addr) pattern'i — Socket.$init(String,int) yakalamaz
    tryHook("Socket.connect (NET_SOCKET_TCP)", () => {
        const Socket = Java.use("java.net.Socket");
        Socket.connect.overload("java.net.SocketAddress").implementation = function (addr: any) {
            inc("socket_create_count");
            recordTime("first_network_ms");
            seqPush("NET_SOCKET_TCP");
            return this.connect(addr);
        };
        Socket.connect.overload("java.net.SocketAddress", "int").implementation = function (
            addr: any, timeout: number
        ) {
            inc("socket_create_count");
            recordTime("first_network_ms");
            seqPush("NET_SOCKET_TCP");
            return this.connect(addr, timeout);
        };
    });

    tryHook("DatagramSocket.send (NET_SOCKET_UDP)", () => {
        const DatagramSocket = Java.use("java.net.DatagramSocket");
        DatagramSocket.send.implementation = function (packet: any) {
            seqPush("NET_SOCKET_UDP");
            return this.send(packet);
        };
    });

    tryHook("InetAddress.getByName (NET_DNS_LOOKUP)", () => {
        const InetAddress = Java.use("java.net.InetAddress");
        InetAddress.getByName.implementation = function (host: string) {
            inc("dns_lookup_count");
            recordTime("first_network_ms");
            seqPush("NET_DNS_LOOKUP");
            console.log(`[NET] DNS: ${host}`);
            return this.getByName(host);
        };
    });

    tryHook("InetAddress.getAllByName (NET_DNS_LOOKUP)", () => {
        const InetAddress = Java.use("java.net.InetAddress");
        InetAddress.getAllByName.implementation = function (host: string) {
            inc("dns_lookup_count");
            recordTime("first_network_ms");
            seqPush("NET_DNS_LOOKUP");
            return this.getAllByName(host);
        };
    });

    tryHook("SSLContext.init (NET_SSL_BYPASS)", () => {
        const SSLContext = Java.use("javax.net.ssl.SSLContext");
        SSLContext.init.implementation = function (km: any, tm: any, sr: any) {
            if (tm !== null) {
                inc("ssl_bypass_attempt");
                inc("ssl_bypass_count");
                seqPush("NET_SSL_BYPASS");
                console.log("[NET] Custom TrustManager — SSL bypass?");
            }
            return this.init(km, tm, sr);
        };
    });

    // OkHttp: modern APK'ların büyük çoğunluğu HttpURLConnection değil OkHttp kullanır.
    // newCall().execute() / enqueue() yerine newCall() hooklamak daha güvenilir —
    // her HTTP isteği için bir kez çağrılır, response gelmeden önce sayılır.
    tryHook("OkHttpClient.newCall (NET_HTTP_GET/POST via OkHttp)", () => {
        const OkHttpClient = Java.use("okhttp3.OkHttpClient");
        OkHttpClient.newCall.implementation = function (request: any) {
            const method: string = request.method();
            if (method === "GET") {
                inc("http_get_count");
                seqPush("NET_HTTP_GET");
            } else if (method === "POST") {
                inc("http_post_count");
                seqPush("NET_HTTP_POST");
            }
            recordTime("first_network_ms");
            return this.newCall(request);
        };
    });

    tryHook("OkHttpClient.newWebSocket (NET_WEBSOCKET)", () => {
        const OkHttpClient = Java.use("okhttp3.OkHttpClient");
        OkHttpClient.newWebSocket.implementation = function (request: any, listener: any) {
            inc("websocket_count");
            seqPush("NET_WEBSOCKET");
            recordTime("first_network_ms");
            console.log("[NET] OkHttpClient.newWebSocket");
            return this.newWebSocket(request, listener);
        };
    });

    tryHook("URLConnection.setRequestProperty", () => {
        const URLConnection = Java.use("java.net.URLConnection");
        URLConnection.setRequestProperty.implementation = function (
            key: string, value: string
        ) {
            inc("setRequestProperty_count");
            return this.setRequestProperty(key, value);
        };
    });

    // ── CRYPTO ────────────────────────────────────────────────────────────────

    // FILE_ENCRYPT_BULK tespiti için session içi AES şifreleme bayrağı
    let _aesEncryptActive = false;

    tryHook("Cipher.init (CRYPTO_AES/RSA)", () => {
        const Cipher = Java.use("javax.crypto.Cipher");
        Cipher.init.overload("int", "java.security.Key").implementation = function (
            opmode: number, key: any
        ) {
            inc("cipher_init_count");
            const algo: string = this.getAlgorithm().toUpperCase();
            if (algo.includes("AES")) {
                inc("cipher_aes_count");
                if (opmode === 1) { // ENCRYPT_MODE=1
                    inc("aes_encrypt_count");
                    _aesEncryptActive = true;
                }
                seqPush("CRYPTO_AES");
            } else if (algo.includes("RSA")) {
                inc("rsa_count");
                seqPush("CRYPTO_RSA");
            }
            recordTime("first_crypto_ms");
            return this.init(opmode, key);
        };
        Cipher.init.overload("int", "java.security.Key", "java.security.spec.AlgorithmParameterSpec")
            .implementation = function (opmode: number, key: any, params: any) {
            inc("cipher_init_count");
            const algo: string = this.getAlgorithm().toUpperCase();
            if (algo.includes("AES")) {
                inc("cipher_aes_count");
                if (opmode === 1) {
                    inc("aes_encrypt_count");
                    _aesEncryptActive = true;
                }
                seqPush("CRYPTO_AES");
            } else if (algo.includes("RSA")) {
                inc("rsa_count");
                seqPush("CRYPTO_RSA");
            }
            recordTime("first_crypto_ms");
            return this.init(opmode, key, params);
        };
    });

    tryHook("MessageDigest.getInstance (CRYPTO_HASH_MD5/SHA)", () => {
        const MessageDigest = Java.use("java.security.MessageDigest");
        MessageDigest.getInstance.overload("java.lang.String").implementation = function (
            algo: string
        ) {
            const up = algo.toUpperCase();
            if (up.includes("MD5")) {
                inc("hash_md5_count");
                seqPush("CRYPTO_HASH_MD5");
            } else if (up.includes("SHA")) {
                inc("hash_sha_count");
                seqPush("CRYPTO_HASH_SHA");
            }
            return this.getInstance(algo);
        };
    });

    tryHook("Base64.encode (CRYPTO_BASE64_ENC)", () => {
        const Base64 = Java.use("android.util.Base64");
        Base64.encode.overload("[B", "int").implementation = function (input: any, flags: number) {
            inc("base64_encode_count");
            inc("base64_enc_count");
            seqPush("CRYPTO_BASE64_ENC");
            return this.encode(input, flags);
        };
        Base64.encodeToString.overload("[B", "int").implementation = function (
            input: any, flags: number
        ) {
            inc("base64_encode_count");
            inc("base64_enc_count");
            seqPush("CRYPTO_BASE64_ENC");
            return this.encodeToString(input, flags);
        };
    });

    tryHook("Base64.decode (CRYPTO_BASE64_DEC)", () => {
        const Base64 = Java.use("android.util.Base64");
        Base64.decode.overload("[B", "int").implementation = function (input: any, flags: number) {
            inc("base64_dec_count");
            seqPush("CRYPTO_BASE64_DEC");
            return this.decode(input, flags);
        };
        Base64.decode.overload("java.lang.String", "int").implementation = function (
            input: string, flags: number
        ) {
            inc("base64_dec_count");
            seqPush("CRYPTO_BASE64_DEC");
            return this.decode(input, flags);
        };
    });

    tryHook("KeyGenerator.generateKey (CRYPTO_KEYGEN)", () => {
        const KeyGenerator = Java.use("javax.crypto.KeyGenerator");
        KeyGenerator.generateKey.implementation = function () {
            inc("secret_key_gen_count");
            seqPush("CRYPTO_KEYGEN");
            return this.generateKey();
        };
    });

    tryHook("KeyPairGenerator.generateKeyPair (CRYPTO_KEYGEN)", () => {
        const KeyPairGenerator = Java.use("java.security.KeyPairGenerator");
        KeyPairGenerator.generateKeyPair.implementation = function () {
            seqPush("CRYPTO_KEYGEN");
            return this.generateKeyPair();
        };
    });

    tryHook("SecureRandom.$init", () => {
        const SecureRandom = Java.use("java.security.SecureRandom");
        SecureRandom.$init.overload().implementation = function () {
            inc("secure_random_count");
            return this.$init();
        };
    });

    // ── SURVEILLANCE ──────────────────────────────────────────────────────────

    tryHook("TelephonyManager.getDeviceId (SURV_DEVICE_ID)", () => {
        const TelephonyManager = Java.use("android.telephony.TelephonyManager");
        TelephonyManager.getDeviceId.overload().implementation = function () {
            inc("getDeviceId_count");
            seqPush("SURV_DEVICE_ID");
            return this.getDeviceId();
        };
    });

    tryHook("TelephonyManager.getSubscriberId (SURV_DEVICE_ID)", () => {
        const TelephonyManager = Java.use("android.telephony.TelephonyManager");
        TelephonyManager.getSubscriberId.overload().implementation = function () {
            inc("getSubscriberId_count");
            seqPush("SURV_DEVICE_ID");
            return this.getSubscriberId();
        };
    });

    tryHook("TelephonyManager.getImei (SURV_DEVICE_ID)", () => {
        const TelephonyManager = Java.use("android.telephony.TelephonyManager");
        TelephonyManager.getImei.overload().implementation = function () {
            inc("getDeviceId_count");
            seqPush("SURV_DEVICE_ID");
            return this.getImei();
        };
    });

    // Modern appler LocationManager değil Google Play Services FusedLocationProviderClient kullanır
    tryHook("FusedLocationProviderClient.getLastLocation (SURV_LOCATION_NET)", () => {
        const FusedClient = Java.use("com.google.android.gms.location.FusedLocationProviderClient");
        FusedClient.getLastLocation.implementation = function () {
            inc("location_net_count");
            seqPush("SURV_LOCATION_NET");
            console.log("[SURV] FusedLocationProviderClient.getLastLocation");
            return this.getLastLocation();
        };
    });

    tryHook("FusedLocationProviderClient.requestLocationUpdates (SURV_LOCATION_NET)", () => {
        const FusedClient = Java.use("com.google.android.gms.location.FusedLocationProviderClient");
        FusedClient.requestLocationUpdates.overload(
            "com.google.android.gms.location.LocationRequest",
            "com.google.android.gms.location.LocationCallback",
            "android.os.Looper"
        ).implementation = function (req: any, cb: any, looper: any) {
            inc("location_net_count");
            seqPush("SURV_LOCATION_NET");
            console.log("[SURV] FusedLocationProviderClient.requestLocationUpdates");
            return this.requestLocationUpdates(req, cb, looper);
        };
    });

    tryHook("LocationManager.requestLocationUpdates (SURV_LOCATION_GPS/NET)", () => {
        const LocationManager = Java.use("android.location.LocationManager");
        LocationManager.requestLocationUpdates.overload(
            "java.lang.String", "long", "float", "android.location.LocationListener"
        ).implementation = function (provider: string, minTime: number, minDist: number, listener: any) {
            if (provider === "gps") {
                inc("location_gps_count");
                seqPush("SURV_LOCATION_GPS");
            } else {
                inc("location_net_count");
                seqPush("SURV_LOCATION_NET");
            }
            return this.requestLocationUpdates(provider, minTime, minDist, listener);
        };
    });

    tryHook("ContentResolver.query (SURV_CONTACT_READ/SMS_READ/CALL_LOG + MEDIA)", () => {
        const ContentResolver = Java.use("android.content.ContentResolver");

        // URI eşleştirme ortak fonksiyon — her iki overload'dan çağrılır
        function classifyQueryUri(uriStr: string): void {
            if (uriStr.includes("contacts") || uriStr.includes("com.android.contacts")) {
                seqPush("SURV_CONTACT_READ");
            } else if (uriStr.includes("content://sms") || uriStr.includes("telephony/sms")) {
                inc("sms_read_count");
                seqPush("SURV_SMS_READ");
            } else if (uriStr.includes("call_log") || uriStr.includes("calls")) {
                inc("call_log_count");
                seqPush("SURV_CALL_LOG");
            } else if (uriStr.includes("images/media") || uriStr.includes("Images/Media")) {
                seqPush("MEDIA_PHOTO_ACCESS");
            } else if (uriStr.includes("video/media") || uriStr.includes("Video/Media")) {
                seqPush("MEDIA_VIDEO_ACCESS");
            }
        }

        // Pre-API29 (5-arg) overload
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
            classifyQueryUri(uri.toString());
            return this.query(uri, proj, sel, selArgs, sort);
        };

        // API29+ (Bundle) overload — Android 10'dan itibaren modern appler bu imzayı kullanır
        ContentResolver.query.overload(
            "android.net.Uri",
            "[Ljava.lang.String;",
            "android.os.Bundle",
            "android.os.CancellationSignal"
        ).implementation = function (
            uri: any, proj: any, queryArgs: any, cancellationSignal: any
        ) {
            inc("content_resolver_query_count");
            classifyQueryUri(uri.toString());
            return this.query(uri, proj, queryArgs, cancellationSignal);
        };
    });

    tryHook("CameraManager.openCamera (SURV_CAMERA)", () => {
        const CameraManager = Java.use("android.hardware.camera2.CameraManager");
        CameraManager.openCamera.implementation = function (
            cameraId: string, callback: any, handler: any
        ) {
            inc("camera_open_count");
            seqPush("SURV_CAMERA");
            console.log(`[SURV] CameraManager.openCamera: ${cameraId}`);
            return this.openCamera(cameraId, callback, handler);
        };
    });

    tryHook("AudioRecord.startRecording (SURV_MIC_RECORD)", () => {
        const AudioRecord = Java.use("android.media.AudioRecord");
        AudioRecord.startRecording.overload().implementation = function () {
            inc("mic_record_count");
            seqPush("SURV_MIC_RECORD");
            console.log("[SURV] AudioRecord.startRecording");
            return this.startRecording();
        };
    });

    tryHook("MediaRecorder.setAudioSource (SURV_MIC_RECORD)", () => {
        const MediaRecorder = Java.use("android.media.MediaRecorder");
        MediaRecorder.setAudioSource.implementation = function (audioSource: number) {
            if (audioSource === 1) { // MIC = 1
                inc("mic_record_count");
                seqPush("SURV_MIC_RECORD");
                console.log("[SURV] MediaRecorder MIC source");
            }
            return this.setAudioSource(audioSource);
        };
    });

    // ── FILE OPERATIONS ───────────────────────────────────────────────────────

    tryHook("FileOutputStream.$init (FILE_WRITE_INTERNAL/EXTERNAL)", () => {
        const FileOutputStream = Java.use("java.io.FileOutputStream");

        function classifyWritePath(path: string): void {
            inc("file_write_count");
            recordTime("first_file_write_ms");
            const extPaths = ["/sdcard/", "/storage/emulated/"];
            const sysPaths = ["/system/", "/data/system/"];
            if (extPaths.some(p => path.startsWith(p))) {
                inc("getExternalStorageDirectory_count");
                seqPush("FILE_WRITE_EXTERNAL");
                // AES encrypt + harici dosya yazımı aynı session'da = ransomware imzası
                if (_aesEncryptActive) {
                    seqPush("FILE_ENCRYPT_BULK");
                    console.log(`[MAL] FILE_ENCRYPT_BULK: ${path}`);
                }
            } else if (sysPaths.some(p => path.startsWith(p))) {
                seqPush("ROOT_PERSIST_SYSTEM");
                console.log(`[FILE] System write attempt: ${path}`);
            } else {
                seqPush("FILE_WRITE_INTERNAL");
            }
            const sensitivePaths = ["/proc/", "/sys/", "/data/"];
            if (sensitivePaths.some(p => path.startsWith(p))) {
                inc("file_read_sensitive_count");
            }
        }

        // String path overload
        FileOutputStream.$init.overload("java.lang.String").implementation = function (
            path: string
        ) {
            classifyWritePath(path);
            return this.$init(path);
        };

        // File object overload — new FileOutputStream(new File(path)) pattern'i yakalar
        FileOutputStream.$init.overload("java.io.File").implementation = function (file: any) {
            try { classifyWritePath(file.getAbsolutePath()); } catch (_) {}
            return this.$init(file);
        };

        // String + append overload
        FileOutputStream.$init.overload("java.lang.String", "boolean").implementation = function (
            path: string, append: boolean
        ) {
            classifyWritePath(path);
            return this.$init(path, append);
        };
    });

    tryHook("FileInputStream.$init (FILE_READ_SENSITIVE)", () => {
        const FileInputStream = Java.use("java.io.FileInputStream");
        FileInputStream.$init.overload("java.lang.String").implementation = function (
            path: string
        ) {
            const sensitivePaths = ["/proc/self/maps", "/proc/self/status", "/system/build.prop"];
            if (sensitivePaths.some(p => path.includes(p))) {
                inc("file_read_sensitive_count");
                seqPush("FILE_READ_SENSITIVE");
                // Frida/Xposed tespiti kontrolü
                if (path.includes("/proc/self/maps")) {
                    seqPush("ANTI_HOOK_DETECT");
                    console.log("[ANTI] /proc/self/maps read — hook detection?");
                }
            }
            return this.$init(path);
        };
    });

    tryHook("File.delete (FILE_DELETE)", () => {
        const File = Java.use("java.io.File");
        File.delete.implementation = function () {
            inc("deleteFile_count");
            inc("file_delete_count");
            seqPush("FILE_DELETE");
            return this.delete();
        };
    });

    tryHook("SharedPreferences.putString (FILE_WRITE_INTERNAL)", () => {
        const Editor = Java.use("android.app.SharedPreferencesImpl$EditorImpl");
        Editor.putString.implementation = function (key: string, value: string) {
            inc("shared_prefs_write_count");
            seqPush("FILE_WRITE_INTERNAL");
            return this.putString(key, value);
        };
    });

    tryHook("ContextWrapper.openFileOutput (FILE_WRITE_INTERNAL)", () => {
        const ContextWrapper = Java.use("android.content.ContextWrapper");
        ContextWrapper.openFileOutput.implementation = function (
            name: string, mode: number
        ) {
            inc("openFileOutput_count");
            seqPush("FILE_WRITE_INTERNAL");
            return this.openFileOutput(name, mode);
        };
    });

    tryHook("Environment.getExternalStorageDirectory", () => {
        const Environment = Java.use("android.os.Environment");
        Environment.getExternalStorageDirectory.implementation = function () {
            inc("getExternalStorageDirectory_count");
            return this.getExternalStorageDirectory();
        };
    });

    // ── EXECUTION ─────────────────────────────────────────────────────────────

    tryHook("Runtime.exec (EXEC_SHELL_CMD/ROOT_CMD)", () => {
        const Runtime = Java.use("java.lang.Runtime");
        Runtime.exec.overload("java.lang.String").implementation = function (cmd: string) {
            inc("runtime_exec_count");
            recordTime("first_exec_ms");
            if (cmd.includes("su") || cmd.startsWith("su ")) {
                seqPush("EXEC_ROOT_CMD");
            } else {
                seqPush("EXEC_SHELL_CMD");
            }
            console.log(`[EXEC] ${cmd}`);
            return this.exec(cmd);
        };
        Runtime.exec.overload("[Ljava.lang.String;").implementation = function (cmds: string[]) {
            inc("runtime_exec_count");
            recordTime("first_exec_ms");
            const joined = cmds.join(" ");
            if (joined.includes("su")) {
                seqPush("EXEC_ROOT_CMD");
            } else {
                seqPush("EXEC_SHELL_CMD");
            }
            console.log(`[EXEC] ${cmds}`);
            return this.exec(cmds);
        };
    });

    tryHook("ProcessBuilder.start (EXEC_SHELL_CMD)", () => {
        const ProcessBuilder = Java.use("java.lang.ProcessBuilder");
        ProcessBuilder.start.implementation = function () {
            inc("runtime_exec_count");
            recordTime("first_exec_ms");
            seqPush("EXEC_SHELL_CMD");
            return this.start();
        };
    });

    // ── PERSISTENCE ───────────────────────────────────────────────────────────

    tryHook("AlarmManager.set (PERSIST_ALARM_REP)", () => {
        const AlarmManager = Java.use("android.app.AlarmManager");
        AlarmManager.set.overload(
            "int", "long", "android.app.PendingIntent"
        ).implementation = function (type: number, triggerAtMillis: number, operation: any) {
            inc("alarm_manager_set_count");
            seqPush("PERSIST_ALARM_REP");
            return this.set(type, triggerAtMillis, operation);
        };
        AlarmManager.set.overload(
            "int", "long", "java.lang.String",
            "android.app.AlarmManager$OnAlarmListener", "android.os.Handler"
        ).implementation = function (
            type: number, triggerAtMillis: number, tag: string, listener: any, handler: any
        ) {
            inc("alarm_manager_set_count");
            seqPush("PERSIST_ALARM_REP");
            return this.set(type, triggerAtMillis, tag, listener, handler);
        };
    });

    tryHook("AlarmManager.setExact (PERSIST_ALARM_REP)", () => {
        const AlarmManager = Java.use("android.app.AlarmManager");
        AlarmManager.setExact.overload(
            "int", "long", "android.app.PendingIntent"
        ).implementation = function (type: number, triggerAtMillis: number, op: any) {
            inc("alarm_manager_set_count");
            seqPush("PERSIST_ALARM_REP");
            return this.setExact(type, triggerAtMillis, op);
        };
    });

    tryHook("AlarmManager.setExactAndAllowWhileIdle (PERSIST_ALARM_REP)", () => {
        const AlarmManager = Java.use("android.app.AlarmManager");
        AlarmManager.setExactAndAllowWhileIdle.overload(
            "int", "long", "android.app.PendingIntent"
        ).implementation = function (type: number, triggerAtMillis: number, op: any) {
            inc("alarm_manager_set_count");
            seqPush("PERSIST_ALARM_REP");
            return this.setExactAndAllowWhileIdle(type, triggerAtMillis, op);
        };
    });

    tryHook("AlarmManager.setRepeating (PERSIST_ALARM_REP)", () => {
        const AlarmManager = Java.use("android.app.AlarmManager");
        AlarmManager.setRepeating.implementation = function (
            type: number, triggerAtMillis: number, intervalMillis: number, operation: any
        ) {
            inc("alarm_manager_set_count");
            seqPush("PERSIST_ALARM_REP");
            return this.setRepeating(type, triggerAtMillis, intervalMillis, operation);
        };
    });

    // JobScheduler interface'ini hooklamak çalışmaz; JobInfo.Builder.build() public class
    tryHook("JobInfo$Builder.build (PERSIST_JOB_SCHED)", () => {
        const JobInfoBuilder = Java.use("android.app.job.JobInfo$Builder");
        JobInfoBuilder.build.implementation = function () {
            inc("job_scheduler_count");
            seqPush("PERSIST_JOB_SCHED");
            return this.build();
        };
    });

    tryHook("ContextWrapper.registerReceiver (PERSIST_BOOT_RECV)", () => {
        const ContextWrapper = Java.use("android.content.ContextWrapper");
        ContextWrapper.registerReceiver.overload(
            "android.content.BroadcastReceiver",
            "android.content.IntentFilter"
        ).implementation = function (receiver: any, filter: any) {
            inc("register_receiver_count");
            seqPush("PERSIST_BOOT_RECV");
            return this.registerReceiver(receiver, filter);
        };
    });

    tryHook("Context.startForegroundService (PERSIST_FG_SERVICE)", () => {
        const ContextWrapper = Java.use("android.content.ContextWrapper");
        ContextWrapper.startForegroundService.implementation = function (intent: any) {
            inc("foreground_service_count");
            seqPush("PERSIST_FG_SERVICE");
            console.log("[PERSIST] startForegroundService");
            return this.startForegroundService(intent);
        };
    });

    // ── ANTI-ANALYSIS ─────────────────────────────────────────────────────────

    tryHook("System.exit (bypass + ANTI_DEBUG)", () => {
        const System = Java.use("java.lang.System");
        System.exit.implementation = function (code: number) {
            inc("system_exit_attempt");
            recordTime("first_anti_analysis_ms");
            seqPush("ANTI_DEBUG");
            console.log(`[ANTI] System.exit(${code}) engellendi`);
        };
    });

    tryHook("Process.killProcess (bypass + ANTI_DEBUG)", () => {
        const Process = Java.use("android.os.Process");
        Process.killProcess.implementation = function (pid: number) {
            const myPid: number = Process.myPid();
            if (pid === myPid) {
                inc("system_exit_attempt");
                recordTime("first_anti_analysis_ms");
                seqPush("ANTI_DEBUG");
                console.log("[ANTI] Process.killProcess(self) engellendi");
            } else {
                this.killProcess(pid);
            }
        };
    });

    tryHook("Runtime.halt (bypass + ANTI_DEBUG)", () => {
        const Runtime = Java.use("java.lang.Runtime");
        Runtime.halt.implementation = function (code: number) {
            inc("system_exit_attempt");
            recordTime("first_anti_analysis_ms");
            seqPush("ANTI_DEBUG");
            console.log(`[ANTI] Runtime.halt(${code}) engellendi`);
        };
    });

    tryHook("Debug.isDebuggerConnected (bypass + ANTI_DEBUG)", () => {
        const Debug = Java.use("android.os.Debug");
        Debug.isDebuggerConnected.implementation = function () {
            inc("debugger_check_count");
            recordTime("first_anti_analysis_ms");
            seqPush("ANTI_DEBUG");
            return false;
        };
    });

    tryHook("Debug.waitingForDebugger (bypass + ANTI_DEBUG)", () => {
        const Debug = Java.use("android.os.Debug");
        Debug.waitingForDebugger.implementation = function () {
            inc("debugger_check_count");
            seqPush("ANTI_DEBUG");
            return false;
        };
    });

    // ANTI_VM_PROPS: 3+ farklı ro.* okuma = VM detection serisi
    const _vmPropsRead = new Set<string>();
    tryHook("SystemProperties.get (ANTI_VM_PROPS/ANTI_EMULATOR)", () => {
        const SystemProperties = Java.use("android.os.SystemProperties");
        SystemProperties.get.overload("java.lang.String").implementation = function (key: string) {
            const emulatorKeys = [
                "ro.product.model", "ro.build.fingerprint", "ro.hardware",
                "ro.product.device", "ro.product.brand", "ro.kernel.qemu"
            ];
            if (emulatorKeys.includes(key)) {
                inc("emulator_check_count");
                _vmPropsRead.add(key);
                if (_vmPropsRead.size >= 3) {
                    seqPush("ANTI_VM_PROPS");
                }
            }
            return this.get(key);
        };
    });

    tryHook("File.exists (ANTI_ROOT_CHECK + ANTI_HOOK_DETECT + ANTI_EMULATOR)", () => {
        const File = Java.use("java.io.File");
        const rootPaths = [
            "/system/app/Superuser.apk", "/sbin/su", "/system/bin/su",
            "/system/xbin/su", "/data/local/xbin/su", "/data/local/bin/su",
            "/system/sd/xbin/su", "/data/local/su"
        ];
        // contains() ile kontrol — "frida-server" gibi uzantılı yolları da yakalar
        const fridaPaths = [
            "/data/local/tmp/frida", "/data/local/tmp/re.frida"
        ];
        // Emülatöre özgü soket/pipe yolları
        const emulatorPaths = [
            "/dev/socket/qemud", "/dev/qemu_pipe", "/dev/goldfish_pipe"
        ];
        File.exists.implementation = function () {
            const path: string = this.getAbsolutePath();
            if (rootPaths.some(p => path.includes(p))) {
                inc("root_check_count");
                recordTime("first_anti_analysis_ms");
                seqPush("ANTI_ROOT_CHECK");
                console.log(`[ANTI] Root check: ${path}`);
                return false;
            }
            if (fridaPaths.some(p => path.includes(p))) {
                seqPush("ANTI_HOOK_DETECT");
                console.log(`[ANTI] Frida path check: ${path}`);
                return false;
            }
            if (emulatorPaths.some(p => path.includes(p))) {
                inc("emulator_check_count");
                recordTime("first_anti_analysis_ms");
                seqPush("ANTI_EMULATOR");
                console.log(`[ANTI] Emulator path check: ${path}`);
                return false;
            }
            return this.exists();
        };
    });

    tryHook("RootBeer.isRooted (ROOT_HIDE)", () => {
        const RootBeer = Java.use("com.scottyab.rootbeer.RootBeer");
        RootBeer.isRooted.implementation = function () {
            seqPush("ROOT_HIDE");
            console.log("[MAL] RootBeer.isRooted — root hide detection");
            return false;
        };
    });

    tryHook("RootBeer.isRootedWithoutBusyBox (ROOT_HIDE)", () => {
        const RootBeer = Java.use("com.scottyab.rootbeer.RootBeer");
        RootBeer.isRootedWithoutBusyBox.implementation = function () {
            seqPush("ROOT_HIDE");
            console.log("[MAL] RootBeer.isRootedWithoutBusyBox");
            return false;
        };
    });

    tryHook("Thread.sleep (ANTI_SLEEP_LONG)", () => {
        const Thread = Java.use("java.lang.Thread");
        Thread.sleep.overload("long").implementation = function (ms: number) {
            if (ms > 3000) {
                inc("sleep_call_count");
                seqPush("ANTI_SLEEP_LONG");
                console.log(`[ANTI] Thread.sleep(${ms}ms)`);
            }
            return this.sleep(ms);
        };
    });

    tryHook("Thread.getStackTrace (anti-analysis)", () => {
        const Thread = Java.use("java.lang.Thread");
        Thread.getStackTrace.implementation = function () {
            inc("stack_trace_inspect_count");
            return this.getStackTrace();
        };
    });

    // ── PACKAGE MANAGEMENT ────────────────────────────────────────────────────

    tryHook("PackageManager.getInstalledPackages (PKG_ENUMERATE)", () => {
        const PackageManager = Java.use("android.app.ApplicationPackageManager");
        PackageManager.getInstalledPackages.overload("int").implementation = function (
            flags: number
        ) {
            inc("pkg_enum_count");
            seqPush("PKG_ENUMERATE");
            return this.getInstalledPackages(flags);
        };
    });

    tryHook("PackageManager.getInstalledApplications (PKG_ENUMERATE)", () => {
        const PackageManager = Java.use("android.app.ApplicationPackageManager");
        PackageManager.getInstalledApplications.overload("int").implementation = function (
            flags: number
        ) {
            inc("pkg_enum_count");
            seqPush("PKG_ENUMERATE");
            return this.getInstalledApplications(flags);
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

    tryHook("PackageManager.setComponentEnabledSetting (PKG_DISABLE)", () => {
        const PackageManager = Java.use("android.app.ApplicationPackageManager");
        PackageManager.setComponentEnabledSetting.implementation = function (
            comp: any, newState: number, flags: number
        ) {
            inc("setComponentEnabled_count");
            if (newState === 2) { // COMPONENT_ENABLED_STATE_DISABLED = 2
                seqPush("PKG_DISABLE");
                console.log(`[PKG] Disable: ${comp}`);
            }
            return this.setComponentEnabledSetting(comp, newState, flags);
        };
    });

    // ── IPC ───────────────────────────────────────────────────────────────────

    tryHook("ContextWrapper.sendBroadcast (IPC_SEND_BROADCAST)", () => {
        const ContextWrapper = Java.use("android.content.ContextWrapper");
        ContextWrapper.sendBroadcast.overload(
            "android.content.Intent"
        ).implementation = function (intent: any) {
            inc("sendBroadcast_count");
            seqPush("IPC_SEND_BROADCAST");
            return this.sendBroadcast(intent);
        };
    });

    tryHook("ContextWrapper.sendOrderedBroadcast (IPC_SEND_BROADCAST)", () => {
        const ContextWrapper = Java.use("android.content.ContextWrapper");
        ContextWrapper.sendOrderedBroadcast.overload(
            "android.content.Intent", "java.lang.String"
        ).implementation = function (intent: any, receiverPermission: any) {
            inc("sendBroadcast_count");
            seqPush("IPC_SEND_BROADCAST");
            return this.sendOrderedBroadcast(intent, receiverPermission);
        };
    });

    tryHook("ContextWrapper.bindService (IPC_BIND_SERVICE)", () => {
        const ContextWrapper = Java.use("android.content.ContextWrapper");
        ContextWrapper.bindService.overload(
            "android.content.Intent",
            "android.content.ServiceConnection",
            "int"
        ).implementation = function (intent: any, conn: any, flags: number) {
            inc("bindService_count");
            seqPush("IPC_BIND_SERVICE");
            return this.bindService(intent, conn, flags);
        };
    });

    tryHook("Activity.startActivity (IPC_IMPLICIT_INTENT)", () => {
        const Activity = Java.use("android.app.Activity");
        Activity.startActivity.overload(
            "android.content.Intent"
        ).implementation = function (intent: any) {
            inc("startActivity_count");
            // Component null ise implicit intent
            if (intent.getComponent() === null) {
                seqPush("IPC_IMPLICIT_INTENT");
            }
            return this.startActivity(intent);
        };
    });

    tryHook("Intent.setAction (implicit_intent + SOCIAL_SHARE + PHONE_CALL_SILENT + PERM_ADMIN_REQ)", () => {
        const Intent = Java.use("android.content.Intent");
        Intent.setAction.implementation = function (action: string) {
            inc("implicit_intent_count");
            if (action === "android.intent.action.SEND" ||
                action === "android.intent.action.SEND_MULTIPLE") {
                seqPush("SOCIAL_SHARE");
            } else if (action === "android.intent.action.CALL" ||
                       action === "android.intent.action.CALL_PRIVILEGED") {
                seqPush("PHONE_CALL_SILENT");
                console.log(`[MAL] Intent ACTION_CALL`);
            } else if (action === "android.app.action.ADD_DEVICE_ADMIN" ||
                       action === "android.intent.action.ADD_DEVICE_ADMIN") {
                seqPush("PERM_ADMIN_REQ");
                console.log(`[MAL] Intent ADD_DEVICE_ADMIN`);
            }
            return this.setAction(action);
        };
    });

    tryHook("ContentResolver.insert", () => {
        const ContentResolver = Java.use("android.content.ContentResolver");
        ContentResolver.insert.overload(
            "android.net.Uri",
            "android.content.ContentValues"
        ).implementation = function (uri: any, values: any) {
            inc("content_resolver_insert_count");
            return this.insert(uri, values);
        };
    });

    // ── BROADCAST RECEIVER (BCAST_SMS_INTERCEPT / BCAST_SCREEN_WAKE) ─────────

    tryHook("BroadcastReceiver.onReceive (BCAST_SMS_INTERCEPT + BCAST_SCREEN_WAKE)", () => {
        const BroadcastReceiver = Java.use("android.content.BroadcastReceiver");
        BroadcastReceiver.onReceive.implementation = function (ctx: any, intent: any) {
            try {
                const action: string = intent.getAction();
                if (action === "android.provider.Telephony.SMS_RECEIVED" ||
                    action === "android.intent.action.DATA_SMS_RECEIVED") {
                    seqPush("BCAST_SMS_INTERCEPT");
                    console.log("[MAL] SMS broadcast intercepted");
                } else if (action === "android.intent.action.SCREEN_ON") {
                    seqPush("BCAST_SCREEN_WAKE");
                    console.log("[MAL] SCREEN_ON broadcast received");
                }
            } catch (_) {}
            return this.onReceive(ctx, intent);
        };
    });

    // ── CLIPBOARD ─────────────────────────────────────────────────────────────

    tryHook("ClipboardManager.getPrimaryClip (CLIPBOARD_ACCESS)", () => {
        const ClipboardManager = Java.use("android.content.ClipboardManager");
        ClipboardManager.getPrimaryClip.implementation = function () {
            inc("clipboard_read_count");
            seqPush("CLIPBOARD_ACCESS");
            return this.getPrimaryClip();
        };
    });

    tryHook("ClipboardManager.setPrimaryClip (CLIPBOARD_ACCESS)", () => {
        const ClipboardManager = Java.use("android.content.ClipboardManager");
        ClipboardManager.setPrimaryClip.implementation = function (clip: any) {
            inc("clipboard_write_count");
            seqPush("CLIPBOARD_ACCESS");
            console.log("[CLIP] setPrimaryClip");
            return this.setPrimaryClip(clip);
        };
    });

    // ── OVERLAY WINDOW ────────────────────────────────────────────────────────

    tryHook("WindowManagerImpl.addView (OVERLAY_WINDOW pre-API26)", () => {
        const WindowManagerImpl = Java.use("android.view.WindowManagerImpl");
        const OVERLAY_TYPES = new Set<number>([2038, 2006, 2003]);
        WindowManagerImpl.addView.overload(
            "android.view.View",
            "android.view.ViewGroup$LayoutParams"
        ).implementation = function (view: any, params: any) {
            if (OVERLAY_TYPES.has(params.type.value as number)) {
                inc("overlay_window_count");
                seqPush("OVERLAY_WINDOW");
                console.log(`[OVERLAY] WindowManagerImpl.addView type=${params.type.value}`);
            }
            return this.addView(view, params);
        };
    });

    // Android 8+ (API 26): WindowManagerImpl.addView → WindowManagerGlobal.addView'e delegate edilir
    tryHook("WindowManagerGlobal.addView (OVERLAY_WINDOW API26+)", () => {
        const WindowManagerGlobal = Java.use("android.view.WindowManagerGlobal");
        const OVERLAY_TYPES = new Set<number>([2038, 2006, 2003]);
        WindowManagerGlobal.addView.overload(
            "android.view.View",
            "android.view.ViewGroup$LayoutParams",
            "android.view.Display",
            "android.view.Window"
        ).implementation = function (view: any, params: any, display: any, parentWindow: any) {
            if (OVERLAY_TYPES.has(params.type.value as number)) {
                inc("overlay_window_count");
                seqPush("OVERLAY_WINDOW");
                console.log(`[OVERLAY] WindowManagerGlobal.addView type=${params.type.value}`);
            }
            return this.addView(view, params, display, parentWindow);
        };
    });

    // ── ACCESSIBILITY (flood önleme kuralları ile) ────────────────────────────

    // isEnabled() her app tarafından çağrılır (kontrol amaçlı), malware sinyali değil.
    // onServiceConnected() sadece AccessibilityService subclass'ı aktifleşince çağrılır.
    tryHook("AccessibilityManager.isEnabled (accessibility_query_count only)", () => {
        const AccessibilityManager = Java.use("android.view.accessibility.AccessibilityManager");
        AccessibilityManager.isEnabled.implementation = function () {
            inc("accessibility_query_count");
            // ACC_SERVICE_BIND push edilmez — yanlış pozitif üretirdi
            return this.isEnabled();
        };
    });

    tryHook("AccessibilityService.onServiceConnected (ACC_SERVICE_BIND)", () => {
        const AccessibilityService = Java.use("android.accessibilityservice.AccessibilityService");
        AccessibilityService.onServiceConnected.implementation = function () {
            // Sadece 1 kez loglanır (SEQ_TAG_MAX['ACC_SERVICE_BIND'] = 1)
            seqPush("ACC_SERVICE_BIND");
            console.log("[ACC] AccessibilityService.onServiceConnected");
            return this.onServiceConnected();
        };
    });

    tryHook("AccessibilityNodeInfo.performAction (ACC_ACTION)", () => {
        const AccessibilityNodeInfo = Java.use("android.view.accessibility.AccessibilityNodeInfo");
        AccessibilityNodeInfo.performAction.overload("int").implementation = function (action: number) {
            inc("acc_action_count");
            seqPush("ACC_ACTION");
            return this.performAction(action);
        };
    });

    tryHook("AccessibilityService.getRootInActiveWindow (ACC_WINDOW_ACCESS)", () => {
        const AccessibilityService = Java.use("android.accessibilityservice.AccessibilityService");
        AccessibilityService.getRootInActiveWindow.implementation = function () {
            inc("acc_window_count");
            seqPush("ACC_WINDOW_ACCESS");
            return this.getRootInActiveWindow();
        };
    });

    tryHook("AccessibilityService.getWindows (ACC_WINDOW_ACCESS)", () => {
        const AccessibilityService = Java.use("android.accessibilityservice.AccessibilityService");
        AccessibilityService.getWindows.implementation = function () {
            inc("acc_window_count");
            seqPush("ACC_WINDOW_ACCESS");
            return this.getWindows();
        };
    });

    // ── MALWARE-EXCLUSIVE: Screen Capture ─────────────────────────────────────

    tryHook("MediaProjectionManager.getMediaProjection (SCREEN_CAPTURE)", () => {
        const MediaProjectionManager = Java.use("android.media.projection.MediaProjectionManager");
        MediaProjectionManager.getMediaProjection.implementation = function (
            resultCode: number, resultData: any
        ) {
            inc("screen_capture_count");
            seqPush("SCREEN_CAPTURE");
            console.log("[MAL] MediaProjectionManager.getMediaProjection");
            return this.getMediaProjection(resultCode, resultData);
        };
    });

    // ── MALWARE-EXCLUSIVE: Input Injection ────────────────────────────────────

    tryHook("AccessibilityService.dispatchGesture (INPUT_INJECT)", () => {
        const AccessibilityService = Java.use("android.accessibilityservice.AccessibilityService");
        AccessibilityService.dispatchGesture.implementation = function (
            gesture: any, callback: any, handler: any
        ) {
            inc("input_inject_count");
            seqPush("INPUT_INJECT");
            console.log("[MAL] dispatchGesture");
            return this.dispatchGesture(gesture, callback, handler);
        };
    });

    // ── MALWARE-EXCLUSIVE: Key Logging ────────────────────────────────────────

    tryHook("InputMethodService.onKeyDown (KEYLOG)", () => {
        const InputMethodService = Java.use("android.inputmethodservice.InputMethodService");
        InputMethodService.onKeyDown.implementation = function (keyCode: number, event: any) {
            seqPush("KEYLOG");
            console.log(`[MAL] InputMethodService.onKeyDown keyCode=${keyCode}`);
            return this.onKeyDown(keyCode, event);
        };
    });

    tryHook("InputMethodService.onKeyUp (KEYLOG)", () => {
        const InputMethodService = Java.use("android.inputmethodservice.InputMethodService");
        InputMethodService.onKeyUp.implementation = function (keyCode: number, event: any) {
            seqPush("KEYLOG");
            return this.onKeyUp(keyCode, event);
        };
    });

    tryHook("KeyEvent.getUnicodeChar (KEYLOG)", () => {
        const KeyEvent = Java.use("android.view.KeyEvent");
        KeyEvent.getUnicodeChar.overload().implementation = function () {
            seqPush("KEYLOG");
            return this.getUnicodeChar();
        };
    });

    // ── MALWARE-EXCLUSIVE: PKG Install ────────────────────────────────────────

    tryHook("PackageInstaller.Session.commit (PKG_INSTALL)", () => {
        const Session = Java.use("android.content.pm.PackageInstaller$Session");
        Session.commit.implementation = function (statusReceiver: any) {
            inc("pkg_install_count");
            seqPush("PKG_INSTALL");
            console.log("[MAL] PackageInstaller.Session.commit");
            return this.commit(statusReceiver);
        };
    });

    // ── MALWARE-EXCLUSIVE: Notification Listener ──────────────────────────────

    tryHook("NotificationListenerService.onNotificationPosted (NOTIF_LISTEN)", () => {
        const NotificationListenerService = Java.use(
            "android.service.notification.NotificationListenerService"
        );
        NotificationListenerService.onNotificationPosted.overload(
            "android.service.notification.StatusBarNotification"
        ).implementation = function (sbn: any) {
            inc("notif_listen_count");
            seqPush("NOTIF_LISTEN");
            console.log("[MAL] onNotificationPosted");
            return this.onNotificationPosted(sbn);
        };
    });

    // ── MALWARE-EXCLUSIVE: Phone State ────────────────────────────────────────

    tryHook("TelephonyManager.listen (PHONE_STATE_LISTEN)", () => {
        const TelephonyManager = Java.use("android.telephony.TelephonyManager");
        TelephonyManager.listen.implementation = function (listener: any, events: number) {
            if (events !== 0) { // 0 = LISTEN_NONE
                seqPush("PHONE_STATE_LISTEN");
                console.log(`[MAL] TelephonyManager.listen events=${events}`);
            }
            return this.listen(listener, events);
        };
    });

    // API 31+ (Android 12): TelephonyManager.listen() deprecated, registerTelephonyCallback() ile değiştirildi
    tryHook("TelephonyManager.registerTelephonyCallback (PHONE_STATE_LISTEN)", () => {
        const TelephonyManager = Java.use("android.telephony.TelephonyManager");
        TelephonyManager.registerTelephonyCallback.overload(
            "java.util.concurrent.Executor",
            "android.telephony.TelephonyCallback"
        ).implementation = function (executor: any, callback: any) {
            seqPush("PHONE_STATE_LISTEN");
            console.log("[MAL] TelephonyManager.registerTelephonyCallback");
            return this.registerTelephonyCallback(executor, callback);
        };
    });

    // ── MALWARE-EXCLUSIVE: Device Admin ───────────────────────────────────────

    tryHook("DevicePolicyManager.addUserRestriction (PERM_ADMIN_REQ)", () => {
        const DevicePolicyManager = Java.use("android.app.admin.DevicePolicyManager");
        DevicePolicyManager.addUserRestriction.implementation = function (
            admin: any, key: string
        ) {
            seqPush("PERM_ADMIN_REQ");
            console.log(`[MAL] DevicePolicyManager.addUserRestriction: ${key}`);
            return this.addUserRestriction(admin, key);
        };
    });

    // ── MALWARE-EXCLUSIVE: Account Token Steal ────────────────────────────────

    tryHook("AccountManager.getAuthToken (ACCOUNT_TOKEN_STEAL)", () => {
        const AccountManager = Java.use("android.accounts.AccountManager");
        AccountManager.getAuthToken.overload(
            "android.accounts.Account", "java.lang.String",
            "android.os.Bundle", "android.app.Activity",
            "android.accounts.AccountManagerCallback", "android.os.Handler"
        ).implementation = function (
            account: any, authTokenType: string, options: any,
            activity: any, callback: any, handler: any
        ) {
            seqPush("ACCOUNT_TOKEN_STEAL");
            console.log(`[MAL] AccountManager.getAuthToken: ${authTokenType}`);
            return this.getAuthToken(account, authTokenType, options, activity, callback, handler);
        };
    });

    tryHook("AccountManager.peekAuthToken (ACCOUNT_TOKEN_STEAL)", () => {
        const AccountManager = Java.use("android.accounts.AccountManager");
        AccountManager.peekAuthToken.implementation = function (account: any, authTokenType: string) {
            seqPush("ACCOUNT_TOKEN_STEAL");
            console.log(`[MAL] AccountManager.peekAuthToken: ${authTokenType}`);
            return this.peekAuthToken(account, authTokenType);
        };
    });

    tryHook("AccountManager.getPassword (ACCOUNT_TOKEN_STEAL)", () => {
        const AccountManager = Java.use("android.accounts.AccountManager");
        AccountManager.getPassword.implementation = function (account: any) {
            seqPush("ACCOUNT_TOKEN_STEAL");
            console.log("[MAL] AccountManager.getPassword");
            return this.getPassword(account);
        };
    });

    // ── MALWARE-EXCLUSIVE: KeyStore Exfil ─────────────────────────────────────

    tryHook("KeyStore.load (KEYSTORE_EXFIL)", () => {
        const KeyStore = Java.use("java.security.KeyStore");
        KeyStore.load.overload("java.io.InputStream", "[C").implementation = function (
            stream: any, password: any
        ) {
            seqPush("KEYSTORE_EXFIL");
            console.log("[MAL] KeyStore.load");
            return this.load(stream, password);
        };
    });

    tryHook("KeyStore.getEntry (KEYSTORE_EXFIL)", () => {
        const KeyStore = Java.use("java.security.KeyStore");
        KeyStore.getEntry.implementation = function (alias: string, param: any) {
            seqPush("KEYSTORE_EXFIL");
            console.log(`[MAL] KeyStore.getEntry: ${alias}`);
            return this.getEntry(alias, param);
        };
    });

    tryHook("KeyStore.getKey (KEYSTORE_EXFIL)", () => {
        const KeyStore = Java.use("java.security.KeyStore");
        KeyStore.getKey.implementation = function (alias: string, password: any) {
            seqPush("KEYSTORE_EXFIL");
            console.log(`[MAL] KeyStore.getKey: ${alias}`);
            return this.getKey(alias, password);
        };
    });

    // ── MALWARE-EXCLUSIVE: WebView JS ─────────────────────────────────────────

    tryHook("WebView.addJavascriptInterface (WEBVIEW_JS_BRIDGE)", () => {
        const WebView = Java.use("android.webkit.WebView");
        WebView.addJavascriptInterface.implementation = function (
            obj: any, name: string
        ) {
            seqPush("WEBVIEW_JS_BRIDGE");
            console.log(`[MAL] WebView.addJavascriptInterface: ${name}`);
            return this.addJavascriptInterface(obj, name);
        };
    });

    tryHook("WebView.loadUrl (WEBVIEW_JS_EXEC)", () => {
        const WebView = Java.use("android.webkit.WebView");
        WebView.loadUrl.overload("java.lang.String").implementation = function (url: string) {
            if (url.startsWith("javascript:")) {
                seqPush("WEBVIEW_JS_EXEC");
                console.log(`[MAL] WebView.loadUrl javascript:`);
            }
            return this.loadUrl(url);
        };
    });

    tryHook("WebView.evaluateJavascript (WEBVIEW_JS_EXEC)", () => {
        const WebView = Java.use("android.webkit.WebView");
        WebView.evaluateJavascript.implementation = function (
            script: string, callback: any
        ) {
            seqPush("WEBVIEW_JS_EXEC");
            console.log("[MAL] WebView.evaluateJavascript");
            return this.evaluateJavascript(script, callback);
        };
    });

    // ── MALWARE-EXCLUSIVE: InMemory DEX (ayrıca DEX_LOAD_MEMORY yukarıda) ─────

    // ── MALWARE-EXCLUSIVE: SMS ────────────────────────────────────────────────

    tryHook("SmsManager.sendTextMessage", () => {
        const SmsManager = Java.use("android.telephony.SmsManager");
        SmsManager.sendTextMessage.overload(
            "java.lang.String", "java.lang.String", "java.lang.String",
            "android.app.PendingIntent", "android.app.PendingIntent"
        ).implementation = function (
            dest: string, src: any, text: string, sent: any, delivery: any
        ) {
            inc("sendTextMessage_count");
            recordTime("first_sms_ms");
            console.log(`[SMS] ${dest}: ${text}`);
            return this.sendTextMessage(dest, src, text, sent, delivery);
        };
        SmsManager.sendTextMessage.overload(
            "java.lang.String", "java.lang.String", "java.lang.String",
            "android.app.PendingIntent", "android.app.PendingIntent", "long"
        ).implementation = function (
            dest: string, src: any, text: string, sent: any, delivery: any, messageId: number
        ) {
            inc("sendTextMessage_count");
            recordTime("first_sms_ms");
            console.log(`[SMS] ${dest}: ${text}`);
            return this.sendTextMessage(dest, src, text, sent, delivery, messageId);
        };
    });

    // ── MALWARE-EXCLUSIVE: Phone Call ─────────────────────────────────────────

    tryHook("TelecomManager.placeCall (PHONE_CALL_SILENT)", () => {
        const TelecomManager = Java.use("android.telecom.TelecomManager");
        TelecomManager.placeCall.implementation = function (address: any, extras: any) {
            seqPush("PHONE_CALL_SILENT");
            console.log(`[MAL] TelecomManager.placeCall: ${address}`);
            return this.placeCall(address, extras);
        };
    });

    // ── BENIGN-EXCLUSIVE: Ads SDK ─────────────────────────────────────────────

    tryHook("MobileAds.initialize (ADS_SDK_INIT)", () => {
        const MobileAds = Java.use("com.google.android.gms.ads.MobileAds");
        MobileAds.initialize.overload(
            "android.content.Context"
        ).implementation = function (ctx: any) {
            seqPush("ADS_SDK_INIT");
            console.log("[BEN] MobileAds.initialize");
            return this.initialize(ctx);
        };
    });

    tryHook("MoPub.initializeSdk (ADS_SDK_INIT)", () => {
        const MoPub = Java.use("com.mopub.mobileads.MoPub");
        MoPub.initializeSdk.implementation = function (ctx: any, config: any, listener: any) {
            seqPush("ADS_SDK_INIT");
            return this.initializeSdk(ctx, config, listener);
        };
    });

    // ── BENIGN-EXCLUSIVE: Analytics ───────────────────────────────────────────

    tryHook("FirebaseAnalytics.logEvent (ANALYTICS_LOG)", () => {
        const FirebaseAnalytics = Java.use("com.google.firebase.analytics.FirebaseAnalytics");
        FirebaseAnalytics.logEvent.implementation = function (
            name: string, params: any
        ) {
            seqPush("ANALYTICS_LOG");
            return this.logEvent(name, params);
        };
    });

    tryHook("MixpanelAPI.track (ANALYTICS_LOG)", () => {
        const MixpanelAPI = Java.use("com.mixpanel.android.mpmetrics.MixpanelAPI");
        MixpanelAPI.track.overload("java.lang.String", "org.json.JSONObject")
            .implementation = function (event: string, props: any) {
            seqPush("ANALYTICS_LOG");
            return this.track(event, props);
        };
    });

    // ── BENIGN-EXCLUSIVE: Crash Report ────────────────────────────────────────

    tryHook("FirebaseCrashlytics.recordException (CRASH_REPORT)", () => {
        const Crashlytics = Java.use("com.google.firebase.crashlytics.FirebaseCrashlytics");
        Crashlytics.recordException.implementation = function (throwable: any) {
            seqPush("CRASH_REPORT");
            return this.recordException(throwable);
        };
    });

    tryHook("Sentry.captureException (CRASH_REPORT)", () => {
        const Sentry = Java.use("io.sentry.Sentry");
        Sentry.captureException.overload("java.lang.Throwable")
            .implementation = function (throwable: any) {
            seqPush("CRASH_REPORT");
            return this.captureException(throwable);
        };
    });

    // ── BENIGN-EXCLUSIVE: In-App Purchase ────────────────────────────────────

    tryHook("BillingClient.launchBillingFlow (IN_APP_PURCHASE)", () => {
        const BillingClient = Java.use("com.android.billingclient.api.BillingClient");
        BillingClient.launchBillingFlow.implementation = function (
            activity: any, params: any
        ) {
            seqPush("IN_APP_PURCHASE");
            console.log("[BEN] BillingClient.launchBillingFlow");
            return this.launchBillingFlow(activity, params);
        };
    });

    // ── BENIGN-EXCLUSIVE: Auth ────────────────────────────────────────────────

    tryHook("GoogleSignIn.getClient (AUTH_OAUTH)", () => {
        const GoogleSignIn = Java.use("com.google.android.gms.auth.api.signin.GoogleSignIn");
        GoogleSignIn.getClient.overload(
            "android.content.Context",
            "com.google.android.gms.auth.api.signin.GoogleSignInOptions"
        ).implementation = function (ctx: any, options: any) {
            seqPush("AUTH_OAUTH");
            console.log("[BEN] GoogleSignIn.getClient");
            return this.getClient(ctx, options);
        };
    });

    tryHook("BiometricPrompt.authenticate (AUTH_BIOMETRIC)", () => {
        const BiometricPrompt = Java.use("androidx.biometric.BiometricPrompt");
        BiometricPrompt.authenticate.overload(
            "androidx.biometric.BiometricPrompt$PromptInfo"
        ).implementation = function (info: any) {
            seqPush("AUTH_BIOMETRIC");
            console.log("[BEN] BiometricPrompt.authenticate");
            return this.authenticate(info);
        };
    });

    // ── BENIGN-EXCLUSIVE: Maps ────────────────────────────────────────────────

    tryHook("SupportMapFragment.getMapAsync (MAPS_API)", () => {
        const SupportMapFragment = Java.use(
            "com.google.android.gms.maps.SupportMapFragment"
        );
        SupportMapFragment.getMapAsync.implementation = function (callback: any) {
            seqPush("MAPS_API");
            return this.getMapAsync(callback);
        };
    });

    // ── BENIGN-EXCLUSIVE: Cloud Storage ──────────────────────────────────────

    tryHook("FirebaseStorage.getReference (CLOUD_STORAGE)", () => {
        const FirebaseStorage = Java.use("com.google.firebase.storage.FirebaseStorage");
        FirebaseStorage.getReference.overload().implementation = function () {
            seqPush("CLOUD_STORAGE");
            return this.getReference();
        };
    });

    // ── BENIGN-EXCLUSIVE: Media Play ─────────────────────────────────────────

    tryHook("MediaPlayer.create (MEDIA_PLAY)", () => {
        const MediaPlayer = Java.use("android.media.MediaPlayer");
        MediaPlayer.create.overload(
            "android.content.Context", "int"
        ).implementation = function (ctx: any, resid: number) {
            seqPush("MEDIA_PLAY");
            return this.create(ctx, resid);
        };
    });

    tryHook("MediaPlayer.start (MEDIA_PLAY)", () => {
        const MediaPlayer = Java.use("android.media.MediaPlayer");
        MediaPlayer.start.implementation = function () {
            seqPush("MEDIA_PLAY");
            return this.start();
        };
    });

    // ── BENIGN-EXCLUSIVE: Notification Post ──────────────────────────────────

    tryHook("NotificationManager.notify (NOTIF_POST_LEGIT)", () => {
        const NotificationManager = Java.use("android.app.NotificationManager");
        NotificationManager.notify.overload("int", "android.app.Notification")
            .implementation = function (id: number, notification: any) {
            seqPush("NOTIF_POST_LEGIT");
            return this.notify(id, notification);
        };
        // String tag overload — NotificationManager.notify(String, int, Notification)
        NotificationManager.notify.overload("java.lang.String", "int", "android.app.Notification")
            .implementation = function (tag: string, id: number, notification: any) {
            seqPush("NOTIF_POST_LEGIT");
            return this.notify(tag, id, notification);
        };
    });

    // ── BENIGN-EXCLUSIVE: Social Share ───────────────────────────────────────
    // ACTION_SEND intent ACTION_SEND = "android.intent.action.SEND"
    // Mevcut setAction hook + flag kontrolü ile izleniyor.

    // ── PUSH / REMOTE CONFIG ──────────────────────────────────────────────────

    tryHook("FirebaseMessaging.getToken (PUSH_CHANNEL_REG)", () => {
        const FirebaseMessaging = Java.use("com.google.firebase.messaging.FirebaseMessaging");
        FirebaseMessaging.getToken.implementation = function () {
            seqPush("PUSH_CHANNEL_REG");
            return this.getToken();
        };
    });

    tryHook("FirebaseRemoteConfig.fetchAndActivate (REMOTE_CONFIG_FETCH)", () => {
        const FirebaseRemoteConfig = Java.use("com.google.firebase.remoteconfig.FirebaseRemoteConfig");
        FirebaseRemoteConfig.fetchAndActivate.implementation = function () {
            seqPush("REMOTE_CONFIG_FETCH");
            return this.fetchAndActivate();
        };
    });

    // ── Activity.requestPermissions ───────────────────────────────────────────

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

    // ── Process & Memory ──────────────────────────────────────────────────────

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

    console.log("=== KangalGuard v4: 87 Tag Hook Hazır ===");
});

// ── NATIVE: mmap + mprotect (MEM_EXEC_MMAP) ──────────────────────────────────
// PROT_EXEC = 0x4 — çalıştırılabilir bellek ayırma = shellcode imzası

try {
    const mmapPtr = (Module as any).findExportByName("libc.so", "mmap");
    if (mmapPtr) {
        Interceptor.attach(mmapPtr, {
            onEnter(args) {
                (this as any)._prot = args[2].toInt32();
            },
            onLeave(_retval) {
                if ((this as any)._prot & 0x4) {
                    seqPush("MEM_EXEC_MMAP");
                    console.log("[MAL] mmap PROT_EXEC");
                }
            }
        });
        console.log("[+] mmap PROT_EXEC interceptor");
    }
} catch (e) {
    console.log(`[-] FAIL: mmap interceptor -> ${e}`);
}

try {
    const mprotectPtr = (Module as any).findExportByName("libc.so", "mprotect");
    if (mprotectPtr) {
        Interceptor.attach(mprotectPtr, {
            onEnter(args) {
                if (args[2].toInt32() & 0x4) {
                    seqPush("MEM_EXEC_MMAP");
                    console.log("[MAL] mprotect PROT_EXEC");
                }
            }
        });
        console.log("[+] mprotect PROT_EXEC interceptor");
    }
} catch (e) {
    console.log(`[-] FAIL: mprotect interceptor -> ${e}`);
}

// ── Otomatik Flush ────────────────────────────────────────────────────────────
setInterval(flushCounters, 20000);

recv("flush", () => {
    flushCounters();
});

// ─── RPC Export ──────────────────────────────────────────────────────────────
rpc.exports = {
    getCounters: (): object => ({
        ...counters,
        _timings: { ...timings },
        _burst_peak: burstPeakCount,
        _session_duration_ms: Date.now() - SESSION_START,
        _seq_log: seqLog.slice(),
    }),
};
