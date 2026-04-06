# KANGAL Feature Reference v4 — Transformer için Zenginleştirilmiş Veri Toplama Kılavuzu

**Bu dosya kolektörü uygulayan kişiye verilecek tam talimattır.**
Hedef: Medyan sequence uzunluğu ≥ 30, her sınıfa özgü net discriminative event'ler, transformer F1 > %90.

---

## NEDEN 3. KEZ?

### Önceki İki Setin Başarısızlık Nedenleri

| Sorun | Veri Etkisi |
|---|---|
| `onAccessibilityEvent()` her UI değişiminde event atıyordu | Sequence'ların ~%60'ı ACCESSIBILITY oldu |
| 18 kaba tag (NETWORK = HTTP + Socket + DNS + WebSocket) | Farklı davranışlar aynı token'a düştü |
| Her iki sınıfta da aynı oranda görülen taglar | Model iki sınıfı ayırt edemedi |
| Kısa sequence: medyan 10 event | Transformer pattern öğrenemedi |
| Benign için hiç "benign marker" yok | Model sadece malware ipuçlarına baktı |

### Bu Sefer Farklı Ne Var

- **87 granüler tag** — her birinin hangi sınıfta çıkması beklediği belirtilmiş
- **22 tag sadece malware'de** çıkması bekleniyor
- **11 tag sadece benign'de** çıkması bekleniyor
- ACCESSIBILITY tamamen yeniden tasarlandı — flood yok
- Sequence uzunluğunu artıracak loglama kuralları değiştirildi
- Minimum sequence filtresi: seq_len < 10 → kayıt yazılmaz

---

## 1. TAG SINIFLANDIRMASI

### 1a. Malware-Exclusive (22 tag) — Benign'de görülmesi beklenmiyor

Bu tag'lerin herhangi birinin varlığı güçlü malware sinyali.

```
Tag                   Beklenti        Açıklama
────────────────────  ──────────────  ────────────────────────────────────────────
SCREEN_CAPTURE        Mal: %70+       MediaProjectionManager - ekran kaydı
                      Ben: <%2        Banking trojan, spyware için ana yöntem
INPUT_INJECT          Mal: %40+       AccessibilityService.dispatchGesture()
                      Ben: <%1        Kullanıcı adına form doldurma, clickjacking
KEYLOG                Mal: %25+       InputMethodService.onKeyDown(), onKeyEvent()
                      Ben: <%1        Şifre/PIN tuş kaydı
PKG_INSTALL           Mal: %30+       PackageInstaller.Session, ACTION_INSTALL_PACKAGE
                      Ben: <%2        Başka APK kurma — dropper malware imzası
PKG_DISABLE           Mal: %20+       setComponentEnabledSetting(DISABLED)
                      Ben: <%1        Uygulama ikonunu gizleme (self-hiding)
NOTIF_LISTEN          Mal: %35+       NotificationListenerService.onNotificationPosted()
                      Ben: <%3        OTP bildirimlerini okuma — banking trojan
PHONE_CALL_SILENT     Mal: %15+       TelecomManager.placeCall() veya ACTION_CALL
                      Ben: <%1        Yetkisiz/sessiz arama, premium fraud
PHONE_STATE_LISTEN    Mal: %20+       PhoneStateListener.onCallStateChanged()
                      Ben: <%2        Arama durumu dinleme, ses kaydı tetikleyici
PERM_ADMIN_REQ        Mal: %25+       DevicePolicyManager.addUserRestriction()
                      Ben: <%2        Cihaz yönetici yetkisi — ransomware için şart
ACCOUNT_TOKEN_STEAL   Mal: %15+       AccountManager.getAuthToken() (Google, sosyal medya)
                      Ben: <%1        Kayıtlı hesap tokenı çalma
KEYSTORE_EXFIL        Mal: %10+       KeyStore.load() + KeyStore.getEntry() zinciri
                      Ben: <%1        Android güvenli depolama okuma/çalma
WEBVIEW_JS_BRIDGE     Mal: %20+       WebView.addJavascriptInterface()
                      Ben: <%3        JS→Java köprüsü — phishing sayfası native erişim
WEBVIEW_JS_EXEC       Mal: %15+       WebView.loadUrl("javascript:...")
                      Ben: <%2        Dinamik JS çalıştırma
MEM_EXEC_MMAP         Mal: %10+       mmap() + mprotect(PROT_EXEC) zinciri (native)
                      Ben: <%1        Çalıştırılabilir bellek ayırma — shellcode
DEX_LOAD_MEMORY       Mal: %15+       InMemoryDexClassLoader (API 26+)
                      Ben: <%1        Bellekten DEX yükleme — dosyasız kod enjeksiyonu
FILE_ENCRYPT_BULK     Mal: %10+       Harici dosyalara AES yazma döngüsü
                      Ben: <%1        Dosya şifreleme — ransomware imzası
ANTI_HOOK_DETECT      Mal: %30+       /proc/self/maps okuma, "frida"/"xposed" string arama
                      Ben: <%2        Frida/Xposed tespiti
ANTI_VM_PROPS         Mal: %35+       SystemProperties.get("ro.product.*") sistematik okuma
                      Ben: <%3        Sanal makine property kontrolü serisi
BCAST_SMS_INTERCEPT   Mal: %20+       SMS_RECEIVED broadcast alındığında tetikleme
                      Ben: <%1        SMS içeriğini okuma/engelleme
BCAST_SCREEN_WAKE     Mal: %15+       SCREEN_ON broadcast'ı dinleyerek gözetleme başlatma
                      Ben: <%1        Ekran açıldığında surveillance tetikleme
ROOT_HIDE             Mal: %10+       Magisk hide API, RootCloak, su binary gizleme
                      Ben: <%1        Root tespitinden kaçınma
ROOT_PERSIST_SYSTEM   Mal: %8+        /system/ veya /data/system/ yazma girişimi
                      Ben: <%1        Sistem kalıcılığı
```

### 1b. Benign-Exclusive (11 tag) — Malware'de görülmesi beklenmiyor

Bu tag'lerin varlığı güçlü benign sinyali. Transformer'ın benign sınıfı tanıması için kritik.

```
Tag                   Beklenti        Açıklama
────────────────────  ──────────────  ────────────────────────────────────────────
ADS_SDK_INIT          Ben: %70+       AdMob.initialize(), MoPub.initializeSdk()
                      Mal: <%3        Reklam SDK'sı başlatma
ANALYTICS_LOG         Ben: %80+       FirebaseAnalytics.logEvent(), Mixpanel.track()
                      Mal: <%5        Kullanıcı davranışı analitik kaydı
CRASH_REPORT          Ben: %50+       Crashlytics.recordException(), Sentry.captureException()
                      Mal: <%2        Hata raporlama servisi
IN_APP_PURCHASE       Ben: %30+       BillingClient.queryProductDetails(), launchBillingFlow()
                      Mal: <%1        Google Play uygulama içi satın alma
AUTH_OAUTH            Ben: %40+       GoogleSignIn.getClient(), OAuth2 token flow
                      Mal: <%3        Standart OAuth2 kimlik doğrulama akışı
AUTH_BIOMETRIC        Ben: %25+       BiometricPrompt.authenticate(), FingerprintManager
                      Mal: <%2        Parmak izi / yüz tanıma ile kullanıcı girişi
MAPS_API              Ben: %30+       GoogleMap.getMapAsync(), SupportMapFragment
                      Mal: <%2        Google Maps SDK kullanımı
CLOUD_STORAGE         Ben: %25+       FirebaseStorage.getReference(), GoogleDrive API
                      Mal: <%2        Kullanıcı verisi bulut depolama (izinli)
SOCIAL_SHARE          Ben: %35+       Intent(ACTION_SEND) ile paylaşım dialogu
                      Mal: <%1        Standart Android içerik paylaşımı
MEDIA_PLAY            Ben: %45+       MediaPlayer.create(), ExoPlayer.setMediaItem()
                      Mal: <%3        Ses/video içerik oynatma
NOTIF_POST_LEGIT      Ben: %60+       NotificationManager.notify() kullanıcı onaylı
                      Mal: <%5        Normal push bildirimi (NOTIF_LISTEN ile karıştırma)
```

### 1c. Shared — Her iki sınıfta da var ama farklı oranlarda (54 tag)

Transformer bu oranlardaki farkı ve sıralamayı öğrenir.

---

## 2. TAM VOCABULARY — 87 TAG

Kolektör bu listedeki TAG isimlerini kullanacak. Python listesi:

```python
TAGS = [
    # ── MALWARE-EXCLUSIVE (22) ──────────────────────────────────────────────
    'SCREEN_CAPTURE',      'INPUT_INJECT',        'KEYLOG',
    'PKG_INSTALL',         'PKG_DISABLE',
    'NOTIF_LISTEN',        'PHONE_CALL_SILENT',   'PHONE_STATE_LISTEN',
    'PERM_ADMIN_REQ',      'ACCOUNT_TOKEN_STEAL', 'KEYSTORE_EXFIL',
    'WEBVIEW_JS_BRIDGE',   'WEBVIEW_JS_EXEC',
    'MEM_EXEC_MMAP',       'DEX_LOAD_MEMORY',
    'FILE_ENCRYPT_BULK',
    'ANTI_HOOK_DETECT',    'ANTI_VM_PROPS',
    'BCAST_SMS_INTERCEPT', 'BCAST_SCREEN_WAKE',
    'ROOT_HIDE',           'ROOT_PERSIST_SYSTEM',

    # ── BENIGN-EXCLUSIVE (11) ───────────────────────────────────────────────
    'ADS_SDK_INIT',        'ANALYTICS_LOG',       'CRASH_REPORT',
    'IN_APP_PURCHASE',     'AUTH_OAUTH',           'AUTH_BIOMETRIC',
    'MAPS_API',            'CLOUD_STORAGE',        'SOCIAL_SHARE',
    'MEDIA_PLAY',          'NOTIF_POST_LEGIT',

    # ── NETWORK (7) ─────────────────────────────────────────────────────────
    'NET_HTTP_GET',        'NET_HTTP_POST',
    'NET_SOCKET_TCP',      'NET_SOCKET_UDP',
    'NET_DNS_LOOKUP',      'NET_SSL_BYPASS',       'NET_WEBSOCKET',

    # ── CRYPTO (6) ──────────────────────────────────────────────────────────
    'CRYPTO_AES',          'CRYPTO_RSA',
    'CRYPTO_HASH_MD5',     'CRYPTO_HASH_SHA',
    'CRYPTO_BASE64_ENC',   'CRYPTO_BASE64_DEC',    'CRYPTO_KEYGEN',

    # ── REFLECTION & LOADING (5) ────────────────────────────────────────────
    'REFLECT_INVOKE',      'REFLECT_CLASS_LOAD',   'REFLECT_FIELD_ACCESS',
    'DEX_LOAD_FILE',       'NATIVE_LIB_LOAD',

    # ── SURVEILLANCE (8) ────────────────────────────────────────────────────
    'SURV_DEVICE_ID',
    'SURV_LOCATION_GPS',   'SURV_LOCATION_NET',
    'SURV_CONTACT_READ',   'SURV_SMS_READ',        'SURV_CALL_LOG',
    'SURV_CAMERA',         'SURV_MIC_RECORD',

    # ── FILE OPERATIONS (5) ─────────────────────────────────────────────────
    'FILE_WRITE_INTERNAL', 'FILE_WRITE_EXTERNAL',
    'FILE_READ_SENSITIVE', 'FILE_DELETE',

    # ── EXECUTION (2) ───────────────────────────────────────────────────────
    'EXEC_SHELL_CMD',      'EXEC_ROOT_CMD',

    # ── PERSISTENCE (4) ─────────────────────────────────────────────────────
    'PERSIST_BOOT_RECV',   'PERSIST_ALARM_REP',
    'PERSIST_JOB_SCHED',   'PERSIST_FG_SERVICE',

    # ── ANTI-ANALYSIS (4) ───────────────────────────────────────────────────
    'ANTI_DEBUG',          'ANTI_EMULATOR',
    'ANTI_ROOT_CHECK',     'ANTI_SLEEP_LONG',

    # ── PACKAGE MANAGEMENT (1) ──────────────────────────────────────────────
    'PKG_ENUMERATE',

    # ── IPC (3) ─────────────────────────────────────────────────────────────
    'IPC_BIND_SERVICE',    'IPC_SEND_BROADCAST',  'IPC_IMPLICIT_INTENT',

    # ── ACCESSIBILITY (3) ───────────────────────────────────────────────────
    'ACC_SERVICE_BIND',    'ACC_ACTION',           'ACC_WINDOW_ACCESS',

    # ── MEDIA & CONTENT (2) ─────────────────────────────────────────────────
    'MEDIA_PHOTO_ACCESS',  'MEDIA_VIDEO_ACCESS',

    # ── UI ABUSE (2) ────────────────────────────────────────────────────────
    'OVERLAY_WINDOW',      'CLIPBOARD_ACCESS',

    # ── C2 CHANNEL (2) ──────────────────────────────────────────────────────
    'PUSH_CHANNEL_REG',    'REMOTE_CONFIG_FETCH',
]

# PAD_ID = 0, TAG2ID = {tag: i+1 for i, tag in enumerate(TAGS)}
# VOCAB_SIZE = 88  (87 tag + 1 PAD)
```

---

## 3. TAG → HOOK EDİLECEK METODLAR (Tam Liste)

### 3a. MALWARE-EXCLUSIVE Hook'ları

```
SCREEN_CAPTURE
  → MediaProjectionManager.getMediaProjection()
  → MediaProjection.createVirtualDisplay()

INPUT_INJECT
  → AccessibilityService.dispatchGesture()
  → UiAutomation.injectInputEvent()

KEYLOG
  → InputMethodService.onKeyDown()
  → View.dispatchKeyEvent() (hook override)
  → KeyEvent.getUnicodeChar()

PKG_INSTALL
  → PackageInstaller.Session.commit()
  → Intent(ACTION_INSTALL_PACKAGE)
  → Intent(ACTION_VIEW) + "application/vnd.android.package-archive"

PKG_DISABLE
  → PackageManager.setComponentEnabledSetting(COMPONENT_ENABLED_STATE_DISABLED)
  → ActivityManager.forceStopPackage()

NOTIF_LISTEN
  → NotificationListenerService.onNotificationPosted()
  → NotificationListenerService.onNotificationRemoved()

PHONE_CALL_SILENT
  → TelecomManager.placeCall()
  → Intent(ACTION_CALL)
  → Intent(ACTION_CALL_PRIVILEGED)

PHONE_STATE_LISTEN
  → TelephonyManager.listen(PhoneStateListener, LISTEN_CALL_STATE)
  → PhoneStateListener.onCallStateChanged()

PERM_ADMIN_REQ
  → DevicePolicyManager.addUserRestriction()
  → Intent(ACTION_ADD_DEVICE_ADMIN)
  → DevicePolicyManager.lockNow()

ACCOUNT_TOKEN_STEAL
  → AccountManager.getAuthToken()
  → AccountManager.peekAuthToken()
  → AccountManager.getPassword()

KEYSTORE_EXFIL
  → KeyStore.load() + KeyStore.getEntry() [zincir tespiti]
  → KeyStore.getKey()

WEBVIEW_JS_BRIDGE
  → WebView.addJavascriptInterface()

WEBVIEW_JS_EXEC
  → WebView.loadUrl("javascript:*")
  → WebView.evaluateJavascript()

MEM_EXEC_MMAP
  → mmap() ile PROT_EXEC flag (JNI üzerinden)
  → mprotect() ile PROT_EXEC geçişi

DEX_LOAD_MEMORY
  → InMemoryDexClassLoader.<init>()
  → dalvik.system.InMemoryDexClassLoader

FILE_ENCRYPT_BULK
  → Cipher.doFinal() + FileOutputStream zinciri AYNI döngüde
  → Şifreleme + harici path birlikte: /sdcard/, /storage/emulated/

ANTI_HOOK_DETECT
  → FileInputStream("/proc/self/maps") + "frida"/"xposed"/"substrate" string arama
  → File("/data/local/tmp/frida*").exists()
  → dlopen("libfrida*")

ANTI_VM_PROPS
  → SystemProperties.get("ro.product.model") + "ro.product.brand" + "ro.hardware" 
    [3+ farklı ro.* okuma = bu tag]
  → Build.FINGERPRINT.contains("generic")

BCAST_SMS_INTERCEPT
  → BroadcastReceiver.onReceive() ile SMS_RECEIVED intent
  → SmsMessage.createFromPdu()

BCAST_SCREEN_WAKE
  → BroadcastReceiver.onReceive() ile SCREEN_ON intent

ROOT_HIDE
  → RootBeer / RootCloak API çağrıları
  → su binary yeniden adlandırma
  → mount -o remount,rw /system

ROOT_PERSIST_SYSTEM
  → FileOutputStream("/system/*")
  → FileOutputStream("/data/system/*")
```

### 3b. BENIGN-EXCLUSIVE Hook'ları

```
ADS_SDK_INIT
  → com.google.android.gms.ads.MobileAds.initialize()
  → com.mopub.mobileads.MoPub.initializeSdk()
  → com.facebook.ads.AudienceNetworkAds.initialize()

ANALYTICS_LOG
  → com.google.firebase.analytics.FirebaseAnalytics.logEvent()
  → com.mixpanel.android.mpmetrics.MixpanelAPI.track()
  → com.amplitude.android.Amplitude.logEvent()

CRASH_REPORT
  → com.google.firebase.crashlytics.FirebaseCrashlytics.recordException()
  → io.sentry.Sentry.captureException()
  → com.bugsnag.android.Bugsnag.notify()

IN_APP_PURCHASE
  → com.android.billingclient.api.BillingClient.queryProductDetailsAsync()
  → com.android.billingclient.api.BillingClient.launchBillingFlow()

AUTH_OAUTH
  → com.google.android.gms.auth.api.signin.GoogleSignIn.getClient()
  → net.openid.appauth.AuthorizationService.performAuthorizationRequest()
  → android.accounts.AccountManager.getAccountsByType("com.google")

AUTH_BIOMETRIC
  → androidx.biometric.BiometricPrompt.authenticate()
  → android.hardware.fingerprint.FingerprintManager.authenticate()

MAPS_API
  → com.google.android.gms.maps.SupportMapFragment.getMapAsync()
  → com.google.android.gms.maps.GoogleMap.*

CLOUD_STORAGE
  → com.google.firebase.storage.FirebaseStorage.getReference()
  → com.google.api.services.drive.Drive.files()

SOCIAL_SHARE
  → Intent(Intent.ACTION_SEND) + type="*/*" şeklinde başlatma
  → ShareCompat.IntentBuilder.startChooser()

MEDIA_PLAY
  → android.media.MediaPlayer.create()
  → com.google.android.exoplayer2.ExoPlayer.setMediaItem()
  → android.media.MediaPlayer.start()

NOTIF_POST_LEGIT
  → NotificationManager.notify() [INPUT_INJECT veya NOTIF_LISTEN olmadan]
  → NotificationManagerCompat.notify()
```

### 3c. SHARED Tag Hook'ları

```
NET_HTTP_GET
  → HttpURLConnection.setRequestMethod("GET") + connect()
  → OkHttpClient: Request.Builder().get().build()

NET_HTTP_POST
  → HttpURLConnection.setRequestMethod("POST") + getOutputStream()
  → OkHttpClient: Request.Builder().post(body).build()

NET_SOCKET_TCP
  → Socket.<init>() + Socket.connect()
  → SSLSocket.connect()

NET_SOCKET_UDP
  → DatagramSocket.send()
  → DatagramSocket.<init>()

NET_DNS_LOOKUP
  → InetAddress.getByName()
  → InetAddress.getAllByName()

NET_SSL_BYPASS
  → X509TrustManager implementasyonu checkServerTrusted() boş
  → HostnameVerifier.verify() her zaman true
  → SSLContext.init(null, trustAllCerts, null)

NET_WEBSOCKET
  → okhttp3.WebSocket
  → javax.websocket.*
  → java.net.http.WebSocket (API 11+)

CRYPTO_AES
  → Cipher.getInstance("AES*") + Cipher.doFinal()

CRYPTO_RSA
  → Cipher.getInstance("RSA*") + Cipher.doFinal()
  → KeyPairGenerator.getInstance("RSA")

CRYPTO_HASH_MD5
  → MessageDigest.getInstance("MD5") + digest()

CRYPTO_HASH_SHA
  → MessageDigest.getInstance("SHA*") + digest()

CRYPTO_BASE64_ENC
  → Base64.encode() veya Base64.encodeToString()

CRYPTO_BASE64_DEC
  → Base64.decode()

CRYPTO_KEYGEN
  → KeyGenerator.generateKey()
  → SecretKeyFactory.generateSecret()
  → KeyPairGenerator.generateKeyPair()

REFLECT_INVOKE
  → java.lang.reflect.Method.invoke()

REFLECT_CLASS_LOAD
  → Class.forName()
  → ClassLoader.loadClass()

REFLECT_FIELD_ACCESS
  → java.lang.reflect.Field.get()
  → java.lang.reflect.Field.set()

DEX_LOAD_FILE
  → dalvik.system.DexClassLoader.<init>() (path harici)
  → dalvik.system.PathClassLoader.<init>() (path /sdcard/ veya /data/local/)

NATIVE_LIB_LOAD
  → System.loadLibrary()
  → System.load() (tam path)

SURV_DEVICE_ID
  → TelephonyManager.getDeviceId()
  → TelephonyManager.getImei()
  → TelephonyManager.getSubscriberId()
  → Settings.Secure.getString(cr, "android_id")

SURV_LOCATION_GPS
  → LocationManager.requestLocationUpdates("gps", ...)
  → LocationManager.getLastKnownLocation("gps")

SURV_LOCATION_NET
  → LocationManager.requestLocationUpdates("network", ...)
  → FusedLocationProviderClient.getLastLocation()

SURV_CONTACT_READ
  → ContentResolver.query(ContactsContract.Contacts.CONTENT_URI, ...)
  → ContentResolver.query("content://contacts/*")

SURV_SMS_READ
  → ContentResolver.query("content://sms/*")
  → ContentResolver.query(Telephony.Sms.CONTENT_URI, ...)

SURV_CALL_LOG
  → ContentResolver.query(CallLog.Calls.CONTENT_URI, ...)
  → ContentResolver.query("content://call_log/calls")

SURV_CAMERA
  → CameraManager.openCamera()
  → Camera.open()

SURV_MIC_RECORD
  → AudioRecord.startRecording()
  → MediaRecorder.setAudioSource(MediaRecorder.AudioSource.MIC)
  → MediaRecorder.start()

FILE_WRITE_INTERNAL
  → FileOutputStream("/data/data/*") veya openFileOutput()
  → SharedPreferences.Editor.commit() / apply()

FILE_WRITE_EXTERNAL
  → FileOutputStream("/sdcard/*") veya "/storage/emulated/*"
  → Environment.getExternalStorageDirectory() ile açılan stream

FILE_READ_SENSITIVE
  → FileInputStream("/proc/*") [maps, status, net/arp]
  → FileInputStream("/system/build.prop")
  → FileInputStream("/data/data/<other_package>/*")

FILE_DELETE
  → File.delete()
  → Files.delete()

EXEC_SHELL_CMD
  → Runtime.getRuntime().exec(String[])
  → ProcessBuilder.start()

EXEC_ROOT_CMD
  → Runtime.exec("su") veya ProcessBuilder("su")
  → Process.waitFor() su sonrası

PERSIST_BOOT_RECV
  → IntentFilter("android.intent.action.BOOT_COMPLETED") + registerReceiver
  → Manifest'te BOOT_COMPLETED receiver

PERSIST_ALARM_REP
  → AlarmManager.setRepeating()
  → AlarmManager.setExact() + zincir içinde tekrar set

PERSIST_JOB_SCHED
  → JobScheduler.schedule()
  → WorkManager.enqueueUniquePeriodicWork()

PERSIST_FG_SERVICE
  → Context.startForegroundService()
  → Service.startForeground()

ANTI_DEBUG
  → android.os.Debug.isDebuggerConnected()
  → Debug.waitingForDebugger()

ANTI_EMULATOR
  → Build.FINGERPRINT.contains("generic") / "emulator"
  → Build.MODEL.contains("Emulator") / "Android SDK"
  → /dev/socket/qemud veya /dev/qemu_pipe varlık kontrolü

ANTI_ROOT_CHECK
  → File("/system/bin/su").exists()
  → File("/system/xbin/su").exists()
  → which su komutu

ANTI_SLEEP_LONG
  → Thread.sleep(ms) → ms > 3000

PKG_ENUMERATE
  → PackageManager.getInstalledPackages()
  → PackageManager.getInstalledApplications()

IPC_BIND_SERVICE
  → Context.bindService()

IPC_SEND_BROADCAST
  → Context.sendBroadcast()
  → Context.sendOrderedBroadcast()

IPC_IMPLICIT_INTENT
  → startActivity(intent) + intent.component == null

ACC_SERVICE_BIND
  → AccessibilityService.onServiceConnected()  [yalnızca 1 kez logla]

ACC_ACTION
  → AccessibilityNodeInfo.performAction()  [maks 20 kez/session]

ACC_WINDOW_ACCESS
  → AccessibilityService.getWindows()
  → AccessibilityService.getRootInActiveWindow()  [maks 10 kez/session]

MEDIA_PHOTO_ACCESS
  → ContentResolver.query(MediaStore.Images.Media.EXTERNAL_CONTENT_URI, ...)

MEDIA_VIDEO_ACCESS
  → ContentResolver.query(MediaStore.Video.Media.EXTERNAL_CONTENT_URI, ...)

OVERLAY_WINDOW
  → WindowManager.addView() + TYPE_APPLICATION_OVERLAY
  → WindowManager.addView() + TYPE_SYSTEM_OVERLAY

CLIPBOARD_ACCESS
  → ClipboardManager.getPrimaryClip()
  → ClipboardManager.setPrimaryClip()

PUSH_CHANNEL_REG
  → FirebaseMessaging.getInstance().getToken()
  → FirebaseInstanceId.getInstance().getInstanceId()

REMOTE_CONFIG_FETCH
  → FirebaseRemoteConfig.getInstance().fetchAndActivate()
  → FirebaseRemoteConfig.fetch()
```

---

## 4. SEQ_LOG FORMATI

```json
{
  "package_name": "com.example.app",
  "label": "malware",
  "session_duration_ms": 47000,
  "seq_len": 34,
  "seq_log": [
    {"tag": "ANTI_DEBUG",        "ms": 120},
    {"tag": "ANTI_EMULATOR",     "ms": 122},
    {"tag": "ANTI_ROOT_CHECK",   "ms": 124},
    {"tag": "ANTI_VM_PROPS",     "ms": 310},
    {"tag": "PKG_ENUMERATE",     "ms": 800},
    {"tag": "ACC_SERVICE_BIND",  "ms": 1200},
    {"tag": "NET_DNS_LOOKUP",    "ms": 1500},
    {"tag": "NET_HTTP_GET",      "ms": 1650},
    {"tag": "SURV_DEVICE_ID",    "ms": 2100},
    {"tag": "SURV_CONTACT_READ", "ms": 2300},
    {"tag": "SURV_SMS_READ",     "ms": 2400},
    {"tag": "NOTIF_LISTEN",      "ms": 2600},
    {"tag": "SCREEN_CAPTURE",    "ms": 3000},
    {"tag": "CRYPTO_AES",        "ms": 3500},
    {"tag": "NET_HTTP_POST",     "ms": 3800},
    {"tag": "NET_HTTP_POST",     "ms": 4100},
    {"tag": "PERSIST_BOOT_RECV", "ms": 5000},
    {"tag": "PUSH_CHANNEL_REG",  "ms": 5200}
  ]
}
```

**`ms`**: session başından itibaren milisaniye. `delta_ms` Transformer notebook'ta hesaplanır.

**Burst alanı** (isteğe bağlı): Aynı tag 5+ kez arka arkaya gelirse:
```json
{"tag": "NET_HTTP_GET", "ms": 8000, "burst": 7}
```

---

## 5. KOLEKTÖRDEKİ DEĞİŞİKLİKLER

### 5a. Global Değişkenler ve Yardımcı Fonksiyonlar

```python
import json

SEQ_LOG_FILE = CSV_FILE.replace('.csv', '_seqlogs.jsonl')

latest_seq_log             = []
latest_session_duration_ms = 0
_seq_last_tag              = None
_seq_last_count            = 0

# Tag başına session limitleri (flood önleme)
_TAG_SESSION_LIMIT = {
    'ACC_SERVICE_BIND': 1,    # sadece 1 kez
    'ACC_ACTION':       20,   # maks 20
    'ACC_WINDOW_ACCESS':10,   # maks 10
    'ANALYTICS_LOG':    10,   # maks 10
    'NET_HTTP_GET':     30,   # maks 30
    'NET_HTTP_POST':    30,
    'CRYPTO_AES':       20,
    'CRYPTO_BASE64_ENC':20,
    'CRYPTO_BASE64_DEC':20,
}
_DEFAULT_SESSION_LIMIT = 15   # diğer tüm taglar için
_tag_session_count = {}       # {tag: count} — session başında sıfırla

def seq_append(tag, ms):
    """Dedup + session limit + burst mantığıyla event ekle."""
    global _seq_last_tag, _seq_last_count

    # Session limiti kontrolü
    limit = _TAG_SESSION_LIMIT.get(tag, _DEFAULT_SESSION_LIMIT)
    count = _tag_session_count.get(tag, 0)
    if count >= limit:
        return
    _tag_session_count[tag] = count + 1

    # Burst tespiti: aynı tag 5+ arka arkaya
    if _seq_last_tag == tag:
        _seq_last_count += 1
        if _seq_last_count >= 5:
            if 'burst' not in latest_seq_log[-1]:
                latest_seq_log[-1]['burst'] = 4
            latest_seq_log[-1]['burst'] += 1
            latest_seq_log[-1]['ms'] = ms
            return
    else:
        _seq_last_tag   = tag
        _seq_last_count = 1

    latest_seq_log.append({'tag': tag, 'ms': ms})
```

### 5b. Session Sıfırlama

```python
def reset_session():
    global latest_seq_log, latest_session_duration_ms
    global _seq_last_tag, _seq_last_count, _tag_session_count
    latest_seq_log             = []
    latest_session_duration_ms = 0
    _seq_last_tag              = None
    _seq_last_count            = 0
    _tag_session_count         = {}
```

### 5c. write_row() İçinde Kaydetme

```python
# MİNİMUM UZUNLUK FİLTRESİ: seq_len < 10 olan kayıtları atla
if latest_seq_log and len(latest_seq_log) >= 10:
    with open(SEQ_LOG_FILE, 'a', encoding='utf-8') as sf:
        sf.write(json.dumps({
            "package_name"       : PACKAGE_NAME,
            "label"              : LABEL,
            "session_duration_ms": latest_session_duration_ms,
            "seq_len"            : len(latest_seq_log),
            "seq_log"            : latest_seq_log
        }) + '\n')
```

### 5d. ACCESSIBILITY Özel Kuralı

```python
# ❌ YAPMA: onAccessibilityEvent() hookunda seq_append çağırma
# ✅ YAP:

def on_accessibility_service_connected():
    seq_append('ACC_SERVICE_BIND', get_ms())

def on_perform_action(action, ms):
    seq_append('ACC_ACTION', ms)

def on_get_windows(ms):
    seq_append('ACC_WINDOW_ACCESS', ms)

# onAccessibilityEvent() için seq_append ÇAĞIRMA.
```

---

## 6. YENİ CSV KOLONLARI

Mevcut kolektöre eklenecek 25 yeni raw count:

```
Yeni kolon                Hook / kaynak                       Açıklama
──────────────────────    ──────────────────────────────────  ─────────────────────────
http_get_count            HttpURLConnection "GET"             HTTP GET sayısı
http_post_count           HttpURLConnection "POST"            HTTP POST sayısı
websocket_count           okhttp3.WebSocket                   WebSocket bağlantısı
ssl_bypass_count          boş TrustManager                    SSL atlatma
aes_encrypt_count         Cipher("AES") ENCRYPT_MODE          AES şifreleme sayısı
rsa_count                 Cipher("RSA")                       RSA işlem sayısı
hash_md5_count            MessageDigest("MD5")                MD5 hash
hash_sha_count            MessageDigest("SHA*")               SHA hash
base64_enc_count          Base64.encode                       Base64 encode
base64_dec_count          Base64.decode                       Base64 decode
location_gps_count        requestLocationUpdates("gps")       GPS konum erişimi
location_net_count        requestLocationUpdates("network")   Ağ konum erişimi
camera_open_count         CameraManager.openCamera            Kamera açma
mic_record_count          AudioRecord.startRecording          Mikrofon kayıt başlatma
sms_read_count            ContentResolver("content://sms")    SMS okuma
call_log_count            ContentResolver("call_log")         Arama kaydı okuma
file_delete_count         File.delete()                       Dosya silme
pkg_install_count         PackageInstaller.Session.commit()   APK kurma
pkg_enum_count            getInstalledPackages()              Uygulama listeleme
notif_listen_count        NotificationListenerService         Bildirim dinleme
screen_capture_count      MediaProjectionManager              Ekran kaydı başlatma
input_inject_count        dispatchGesture()                   Girdi enjeksiyonu
acc_action_count          performAction()                     Erişilebilirlik aksiyon
acc_window_count          getWindows()                        Pencere erişimi
foreground_service_count  startForegroundService()            Ön plan servis
```

---

## 7. VERİ KALİTE KONTROL KODU

Veri toplandıktan hemen sonra çalıştır. Bir hafta boşa gitmesin.

```python
import json
import numpy as np
from collections import Counter

def load_jsonl(path):
    with open(path, encoding='utf-8') as f:
        return [json.loads(l) for l in f]

def quality_check(path, label, expected_label):
    recs  = load_jsonl(path)
    lens  = np.array([r['seq_len'] for r in recs])
    uniq  = np.array([len(set(e['tag'] for e in r['seq_log'])) for r in recs])
    all_tags = Counter(e['tag'] for r in recs for e in r['seq_log'])
    total_events = sum(all_tags.values())

    # ACC oranı
    acc_tags  = ['ACC_SERVICE_BIND', 'ACC_ACTION', 'ACC_WINDOW_ACCESS']
    acc_count = sum(all_tags.get(t, 0) for t in acc_tags)

    # Malware exclusive'ların varlığı (malware setinde yüksek olmalı)
    mal_excl = ['SCREEN_CAPTURE','INPUT_INJECT','KEYLOG','PKG_INSTALL',
                'NOTIF_LISTEN','PERM_ADMIN_REQ','ANTI_HOOK_DETECT','DEX_LOAD_MEMORY']
    mal_excl_present = sum(1 for r in recs
                           if any(e['tag'] in mal_excl for e in r['seq_log']))

    # Benign exclusive'ların varlığı (benign setinde yüksek olmalı)
    ben_excl = ['ADS_SDK_INIT','ANALYTICS_LOG','AUTH_OAUTH',
                'IN_APP_PURCHASE','CRASH_REPORT','MAPS_API']
    ben_excl_present = sum(1 for r in recs
                           if any(e['tag'] in ben_excl for e in r['seq_log']))

    print(f'\n{"="*60}')
    print(f'{label} ({len(recs)} örnek)')
    print(f'{"="*60}')
    print(f'Seq uzunluk  — min={lens.min()} medyan={np.median(lens):.0f} '
          f'mean={lens.mean():.1f} p95={np.percentile(lens,95):.0f}')
    print(f'Unique tag   — medyan={np.median(uniq):.0f} mean={uniq.mean():.1f}')
    print(f'ACC* oranı   — %{100*acc_count/total_events:.1f}  (hedef: <%15)')
    print(f'Mal-exclusive— {mal_excl_present}/{len(recs)} örnekte '
          f'(%{100*mal_excl_present/len(recs):.0f})')
    print(f'Ben-exclusive— {ben_excl_present}/{len(recs)} örnekte '
          f'(%{100*ben_excl_present/len(recs):.0f})')
    print(f'seq_len < 10 — {(lens<10).sum()} OLMAMALI')
    print(f'\nTop 10 tag:')
    for tag, cnt in all_tags.most_common(10):
        print(f'  {tag:<25} {cnt:>6}  (%{100*cnt/total_events:.1f})')

    # UYARILAR
    print(f'\n── Kontroller ──────────────')
    checks = [
        (np.median(lens) >= 20,    f'Medyan seq uzunluğu ≥ 20  (şu an: {np.median(lens):.0f})'),
        (np.median(uniq) >= 3,     f'Medyan unique tag ≥ 3     (şu an: {np.median(uniq):.0f})'),
        (acc_count/total_events < 0.15, f'ACC* oranı < %15       (şu an: %{100*acc_count/total_events:.1f})'),
        ((lens<10).sum() == 0,     f'seq_len < 10 = 0          (şu an: {(lens<10).sum()})'),
    ]
    if expected_label == 'malware':
        checks.append((mal_excl_present/len(recs) > 0.3,
                        f'Malware exclusive ≥ %30   (şu an: %{100*mal_excl_present/len(recs):.0f})'))
    else:
        checks.append((ben_excl_present/len(recs) > 0.4,
                        f'Benign exclusive ≥ %40    (şu an: %{100*ben_excl_present/len(recs):.0f})'))

    all_pass = True
    for ok, msg in checks:
        status = '✓' if ok else '✗ SORUN'
        print(f'  {status}  {msg}')
        if not ok:
            all_pass = False
    if all_pass:
        print('\n  ✓ Tüm kriterler geçti — eğitime geçebilirsin.')
    else:
        print('\n  ✗ Sorunları gider, tekrar veri toplama.')

quality_check('kangal_malware_seqlogs.jsonl', 'MALWARE', 'malware')
quality_check('kangal_benign_seqlogs.jsonl',  'BENIGN',  'benign')
```

---

## 8. TRANSFORMER NOTEBOOK DEĞİŞİKLİKLERİ

### 8a. Sabitler

```python
TAGS = [...]     # Bölüm 2'deki 87-tag listesi
VOCAB_SIZE = 88  # 87 tag + PAD
MAX_SEQ_LEN = 128  # Yeni veriyle uzun sequence'lar bekleniyor
```

### 8b. encode_seq — delta_ms eklentisi

```python
def encode_seq(seq_log, session_duration_ms, max_len=MAX_SEQ_LEN):
    dur    = max(session_duration_ms, 1)
    events = seq_log[:max_len]

    tag_ids    = np.zeros(max_len,   dtype=np.int64)
    time_vals  = np.zeros(max_len,   dtype=np.float32)  # ms / dur
    delta_vals = np.zeros(max_len,   dtype=np.float32)  # delta_ms / dur
    attn_mask  = np.ones(max_len,    dtype=bool)
    tag_freq   = np.zeros(len(TAGS), dtype=np.float32)

    prev_ms = 0
    for i, ev in enumerate(events):
        tid           = TAG2ID.get(ev['tag'], PAD_ID)
        cur_ms        = ev['ms']
        weight        = ev.get('burst', 1)  # burst varsa frekansa sayılır
        tag_ids[i]    = tid
        time_vals[i]  = min(cur_ms / dur, 1.0)
        delta_vals[i] = min((cur_ms - prev_ms) / dur, 1.0)
        attn_mask[i]  = False
        if tid > 0:
            tag_freq[tid - 1] += weight
        prev_ms = cur_ms

    total = tag_freq.sum()
    if total > 0:
        tag_freq /= total

    return tag_ids, time_vals, delta_vals, attn_mask, tag_freq
```

### 8c. Dataset — delta_vals eklentisi

```python
def __getitem__(self, idx):
    row = self.df.iloc[idx]
    tag_ids, time_vals, delta_vals, attn_mask, tag_freq = encode_seq(
        row['seq_log'], row['session_duration_ms'], self.max_len
    )
    return (
        torch.tensor(tag_ids,    dtype=torch.long),
        torch.tensor(time_vals,  dtype=torch.float),
        torch.tensor(delta_vals, dtype=torch.float),
        torch.tensor(attn_mask,  dtype=torch.bool),
        torch.tensor(tag_freq,   dtype=torch.float),
        torch.tensor(row['label_bin'], dtype=torch.float),
    )
```

### 8d. Model — delta_proj eklentisi

```python
# __init__ içinde:
self.time_proj  = nn.Sequential(nn.Linear(1, embed_dim//2), nn.GELU(),
                                 nn.Linear(embed_dim//2, embed_dim))
self.delta_proj = nn.Sequential(nn.Linear(1, embed_dim//2), nn.GELU(),
                                 nn.Linear(embed_dim//2, embed_dim))

# forward içinde:
time_e  = self.time_proj(time_vals.unsqueeze(-1))
delta_e = self.delta_proj(delta_vals.unsqueeze(-1))
x = self.input_norm(tag_e + time_e + delta_e)
```

---

## 9. BEKLENEN ETKİLER

| Metrik | v2 (Şimdiki) | v4 Hedef |
|---|---|---|
| Vocabulary boyutu | 18 tag | **87 tag** |
| Medyan seq uzunluğu | 10 event | **≥ 30 event** |
| Medyan unique tag/sample | 1 | **≥ 5** |
| ACC* event oranı | %60 | **< %15** |
| Sınıflandırılamaz örnek | %47 | **< %5** |
| Transformer Val F1 | ~%80 | **> %90** |
| Malware-exclusive tag'i olan örnek | %18 | **> %50** |
| Benign-exclusive tag'i olan örnek | 0 | **> %60** |

---

## 10. KOLEKTÖRCÜYE VERİLECEK TALİMATLAR (Özet)

1. **Bölüm 3'teki tüm hook'ları ekle** — 87 tag için exact Java metodları verilmiş.
2. **ACC flood'u durdur** — `onAccessibilityEvent()` hook'unu kaldır, sadece `onServiceConnected`, `performAction`, `getWindows` hookla.
3. **`seq_append()` fonksiyonunu kullan** (Bölüm 5a) — session limit + burst mantığı dahil.
4. **Minimum filtre** — `seq_len < 10` olan kayıtları JSONL'e yazma.
5. **Bölüm 6'daki 25 yeni CSV kolonunu** ekle.
6. **Veri toplandıktan sonra** Bölüm 7'deki kalite kontrol kodunu çalıştır, tüm kriterler geçmeden eğitime başlama.
