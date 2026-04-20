# KangalGuard — Windows Kurulum Rehberi

Bu rehber, Linux'taki KangalGuard analiz ortamını Windows PC'ye taşımak için adım adım talimatları içerir.

---

## Gereksinimler (İndirilecekler)

Okula gitmeden önce bunları USB'ye/buluta at:

| Dosya | Nereden |
|-------|---------|
| Genymotion installer (.exe) | genymotion.com → Personal |
| Miniconda installer (.exe) | docs.conda.io/en/latest/miniconda |
| Node.js LTS installer (.exe) | nodejs.org |
| 7-Zip installer (.exe) | 7-zip.org |
| Android SDK Platform Tools (zip) | developer.android.com/studio/releases/platform-tools → Windows |
| frida-server binary | github.com/frida/frida/releases/tag/17.8.2 → `frida-server-17.8.2-android-x86_64.xz` |
| Bu repo (zip veya git clone) | — |

> **Not:** `aapt` için ayrıca Android SDK Build Tools indirmene gerek yok.
> `androguard` pip paketi fallback olarak kullanılıyor (Adım 3'te kurulacak).

---

## Adım 1 — Genymotion Kurulumu

1. Genymotion installer'ı çalıştır, varsayılan yola kur.
2. Genymotion'ı aç, Personal lisansıyla giriş yap.
3. **Yeni cihaz oluştur:**
   - `+` butonuna tıkla
   - Arama: `Nexus 5` → Android 9.0 (API 28) seç
   - Cihaz adı: `kangal_base`
   - Oluştur ve başlat

---

## Adım 2 — ADB ve AAPT Kurulumu

1. Platform Tools zip'ini `C:\tools\platform-tools\` klasörüne çıkar.
2. Build Tools zip'ini `C:\tools\build-tools\` klasörüne çıkar.
3. Bu iki yolu **sistem PATH**'ine ekle:
   - Başlat → "ortam değişkenleri" → `Path` → Düzenle → Yeni:
     ```
     C:\tools\platform-tools
     C:\tools\build-tools
     ```
4. Yeni bir CMD aç, doğrula:
   ```cmd
   adb version
   aapt version
   ```

---

## Adım 3 — Miniconda + frida Ortamı

```cmd
:: Miniconda kurulduktan sonra Anaconda Prompt'u aç:

conda create -n frida python=3.11
conda activate frida
pip install -r requirements_windows.txt
pip install androguard
```

Doğrula:
```cmd
python -c "import frida; print(frida.__version__)"
:: Çıktı: 17.8.2
```

---

## Adım 4 — Node.js ve npm Bağımlılıkları

1. Node.js LTS installer'ı çalıştır, varsayılan seçeneklerle kur.

2. Doğrula:
```cmd
node --version
npm --version
```

3. Proje klasörüne git ve bağımlılıkları yükle:
```cmd
cd <proje_klasörü>
npm install
```

`node_modules/` klasörü oluşmalı. Bu klasör olmadan `frida.Compiler()` `agent.ts`'i derleyemez.

Doğrula:
```cmd
dir node_modules\@types\frida-gum
:: Klasör listeleniyorsa başarılı
```

---

## Adım 5 — frida-server'ı Emülatöre Yükle

1. frida-server-17.8.2-android-x86_64.xz dosyasını **7-Zip ile** aç, `frida-server` binary'sini çıkar.
   (7-Zip → sağ tık → Extract Here)
2. Genymotion'da `kangal_base` cihazının çalıştığından emin ol.
3. ADB ile bağlan ve yükle:

```cmd
adb connect 127.0.0.1:6555
adb -s 127.0.0.1:6555 push frida-server /data/local/tmp/
adb -s 127.0.0.1:6555 shell chmod 755 /data/local/tmp/frida-server
```

4. frida-server'ı başlat:
```cmd
adb -s 127.0.0.1:6555 shell "su 0 /data/local/tmp/frida-server &"
```

5. frida bağlantısını doğrula:
```cmd
conda activate frida
python -c "import frida; d=frida.get_device('127.0.0.1:6555', timeout=10); print(d.name)"
```

---

## Adım 6 — Temiz Snapshot Kaydet

Bu adım her emülatör için tekrarlanacak. Şimdi sadece `kangal_base` için:

```cmd
conda activate frida
python batch_analyzer.py --device 127.0.0.1:6555 --setup
```

`[+] Snapshot kaydedildi: 'kangal_clean'` mesajını görürsen başarılı.

---

## Adım 7 — Emülatörü Klonla

`gmtool.exe` Genymotion kurulum klasöründedir. PATH'e eklemek için:
- `C:\Program Files\Genymobile\Genymotion\` yolunu da PATH'e ekle

Önce base cihazın UUID'ini öğren:
```cmd
gmtool admin list
```

Çıktıdan `kangal_base`'in UUID'ini kopyala, sonra 2 kez klonla (malware için 3):
```cmd
gmtool admin clone <uuid>
gmtool admin clone <uuid>
```

Yeni UUID'leri not al:
```cmd
gmtool admin list
```

---

## Adım 8 — Her Klona frida-server Yükle

Genymotion klonlanan cihazları sıradaki portlara (6562, 6569, ...) atar.

```cmd
:: Her klonun portunu gmtool admin list ile öğren, sonra:

adb connect 127.0.0.1:6562
adb -s 127.0.0.1:6562 push frida-server /data/local/tmp/
adb -s 127.0.0.1:6562 shell chmod 755 /data/local/tmp/frida-server
adb -s 127.0.0.1:6562 shell "su 0 /data/local/tmp/frida-server &"
python batch_analyzer.py --device 127.0.0.1:6562 --setup

:: 6569 için tekrarla...
```

---

## Adım 9 — win_run_all_*.py Güncelle

`win_run_all_benign.py` ve `win_run_all_malware.py` dosyalarını aç.
`EMULATORS` dict'ini yeni UUID ve IP:port bilgileriyle güncelle:

```python
# Örnek:
EMULATORS = {
    "127.0.0.1:6555": "<adim_7_de_aldığın_uuid_1>",
    "127.0.0.1:6562": "<adim_7_de_aldığın_uuid_2>",
    "127.0.0.1:6569": "<adim_7_de_aldığın_uuid_3>",
}
```

`GMTOOL` satırını da kontrol et — varsayılan değer doğruysa değiştirmene gerek yok:
```python
GMTOOL = r"C:\Program Files\Genymobile\Genymotion\gmtool.exe"
```

---

## Adım 10 — Test Çalıştırması

```cmd
conda activate frida
cd <proje_klasörü>

:: Küçük test (2 APK):
python batch_analyzer.py --device 127.0.0.1:6555 --dir .\data\benign --label benign --csv test.csv --limit 2
```

Her şey yolundaysa tam analizi başlat:

```cmd
:: Benign için:
python win_run_all_benign.py

:: Malware için:
python win_run_all_malware.py
```

---

## Sık Karşılaşılan Sorunlar

| Sorun | Çözüm |
|-------|-------|
| `adb: command not found` | PATH'e platform-tools eklenmemiş |
| `frida.TransportError` | frida-server çalışmıyor — Adım 5'i tekrarla |
| `frida-server version mismatch` | frida-server binary'si ile pip paketi aynı versiyonda olmalı (17.8.2) |
| `gmtool: command not found` | Genymotion klasörü PATH'e eklenmemiş |
| Snapshot `KO` döndürüyor | `--setup` adımını tekrarla, emülatörün açık olduğunu kontrol et |
| `aapt: command not found` | Sorun değil — androguard otomatik devreye girer (Adım 3'te kuruldu) |
