# DriftDroid — Research Direction

## Tek Cümlelik Kimlik

> DriftDroid, Android zararlı yazılım runtime davranışının zaman içinde nasıl evrildiğini inceler ve bu davranışsal anlayışın hafif bir temporal kalibrasyon için nasıl kullanılabileceğini araştırır.

---

## Ana Araştırma Kimliği

Bu çalışma bir online learning veya adaptasyon makalesi **değildir.**

Asıl soru:
> "Hangi runtime davranışları zamanla değişti ve bu değişimler model bozulmasını nasıl açıklıyor?"

Mevcut temporal çalışmaların bıraktığı boşluk:

| Mevcut Yön | Sınırlılık |
|---|---|
| Temporal evaluation (TESSERACT vb.) | Bozulmayı gösterir, neden değiştiğini açıklamaz |
| Online / active learning | Modeli günceller, davranışsal evrimi açıklamaz |
| Representation robustness | Kararlı özellik öğrenir, runtime drift'i analiz etmez |

**Bizim farkımız:** Dinamik Android zararlı yazılım tespitinde davranışsal drift'i açıkça karakterize etmek.

---

## Katkı Yapısı

### Katkı 1 — Temporal Generalization Değerlendirmesi
Strict train-past / test-future protokolü ile gerçekçi temporal bozulmanın ölçülmesi.

### Katkı 2 — Behavior-Centric Feature Pipeline
87 runtime behavioral tag, aggregate özellikler ve sekans temsili içeren çift formatlı çıktı (CSV + JSONL).

### Katkı 3 — Behavioral Drift Analizi ⭐ (Ana Katkı)
KronoDroid → AndroZoo geçişinde hangi davranışların değiştiğinin ölçülmesi ve açıklanması.

### Katkı 4 — Sekans Düzeyinde Drift
Runtime davranış sıralamasının zaman içindeki evriminin analizi.

### Katkı 5 — Hafif Drift-Aware Adaptasyon (Exploratory)
Sınırlı gelecek-domain verisiyle temporal bozulmanın kısmen telafi edilip edilemeyeceğinin araştırılması.

---

## Deneysel Yapı

### Faz 1 — Temporal Generalization
- **Train:** KronoDroid
- **Test:** AndroZoo 2025–2026
- **Hedef:** Gerçekçi temporal bozulmanın ölçülmesi

### Faz 2 — Behavioral Drift Analizi (Ana Katkı)
- KL divergence, Jensen–Shannon divergence, entropy değişimi, prevalence shift, effect size
- **Çıktılar:** Top drifting features tablosu, kategori bazında drift figürü, sekans evrim analizi
- **Kategoriler:** Reflection & Dynamic Loading, Network, Cryptography, Anti-analysis, Persistence, Accessibility & Overlay, Privacy-sensitive APIs
- **İstatistiksel testler:** Sayısal → Mann–Whitney U, KS testi / Binary → Chi-square, Fisher exact

> Statik vs dinamik özelliklerin ayrı ayrı nasıl drift ettiği de analiz edilecek. (AndroZoo feature extraction tamamlandığında eklenecek.)

### Faz 3 — Hafif Adaptasyon (1-2 sayfa, tek tablo)
- **Veri:** AndroZoo'nun temporal k-fold ile oluşturulmuş %10'luk subsetleri (5 fold, zamana göre sıralı — data leakage önlemek için klasik k-fold değil)
- **Setup A (Unsupervised):** Sadece dağılım istatistikleri, etiket yok → akademik açıdan daha savunulabilir
- **Setup B (Supervised few-shot):** Sınırlı etiketli sample (%1, %5, %10) → daha güçlü performans

| Setup | Etiket | Akademik Güç | Performans |
|---|---|---|---|
| No adaptation | ❌ | baseline | düşük |
| Unsupervised | ❌ | yüksek | orta |
| Supervised few-shot | ✅ | orta | yüksek |
| Full retraining | ✅ | üst sınır | en yüksek |

**Tercih edilen yöntemler:** Drift-aware feature weighting (w_i ∝ 1/drift_i), CORAL / adaptive normalization. Karmaşık continual learning veya active learning pipeline'larından kaçınılacak.

**Hedef bulgu:**
> "%10 gelecek-domain verisi, temporal performans kaybının önemli bir bölümünü telafi eder."

---

## Reviewer Pozisyonlaması

Paper şunu **ima etmemeli:**
- Concept drift çözüldü
- Yeniden eğitime artık gerek yok
- Adaptasyon birincil katkıdır

Paper şunu söylemeli:
> "Runtime davranışsal drift'i karakterize ediyoruz ve bu anlayışın hafif bir kalibrasyon için kullanılıp kullanılamayacağını araştırıyoruz."

---

## Hedef Venue
TDSC veya TIFS — pratik deployment ve behavioral explainability vurgusuyla her ikisi de uygun.
