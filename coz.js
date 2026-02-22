Java.perform(function () {
    console.log("\n[*] Dinamik analiz başlıyor... Gizli şifreyi yakalayacağız.");

    // AES şifre çözme sınıfını yakalayalım
    // Sınıf: sg.vantagepoint.a.a  Metot: a
    var cryptoClass = Java.use('sg.vantagepoint.a.a');

    cryptoClass.a.implementation = function (arg1, arg2) {
        // Orijinal fonksiyonu çalıştır ve sonucunu (şifresi çözülmüş byte array) al
        var decryptedBytes = this.a(arg1, arg2);

        // Byte array'i okunabilir bir metne (String) çevir
        var secret = "";
        for (var i = 0; i < decryptedBytes.length; i++) {
            secret += String.fromCharCode(decryptedBytes[i]);
        }

        console.log("\n[!] YAKALANDI!");
        console.log("[+] Çözülen Gizli Şifre: " + secret);
        console.log("[+]-----------------------------------[+]");

        return decryptedBytes;
    };
});