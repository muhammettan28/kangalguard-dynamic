#!/bin/bash
# ~/GitHub/kangalguard-dynamic/restart_emulators.sh

GMTOOL="/home/tan/genymotion/gmtool"

declare -A EMULATORS=(
    ["127.0.0.1:6555"]="73d80fc5-4023-479b-961b-ad02ee901a45"
    ["127.0.0.1:6562"]="dbf1ab74-2ade-466d-b043-f8130f5b0c6a"
    ["127.0.0.1:6569"]="953f40d8-3e5e-48ef-a506-b7a0e371809f"
)

stop_all() {
    echo "Tum emulatorler kapatiliyor..."
    for ip in "${!EMULATORS[@]}"; do
        uuid="${EMULATORS[$ip]}"
        echo "  $ip durduruluyor..."
        adb disconnect "$ip" 2>/dev/null
        $GMTOOL admin stop "$uuid"
    done
    echo "Tum emulatorler kapatildi"
}

start_all() {
    echo "Tum emulatorler baslatiliyor..."
    for ip in "${!EMULATORS[@]}"; do
        uuid="${EMULATORS[$ip]}"
        echo "  $ip baslatiliyor..."
        $GMTOOL admin start "$uuid"
    done
    echo "Emulatorler ayaga kalkiyor, 20 saniye bekleniyor..."
    sleep 20
    for ip in "${!EMULATORS[@]}"; do
        adb connect "$ip"
    done
    echo ""
    echo "Guncel ADB cihaz listesi:"
    adb devices
}

recover() {
    echo "Emulator durumlari kontrol ediliyor..."
    for ip in "${!EMULATORS[@]}"; do
        uuid="${EMULATORS[$ip]}"
        status=$(adb -s "$ip" get-state 2>/dev/null)
        if [ "$status" == "device" ]; then
            echo "OK $ip -> aktif"
        else
            echo "!! $ip -> offline! Yeniden baslatiliyor..."
            adb disconnect "$ip" 2>/dev/null
            $GMTOOL admin stop "$uuid" 2>/dev/null
            sleep 3
            $GMTOOL admin start "$uuid"
            echo "Bekleniyor..."
            sleep 15
            adb connect "$ip"
            new_status=$(adb -s "$ip" get-state 2>/dev/null)
            if [ "$new_status" == "device" ]; then
                echo "OK $ip -> kurtarildi"
            else
                echo "WARN $ip -> baslatılamadı"
            fi
        fi
    done
    echo ""
    echo "Guncel ADB cihaz listesi:"
    adb devices
}

case "$1" in
    stop)    stop_all ;;
    start)   start_all ;;
    restart) stop_all; sleep 5; start_all ;;
    recover) recover ;;
    *)
        echo "Kullanim: $0 {stop|start|restart|recover}"
        echo ""
        echo "  stop     -> Tum emulatorleri kapat"
        echo "  start    -> Tum emulatorleri baslat"
        echo "  restart  -> Kapat ve tekrar baslat (RAM temizleme)"
        echo "  recover  -> Sadece crash olan emulatorleri kurtarmaya calis"
        ;;
esac
