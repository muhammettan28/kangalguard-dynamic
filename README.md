# Benign directory
python batch_analyzer.py --dir ./benign --label benign

# Malware directory
python batch_analyzer.py --dir ./malware --label malware

# Test: first 5 APK, 30sn timeout
python batch_analyzer.py --dir ./benign --label benign --limit 5 --timeout 30
