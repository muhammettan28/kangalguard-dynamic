# Benign directory
python batch_analyzer.py --dir ./data/benign --label benign

# Malware directory
python batch_analyzer.py --dir ./data/malware --label malware

# Test: first 5 APK, 30sn timeout
python batch_analyzer.py --dir ./data/benign --label benign --limit 5 --timeout 30
