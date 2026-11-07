from certificate_analyzer import analyze_certificate

result = analyze_certificate("https://google.com")

print("\n===== NEXVOLT CERTIFICATE ANALYSIS =====")

for key, value in result.items():
    print(f"{key}: {value}")
