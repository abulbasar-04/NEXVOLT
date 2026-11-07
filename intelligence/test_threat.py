from threat_intelligence import analyze_threat_intelligence

url = input("Enter website URL: ")

result = analyze_threat_intelligence(url)

print("\n===== NEXVOLT THREAT INTELLIGENCE =====")

for key, value in result.items():
    print(f"{key}: {value}")
