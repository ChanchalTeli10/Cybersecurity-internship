import unicodedata

#  List of Unicode homoglyphs that look like English letters
homoglyphs = {
    'а': 'a', 'е': 'e', 'о': 'o', 'с': 'c', 'р': 'p', 'х': 'x',
    'і': 'i', 'ѕ': 's', 'ѵ': 'v',
    'Α': 'A', 'Β': 'B', 'Ε': 'E', 'Ζ': 'Z', 'Η': 'H', 'Ι': 'I',
    'Κ': 'K', 'Μ': 'M', 'Ν': 'N', 'Ο': 'O', 'Ρ': 'P', 'Τ': 'T',
    'Υ': 'Y', 'Χ': 'X',
}

#  Find the script (language block) of a character
def get_script(char):
    try:
        return unicodedata.name(char).split(' ')[0]
    except ValueError:
        return 'UNKNOWN'

#  Check if the URL has homoglyphs or mixed scripts
def detect_homograph(url):
    suspicious_chars = []
    scripts_found = set()

    for ch in url:
        scripts_found.add(get_script(ch))
        if ch in homoglyphs:
            suspicious_chars.append((ch, homoglyphs[ch]))

    has_latin = any('LATIN' in s for s in scripts_found)
    has_non_latin = any(s not in ('LATIN', 'COMMON', 'UNKNOWN', 'DIGIT') for s in scripts_found)
    is_suspicious = (len(suspicious_chars) > 0) and has_latin and has_non_latin

    return is_suspicious, suspicious_chars, scripts_found

#  MAIN CODE 
url = input(" Enter the URL to check: ").strip()

suspicious, chars, scripts = detect_homograph(url)

print(f"\n📎 URL: {url}")
print(f" Scripts used: {scripts}")

if suspicious:
    print("⚠️ WARNING: Suspicious homoglyphs detected!")
    for original, looks_like in chars:
        print(f"  → '{original}' looks like '{looks_like}'")
else:
    print("✅ This URL looks clean — no homoglyphs found.")
