import os

print("--- ROZPOCZYNAM TEST IMPORTÓW ---")
print(f"Jestem w katalogu: {os.getcwd()}")

try:
    from utils.http_client import HttpClient
    print("✅ SUKCES: Poprawnie zaimportowano HTTPClient z utils.")
except ImportError as e:
    print(f"❌ BŁĄD: Nie udało się zaimportować HTTPClient. Powód: {e}")
except Exception as e:
    print(f"❌ KRYTYCZNY BŁĄD: {e}")

print("--- ZAKOŃCZONO TEST ---")