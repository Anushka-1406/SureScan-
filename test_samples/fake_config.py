# FAKE secrets used only to test the scanner. None of these are real.
password = "abc123"
API_KEY = "sk-test-1234567890"
aws = "AKIAABCDEFGHIJKLMNOP"
safe = os.environ.get("DB_PASSWORD")   # reading from environment: should NOT be flagged
