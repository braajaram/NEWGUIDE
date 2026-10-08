import pytest
from app.scanners import analyze_email, analyze_file, validate_url
from app.security import hash_password, verify_password

def test_ssrf_rejects_loopback():
    with pytest.raises(ValueError): validate_url("http://127.0.0.1/admin")

def test_file_hashes_and_never_executes():
    result = analyze_file("note.txt", b"hello")
    assert result["sha256"] == "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
    assert result["limitations"]

def test_email_parses_mismatch():
    result = analyze_email(b"From: sender@example.com\nReply-To: attacker.invalid\n\nHello")
    assert result["headers"]["from"] == "sender@example.com"
    assert result["indicators"]

def test_password_hashing():
    encoded = hash_password("correct horse battery staple")
    assert verify_password("correct horse battery staple", encoded)
    assert not verify_password("wrong", encoded)
