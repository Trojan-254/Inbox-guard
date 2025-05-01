"""
Unit tests for DKIM record analysis
"""
import pytest

from app.services.dns.dkim import analyze_dkim_record


class TestDKIMAnalysis:
    """Test cases for DKIM analysis"""

    def test_valid_dkim(self):
        """Test a valid DKIM record"""
        record = "v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA123456789abcdefghijk"
        result = analyze_dkim_record(record, "_domainkey")
        
        assert result["status"] == "valid"
        assert result["value"] == record
        assert not result["issues"]
        assert "looks good" in result["recommendations"][0]
    
    def test_missing_version(self):
        """Test DKIM record missing version tag"""
        record = "k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA123456789abcdefghijk"
        result = analyze_dkim_record(record, "_domainkey")
        
        assert result["status"] == "invalid"
        assert "does not contain 'v=DKIM1'" in result["issues"][0]
    
    def test_missing_public_key(self):
        """Test DKIM record missing public key"""
        record = "v=DKIM1; k=rsa;"
        result = analyze_dkim_record(record, "_domainkey")
        
        assert result["status"] == "invalid"
        assert "missing 'p='" in result["issues"][0]
    
    def test_revoked_key(self):
        """Test DKIM record with revoked key"""
        record = "v=DKIM1; k=rsa; p=;"
        result = analyze_dkim_record(record, "_domainkey")
        
        assert result["status"] == "invalid"
        assert "revoked" in result["issues"][0]
    
    def test_unsupported_key_type(self):
        """Test DKIM record with unsupported key type"""
        record = "v=DKIM1; k=unsupported; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA123456789abcdefghijk"
        result = analyze_dkim_record(record, "_domainkey")
        
        assert result["status"] == "warning"
        assert "unsupported key type" in result["issues"][0]