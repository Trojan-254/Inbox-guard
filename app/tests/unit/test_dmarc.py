"""
Unit tests for DMARC record analysis
"""
import pytest

from app.services.dns.dmarc import analyze_dmarc_record


class TestDMARCAnalysis:
    """Test cases for DMARC analysis"""

    def test_valid_dmarc(self):
        """Test a valid DMARC record"""
        record = "v=DMARC1; p=reject; rua=mailto:dmarc@example.com"
        result = analyze_dmarc_record(record)
        
        assert result["status"] == "valid"
        assert result["value"] == record
        assert not result["issues"]
        assert "looks good" in result["recommendations"][0]
    
    def test_missing_version(self):
        """Test DMARC record missing version tag"""
        record = "p=none; rua=mailto:dmarc@example.com"
        result = analyze_dmarc_record(record)
        
        assert result["status"] == "invalid"
        assert "does not start with 'v=DMARC1'" in result["issues"][0]
    
    def test_missing_policy(self):
        """Test DMARC record missing policy tag"""
        record = "v=DMARC1; rua=mailto:dmarc@example.com"
        result = analyze_dmarc_record(record)
        
        assert result["status"] == "invalid"
        assert "missing 'p='" in result["issues"][0]
    
    def test_none_policy(self):
        """Test DMARC record with 'none' policy"""
        record = "v=DMARC1; p=none; rua=mailto:dmarc@example.com"
        result = analyze_dmarc_record(record)
        
        assert result["status"] == "warning"
        assert "policy is set to 'none'" in result["issues"][0]
    
    def test_invalid_policy(self):
        """Test DMARC record with invalid policy"""
        record = "v=DMARC1; p=invalid; rua=mailto:dmarc@example.com"
        result = analyze_dmarc_record(record)
        
        assert result["status"] == "invalid"
        assert "invalid policy value" in result["issues"][0]
    
    def test_missing_rua(self):
        """Test DMARC record missing aggregate report URI"""
        record = "v=DMARC1; p=reject;"
        result = analyze_dmarc_record(record)
        
        assert result["status"] == "warning"
        assert "no aggregate report address" in result["issues"][0]
    
    def test_partial_percent(self):
        """Test DMARC record with partial deployment percentage"""
        record = "v=DMARC1; p=reject; pct=50; rua=mailto:dmarc@example.com"
        result = analyze_dmarc_record(record)
        
        assert result["status"] == "warning"
        assert "policy applies to only 50%" in result["issues"][0]