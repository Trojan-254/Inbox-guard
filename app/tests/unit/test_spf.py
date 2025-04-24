"""
Unit tests for SPF record analysis
"""
import pytest
from app.services.dns.spf import analyze_spf_record


class TestSPFAnalysis:
    """Test cases for SPF analysis"""
    
    def test_valid_spf(self):
        """Test a valid SPF record"""
        record = "v=spf1 include:_spf.google.com include:sendgrid.net ip4:192.168.1.1 ~all"
        result = analyze_spf_record(record)
        
        assert result["status"] == "valid"
        assert result["value"] == record
        assert not result["issues"]
        assert "looks good" in result["recommendations"][0]
    
    def test_missing_all(self):
        """Test SPF record missing the 'all' mechanism"""
        record = "v=spf1 include:_spf.google.com"
        result = analyze_spf_record(record)
        
        assert result["status"] == "warning"
        assert "does not end with an 'all' mechanism" in result["issues"][0]
        assert any("Add '~all'" in rec for rec in result["recommendations"])
    
    def test_plus_all(self):
        """Test SPF record with dangerous '+all'"""
        record = "v=spf1 include:_spf.google.com +all"
        result = analyze_spf_record(record)
        
        assert result["status"] == "invalid"
        assert "contains '+all'" in result["issues"][0]
        assert any("Replace '+all'" in rec for rec in result["recommendations"])
    
    def test_too_many_lookups(self):
        """Test SPF record with too many DNS lookups"""
        record = "v=spf1 include:a.com include:b.com include:c.com include:d.com include:e.com include:f.com include:g.com include:h.com include:i.com include:j.com include:k.com ~all"
        result = analyze_spf_record(record)
        
        assert result["status"] == "invalid"
        assert "too many DNS lookups" in result["issues"][0]
        assert any("Simplify your SPF" in rec for rec in result["recommendations"])
    
    def test_missing_version(self):
        """Test SPF record with missing version"""
        record = "include:_spf.google.com ~all"
        result = analyze_spf_record(record)
        
        assert result["status"] == "invalid"
        assert "does not start with 'v=spf1'" in result["issues"][0]
    
    def test_deprecated_ptr(self):
        """Test SPF record with deprecated ptr mechanism"""
        record = "v=spf1 ptr:example.com ~all"
        result = analyze_spf_record(record)
        
        assert result["status"] == "warning"
        assert "deprecated 'ptr' mechanism" in result["issues"][0]