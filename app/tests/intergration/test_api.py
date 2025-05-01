"""
Integration tests for the API endpoints
"""
import pytest
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)


class TestDNSVerificationAPI:
    """Test cases for DNS verification API endpoints"""
    
    def test_health_check(self):
        """Test the health check endpoint"""
        response = client.get("/api/v1/health")
        assert response.status_code == 200
        assert response.json() == {"status": "healthy"}
    
    @pytest.mark.parametrize("domain", [
        "google.com",
        "microsoft.com",
        "github.com"
    ])
    def test_verify_valid_domain(self, domain):
        """Test verifying a valid domain"""
        payload = {
            "domain": domain,
            "check_spf": True,
            "check_dkim": True,
            "check_dmarc": True
        }
        
        response = client.post("/api/v1/dns/verify", json=payload)
        
        assert response.status_code == 200
        result = response.json()
        assert result["domain"] == domain
        assert "overall_status" in result
        assert "timestamp" in result
        
        if "spf_analysis" in result:
            assert "status" in result["spf_analysis"]
            assert "record_type" in result["spf_analysis"]
        
        if "dkim_analysis" in result:
            assert "status" in result["dkim_analysis"]
            assert "record_type" in result["dkim_analysis"]
        
        if "dmarc_analysis" in result:
            assert "status" in result["dmarc_analysis"]
            assert "record_type" in result["dmarc_analysis"]
    
    def test_verify_invalid_domain(self):
        """Test verifying an invalid domain"""
        payload = {
            "domain": "invalid-domain-123456789.com",
            "check_spf": True,
            "check_dkim": True,
            "check_dmarc": True
        }
        
        response = client.post("/api/v1/dns/verify", json=payload)
        
        # The API should still return a 200 response with analysis results
        assert response.status_code == 200
        result = response.json()
        assert result["domain"] == "invalid-domain-123456789.com"
        assert "overall_status" in result
        assert result["overall_status"] == "critical"  # Since records won't exist
    
    def test_verify_malformed_domain(self):
        """Test verifying a malformed domain"""
        payload = {
            "domain": "not a domain",
            "check_spf": True,
            "check_dkim": True,
            "check_dmarc": True
        }
        
        response = client.post("/api/v1/dns/verify", json=payload)
        
        # Should return a 400 Bad Request
        assert response.status_code == 400
        assert "detail" in response.json()
    
    def test_domain_history_endpoint(self):
        """Test retrieving domain history"""
        response = client.get("/api/v1/dns/history/example.com")
        
        # Should return a 200 OK with an empty list (since we don't have a DB yet)
        assert response.status_code == 200
        assert isinstance(response.json(), list)