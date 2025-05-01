"""
Pytest configuration and fixtures
"""
import os
import pytest
from unittest.mock import patch

# Set test environment variables
os.environ["LOG_LEVEL"] = "DEBUG"
os.environ["CELERY_BROKER_URL"] = "memory://"
os.environ["CELERY_RESULT_BACKEND"] = "memory://"


@pytest.fixture
def mock_dns_lookup():
    """
    Fixture to mock DNS lookups
    """
    with patch("app.services.dns.lookup.lookup_txt_record") as mock_lookup:
        # Mock responses for common domains
        async def mock_txt_response(domain):
            # SPF records
            if domain == "google.com":
                return ["v=spf1 include:_spf.google.com ~all"]
            elif domain == "microsoft.com":
                return ["v=spf1 include:spf.protection.outlook.com -all"]
            elif domain == "github.com":
                return ["v=spf1 include:_spf.google.com include:_netblocks.google.com include:_netblocks2.google.com include:_netblocks3.google.com include:spf.protection.outlook.com include:mail.zendesk.com include:_spf.salesforce.com ~all"]
            # DKIM records
            elif "_domainkey.google.com" in domain:
                return ["v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxmREOr/"]
            elif "_domainkey.microsoft.com" in domain:
                return ["v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvrgj"]
            # DMARC records
            elif "_dmarc.google.com" in domain:
                return ["v=DMARC1; p=reject; sp=reject; rua=mailto:mailauth-reports@google.com"]
            elif "_dmarc.microsoft.com" in domain:
                return ["v=DMARC1; p=none; pct=100; rua=mailto:d@rua.contoso.com; ruf=mailto:d@ruf.contoso.com; fo=1"]
            # Default empty response
            else:
                return []
        
        mock_lookup.side_effect = mock_txt_response
        yield mock_lookup