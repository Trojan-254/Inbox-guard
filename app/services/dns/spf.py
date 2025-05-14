"""
SPF (Sender Policy Framework) Record Analysis
"""
import logging
import re
from typing import Dict, List, Any, Optional

logger = logging.getLogger(__name__)

class SPFAnalyzer:
    """Comprehensive SPF record analyzer with best practice checks"""
    
    # Constants
    MAX_DNS_LOOKUPS = 10
    MAX_RECORD_LENGTH = 255
    SPF_VERSION_PATTERN = r'^v=spf1\s'
    
    def __init__(self):
        self.mechanism_patterns = {
            'include': re.compile(r'(?:^|\s)include:([^\s]+)'),
            'a': re.compile(r'(?:^|\s)a(?::([^\s]+))?(?:\s|$)'),
            'mx': re.compile(r'(?:^|\s)mx(?::([^\s]+))?(?:\s|$)'),
            'ptr': re.compile(r'(?:^|\s)ptr:([^\s]+)'),
            'exists': re.compile(r'(?:^|\s)exists:([^\s]+)'),
            'ip4': re.compile(r'(?:^|\s)ip4:([^\s]+)'),
            'ip6': re.compile(r'(?:^|\s)ip6:([^\s]+)'),
            'all': re.compile(r'(?:^|\s)([~?+-]all)\s*$')
        }

    def analyze(self, spf_value: str) -> Dict[str, Any]:
        """
        Analyze an SPF record with comprehensive validation
        
        Args:
            spf_value: Raw SPF record string
            
        Returns:
            {
                "record_type": "SPF",
                "status": "valid|warning|invalid",
                "value": original_value,
                "issues": List[str],
                "recommendations": List[str],
                "mechanisms": Dict[str, List[str]],
                "lookup_count": int
            }
        """
        if not spf_value:
            return self._empty_result("Empty SPF record provided")
            
        spf_value = spf_value.strip()
        result = self._initialize_result(spf_value)
        
        # Extract mechanisms first
        mechanisms = self._extract_mechanisms(spf_value)
        result['mechanisms'] = mechanisms
        result['lookup_count'] = self._count_dns_lookups(mechanisms)
        
        # Run validation checks
        self._validate_version(spf_value, result)
        self._validate_all_mechanism(spf_value, result)
        self._validate_dns_lookups(result)
        self._validate_deprecated_mechanisms(mechanisms, result)
        self._validate_ip_ranges(mechanisms, result)
        self._validate_record_length(spf_value, result)
        
        # Finalize recommendations
        self._finalize_recommendations(result)
        
        return result
    
    def _initialize_result(self, spf_value: str) -> Dict[str, Any]:
        """Initialize the analysis result structure"""
        return {
            "record_type": "SPF",
            "status": "valid",
            "value": spf_value,
            "issues": [],
            "recommendations": [],
            "mechanisms": {},
            "lookup_count": 0
        }
    
    def _empty_result(self, message: str) -> Dict[str, Any]:
        """Return result for empty input"""
        return {
            "record_type": "SPF",
            "status": "invalid",
            "value": "",
            "issues": [message],
            "recommendations": ["Provide a valid SPF record"],
            "mechanisms": {},
            "lookup_count": 0
        }
    
    def _extract_mechanisms(self, spf_value: str) -> Dict[str, List[str]]:
        """Extract all SPF mechanisms and their values"""
        mechanisms = {}
        for mech_name, pattern in self.mechanism_patterns.items():
            matches = pattern.findall(spf_value)
            if matches:
                mechanisms[mech_name] = [m for m in matches if m] if mech_name != 'all' else matches
        return mechanisms
    
    def _count_dns_lookups(self, mechanisms: Dict[str, List[str]]) -> int:
        """Count total DNS lookups required by the SPF record"""
        lookup_mechanisms = ['include', 'a', 'mx', 'ptr', 'exists']
        return sum(len(mechanisms.get(mech, [])) for mech in lookup_mechanisms)
    
    def _validate_version(self, spf_value: str, result: Dict[str, Any]) -> None:
        """Check SPF version prefix"""
        if not re.match(self.SPF_VERSION_PATTERN, spf_value):
            result["status"] = "invalid"
            result["issues"].append("Missing or invalid SPF version identifier")
            result["recommendations"].append("SPF record must start with 'v=spf1'")
    
    def _validate_all_mechanism(self, spf_value: str, result: Dict[str, Any]) -> None:
        """Validate the ALL mechanism"""
        all_mechanisms = result['mechanisms'].get('all', [])
        
        if not all_mechanisms:
            result["status"] = "warning"
            result["issues"].append("Missing 'all' mechanism")
            result["recommendations"].append("Add default mechanism like '~all' (soft fail) or '-all' (hard fail)")
        elif '+all' in all_mechanisms:
            result["status"] = "invalid"
            result["issues"].append("Dangerous '+all' mechanism allows all senders")
            result["recommendations"].append("Replace '+all' with restrictive mechanism ('-all' or '~all')")
    
    def _validate_dns_lookups(self, result: Dict[str, Any]) -> None:
        """Validate DNS lookup count"""
        if result['lookup_count'] > self.MAX_DNS_LOOKUPS:
            result["status"] = "invalid"
            result["issues"].append(
                f"Exceeds maximum DNS lookups ({result['lookup_count']}/{self.MAX_DNS_LOOKUPS})"
            )
            result["recommendations"].append(
                "Reduce DNS lookups by removing unnecessary includes or using SPF flattening"
            )
    
    def _validate_deprecated_mechanisms(self, mechanisms: Dict[str, List[str]], result: Dict[str, Any]) -> None:
        """Check for deprecated mechanisms"""
        if 'ptr' in mechanisms:
            result["status"] = "warning"
            result["issues"].append("Deprecated 'ptr' mechanism found")
            result["recommendations"].append("Remove 'ptr' mechanism as it's inefficient")
    
    def _validate_ip_ranges(self, mechanisms: Dict[str, List[str]], result: Dict[str, Any]) -> None:
        """Validate IP address ranges"""
        for ip in mechanisms.get('ip4', []):
            if ip == "0.0.0.0/0":
                result["status"] = "invalid"
                result["issues"].append("Overly permissive IPv4 range (0.0.0.0/0)")
                result["recommendations"].append("Restrict IP ranges to only necessary sending hosts")
        
        for ip in mechanisms.get('ip6', []):
            if ip == "::/0":
                result["status"] = "invalid"
                result["issues"].append("Overly permissive IPv6 range (::/0)")
                result["recommendations"].append("Restrict IPv6 ranges to only necessary sending hosts")
    
    def _validate_record_length(self, spf_value: str, result: Dict[str, Any]) -> None:
        """Check SPF record length"""
        if len(spf_value) > self.MAX_RECORD_LENGTH:
            result["status"] = "warning"
            result["issues"].append(
                f"Record length ({len(spf_value)} chars) exceeds DNS TXT record limits"
            )
            result["recommendations"].append(
                "Consider SPF flattening or reducing mechanisms"
            )
    
    def _finalize_recommendations(self, result: Dict[str, Any]) -> None:
        """Add final recommendations based on issues found"""
        if not result["issues"]:
            result["recommendations"].append("SPF record configuration is optimal")
        
        # Add general security recommendation
        if '-all' not in result['mechanisms'].get('all', []):
            result["recommendations"].append(
                "For maximum security, consider using '-all' instead of '~all'"
            )