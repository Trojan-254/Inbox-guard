"""
Enhanced DMARC (Domain-based Message Authentication, Reporting and Conformance) Record Analysis
"""
import logging
import re
from typing import Dict, List, Any, Optional, Set

logger = logging.getLogger(__name__)

class DMARCAnalyzer:
    """Comprehensive DMARC record analyzer with best practice checks"""
    
    # Constants
    MAX_RECORD_LENGTH = 255
    VALID_POLICIES = {"none", "quarantine", "reject"}
    VALID_REPORT_FORMATS = {"afrf", "iodef"}
    VALID_ALIGNMENT_MODES = {"r", "s"}
    VALID_OPTIONS = {"0", "1"}
    
    def __init__(self):
        self.tag_patterns = {
            'v': re.compile(r'v=([^;]+)'),
            'p': re.compile(r'p=([^;]+)'),
            'sp': re.compile(r'sp=([^;]+)'),
            'rua': re.compile(r'rua=([^;]+)'),
            'ruf': re.compile(r'ruf=([^;]+)'),
            'pct': re.compile(r'pct=([^;]+)'),
            'adkim': re.compile(r'adkim=([^;]+)'),
            'aspf': re.compile(r'aspf=([^;]+)'),
            'rf': re.compile(r'rf=([^;]+)'),
            'ri': re.compile(r'ri=([^;]+)'),
            'fo': re.compile(r'fo=([^;]+)')
        }

    def analyze(self, dmarc_value: str) -> Dict[str, Any]:
        """
        Analyze a DMARC record with comprehensive validation
        
        Args:
            dmarc_value: Raw DMARC record string
            
        Returns:
            {
                "record_type": "DMARC",
                "status": "valid|warning|invalid",
                "value": original_value,
                "tags": Dict[str, str],
                "issues": List[str],
                "recommendations": List[str],
                "policy_strength": int  # 0=none, 1=quarantine, 2=reject
            }
        """
        if not dmarc_value:
            return self._empty_result()
            
        dmarc_value = dmarc_value.strip()
        result = self._initialize_result(dmarc_value)
        tags = self._extract_tags(dmarc_value)
        result['tags'] = tags
        
        # Run validation checks
        self._validate_version(tags, result)
        self._validate_policy(tags, result)
        self._validate_subdomain_policy(tags, result)
        self._validate_reporting(tags, result)
        self._validate_alignment(tags, result)
        self._validate_percentage(tags, result)
        self._validate_failure_options(tags, result)
        self._validate_record_length(dmarc_value, result)
        
        # Calculate policy strength
        self._calculate_policy_strength(tags, result)
        
        # Finalize recommendations
        self._finalize_recommendations(result)
        
        return result
    
    def _initialize_result(self, dmarc_value: str) -> Dict[str, Any]:
        """Initialize the analysis result structure"""
        return {
            "record_type": "DMARC",
            "status": "valid",
            "value": dmarc_value,
            "tags": {},
            "issues": [],
            "recommendations": [],
            "policy_strength": 0
        }
    
    def _empty_result(self) -> Dict[str, Any]:
        """Return result for empty input"""
        return {
            "record_type": "DMARC",
            "status": "invalid",
            "value": "",
            "tags": {},
            "issues": ["Empty DMARC record provided"],
            "recommendations": ["Provide a valid DMARC record"],
            "policy_strength": 0
        }
    
    def _extract_tags(self, dmarc_value: str) -> Dict[str, str]:
        """Extract all DMARC tags and their values"""
        tags = {}
        for tag_name, pattern in self.tag_patterns.items():
            match = pattern.search(dmarc_value)
            if match:
                tags[tag_name] = match.group(1).lower()
        return tags
    
    def _validate_version(self, tags: Dict[str, str], result: Dict[str, Any]) -> None:
        """Check DMARC version tag"""
        if 'v' not in tags:
            result["status"] = "invalid"
            result["issues"].append("Missing version tag (v=)")
            result["recommendations"].append("DMARC record must include 'v=DMARC1'")
        elif tags['v'] != "dmarc1":
            result["status"] = "invalid"
            result["issues"].append(f"Unsupported version '{tags['v']}'")
            result["recommendations"].append("Use 'v=DMARC1' as the version tag")
    
    def _validate_policy(self, tags: Dict[str, str], result: Dict[str, Any]) -> None:
        """Validate policy tag"""
        if 'p' not in tags:
            result["status"] = "invalid"
            result["issues"].append("Missing policy tag (p=)")
            result["recommendations"].append("Add a policy tag (p=none, p=quarantine, or p=reject)")
        elif tags['p'] not in self.VALID_POLICIES:
            result["status"] = "invalid"
            result["issues"].append(f"Invalid policy value '{tags['p']}'")
            result["recommendations"].append(f"Use one of: {', '.join(sorted(self.VALID_POLICIES))}")
        elif tags['p'] == "none":
            result["status"] = "warning"
            result["issues"].append("Policy is set to 'none' (monitoring only)")
            result["recommendations"].append("Consider moving to 'quarantine' or 'reject' after monitoring")
    
    def _validate_subdomain_policy(self, tags: Dict[str, str], result: Dict[str, Any]) -> None:
        """Validate subdomain policy tag"""
        if 'sp' in tags:
            if tags['sp'] not in self.VALID_POLICIES:
                result["status"] = "invalid"
                result["issues"].append(f"Invalid subdomain policy value '{tags['sp']}'")
                result["recommendations"].append(f"Use one of: {', '.join(sorted(self.VALID_POLICIES))}")
            elif tags['sp'] == "none" and tags.get('p') != "none":
                result["status"] = "warning"
                result["issues"].append("Subdomain policy is weaker than domain policy")
                result["recommendations"].append("Consider using the same policy for subdomains")
    
    def _validate_reporting(self, tags: Dict[str, str], result: Dict[str, Any]) -> None:
        """Validate reporting addresses"""
        if 'rua' not in tags:
            result["status"] = "warning"
            result["issues"].append("Missing aggregate report address (rua=)")
            result["recommendations"].append("Add rua=mailto:reports@yourdomain.com to receive DMARC reports")
        
        if 'ruf' in tags:
            result["recommendations"].append("Forensic reports (ruf=) may generate high email volume - monitor carefully")
    
    def _validate_alignment(self, tags: Dict[str, str], result: Dict[str, Any]) -> None:
        """Validate alignment modes"""
        for alignment_tag in ['adkim', 'aspf']:
            if alignment_tag in tags and tags[alignment_tag] not in self.VALID_ALIGNMENT_MODES:
                result["status"] = "warning"
                result["issues"].append(f"Invalid {alignment_tag} value '{tags[alignment_tag]}'")
                result["recommendations"].append(f"Use 'r' (relaxed) or 's' (strict) for {alignment_tag}")
    
    def _validate_percentage(self, tags: Dict[str, str], result: Dict[str, Any]) -> None:
        """Validate percentage tag"""
        if 'pct' in tags:
            try:
                pct = int(tags['pct'])
                if pct < 1 or pct > 100:
                    result["status"] = "invalid"
                    result["issues"].append(f"Invalid pct value '{tags['pct']}' (must be 1-100)")
                    result["recommendations"].append("Use pct=100 for full policy application")
                elif pct < 100:
                    result["status"] = "warning"
                    result["issues"].append(f"Policy applies to only {pct}% of messages")
                    result["recommendations"].append("Consider increasing to pct=100 for full protection")
            except ValueError:
                result["status"] = "invalid"
                result["issues"].append(f"Invalid pct value '{tags['pct']}'")
                result["recommendations"].append("pct must be a number between 1 and 100")
    
    def _validate_failure_options(self, tags: Dict[str, str], result: Dict[str, Any]) -> None:
        """Validate failure reporting options"""
        if 'rf' in tags:
            invalid_formats = set(tags['rf'].split(':')) - self.VALID_REPORT_FORMATS
            if invalid_formats:
                result["status"] = "warning"
                result["issues"].append(f"Invalid report formats: {', '.join(invalid_formats)}")
                result["recommendations"].append(f"Use only: {', '.join(sorted(self.VALID_REPORT_FORMATS))}")
        
        if 'fo' in tags:
            invalid_options = set(tags['fo'].split(':')) - self.VALID_OPTIONS
            if invalid_options:
                result["status"] = "warning"
                result["issues"].append(f"Invalid failure options: {', '.join(invalid_options)}")
                result["recommendations"].append("Use only 0 and/or 1 for failure options (fo=)")
    
    def _validate_record_length(self, dmarc_value: str, result: Dict[str, Any]) -> None:
        """Check DMARC record length"""
        if len(dmarc_value) > self.MAX_RECORD_LENGTH:
            result["status"] = "warning"
            result["issues"].append(f"Record length ({len(dmarc_value)} chars) exceeds DNS TXT record limits")
            result["recommendations"].append("Your DNS provider may need to split this record")
    
    def _calculate_policy_strength(self, tags: Dict[str, str], result: Dict[str, Any]) -> None:
        """Calculate policy strength score"""
        policy_strength = {
            "none": 0,
            "quarantine": 1,
            "reject": 2
        }
        result["policy_strength"] = policy_strength.get(tags.get('p', 'none'), 0)
    
    def _finalize_recommendations(self, result: Dict[str, Any]) -> None:
        """Add final recommendations based on issues found"""
        if not result["issues"]:
            result["recommendations"].append("DMARC configuration is optimal")
        
        # Security recommendations
        if result["policy_strength"] < 2:
            result["recommendations"].append(
                "For maximum protection, consider moving to 'p=reject'"
            )