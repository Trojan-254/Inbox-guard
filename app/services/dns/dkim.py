"""
Enhanced DKIM (DomainKeys Identified Mail) Record Analysis
"""
import logging
import re
from typing import Dict, List, Any, Optional

logger = logging.getLogger(__name__)

class DKIMAnalyzer:
    """Comprehensive DKIM record analyzer with best practice checks"""
    
    # Constants
    MAX_RECORD_LENGTH = 255
    SUPPORTED_KEY_TYPES = {"rsa", "ed25519"}
    SUPPORTED_HASH_ALGS = {"sha1", "sha256"}
    SUPPORTED_SERVICE_TYPES = {"email", "*"}
    
    def __init__(self):
        self.tag_patterns = {
            'v': re.compile(r'v=([^;]+)'),
            'p': re.compile(r'p=([^;]*)'),
            'k': re.compile(r'k=([^;]+)'),
            'h': re.compile(r'h=([^;]+)'),
            's': re.compile(r's=([^;]+)'),
            't': re.compile(r't=([^;]+)')
        }

    def analyze(self, dkim_value: str, selector: str = "default") -> Dict[str, Any]:
        """
        Analyze a DKIM record with comprehensive validation
        
        Args:
            dkim_value: Raw DKIM record string
            selector: DKIM selector used (for reference)
            
        Returns:
            {
                "record_type": "DKIM",
                "status": "valid|warning|invalid",
                "selector": selector,
                "value": original_value,
                "tags": Dict[str, str],
                "issues": List[str],
                "recommendations": List[str],
                "key_length": Optional[int]  # For RSA keys
            }
        """
        if not dkim_value:
            return self._empty_result(selector)
            
        dkim_value = dkim_value.strip()
        result = self._initialize_result(dkim_value, selector)
        tags = self._extract_tags(dkim_value)
        result['tags'] = tags
        
        # Run validation checks
        self._validate_version(tags, result)
        self._validate_public_key(tags, result)
        self._validate_key_type(tags, result)
        self._validate_hash_algorithms(tags, result)
        self._validate_service_type(tags, result)
        self._validate_flags(tags, result)
        self._validate_record_length(dkim_value, result)
        
        # Additional RSA key validation if present
        if 'p' in tags and tags.get('k', 'rsa') == 'rsa':
            self._validate_rsa_key(tags['p'], result)
        
        # Finalize recommendations
        self._finalize_recommendations(result)
        
        return result
    
    def _initialize_result(self, dkim_value: str, selector: str) -> Dict[str, Any]:
        """Initialize the analysis result structure"""
        return {
            "record_type": "DKIM",
            "status": "valid",
            "selector": selector,
            "value": dkim_value,
            "tags": {},
            "issues": [],
            "recommendations": [],
            "key_length": None
        }
    
    def _empty_result(self, selector: str) -> Dict[str, Any]:
        """Return result for empty input"""
        return {
            "record_type": "DKIM",
            "status": "invalid",
            "selector": selector,
            "value": "",
            "tags": {},
            "issues": ["Empty DKIM record provided"],
            "recommendations": ["Provide a valid DKIM record"],
            "key_length": None
        }
    
    def _extract_tags(self, dkim_value: str) -> Dict[str, str]:
        """Extract all DKIM tags and their values"""
        tags = {}
        for tag_name, pattern in self.tag_patterns.items():
            match = pattern.search(dkim_value)
            if match:
                tags[tag_name] = match.group(1)
        return tags
    
    def _validate_version(self, tags: Dict[str, str], result: Dict[str, Any]) -> None:
        """Check DKIM version tag"""
        if 'v' not in tags:
            result["status"] = "invalid"
            result["issues"].append("Missing version tag (v=)")
            result["recommendations"].append("DKIM record must include 'v=DKIM1'")
        elif tags['v'] != "DKIM1":
            result["status"] = "invalid"
            result["issues"].append(f"Unsupported version '{tags['v']}'")
            result["recommendations"].append("Use 'v=DKIM1' as the version tag")
    
    def _validate_public_key(self, tags: Dict[str, str], result: Dict[str, Any]) -> None:
        """Validate public key tag"""
        if 'p' not in tags:
            result["status"] = "invalid"
            result["issues"].append("Missing public key tag (p=)")
            result["recommendations"].append("Public key is required in DKIM records")
        elif tags['p'] == "":
            result["status"] = "invalid"
            result["issues"].append("Public key is revoked (p=;)")
            result["recommendations"].append("Generate new DKIM keys and update DNS")
    
    def _validate_key_type(self, tags: Dict[str, str], result: Dict[str, Any]) -> None:
        """Validate key type tag"""
        if 'k' in tags and tags['k'] not in self.SUPPORTED_KEY_TYPES:
            result["status"] = "warning"
            result["issues"].append(f"Unsupported key type '{tags['k']}'")
            result["recommendations"].append(
                f"Use one of: {', '.join(sorted(self.SUPPORTED_KEY_TYPES))}"
            )
    
    def _validate_hash_algorithms(self, tags: Dict[str, str], result: Dict[str, Any]) -> None:
        """Validate hash algorithms tag"""
        if 'h' in tags:
            algs = tags['h'].split(':')
            invalid_algs = [a for a in algs if a not in self.SUPPORTED_HASH_ALGS]
            
            if invalid_algs:
                result["status"] = "warning"
                result["issues"].append(f"Unsupported hash algorithm(s): {', '.join(invalid_algs)}")
                result["recommendations"].append(
                    f"Use only: {', '.join(sorted(self.SUPPORTED_HASH_ALGS))}"
                )
            
            if 'sha1' in algs and 'sha256' not in algs:
                result["status"] = "warning"
                result["issues"].append("Using only SHA-1 which is considered weak")
                result["recommendations"].append("Add SHA-256 to hash algorithms (h=sha1:sha256)")
    
    def _validate_service_type(self, tags: Dict[str, str], result: Dict[str, Any]) -> None:
        """Validate service type tag"""
        if 's' in tags:
            services = tags['s'].split(':')
            invalid_services = [s for s in services if s not in self.SUPPORTED_SERVICE_TYPES]
            
            if invalid_services:
                result["status"] = "warning"
                result["issues"].append(f"Unsupported service type(s): {', '.join(invalid_services)}")
                result["recommendations"].append(
                    f"Use only: {', '.join(sorted(self.SUPPORTED_SERVICE_TYPES))}"
                )
    
    def _validate_flags(self, tags: Dict[str, str], result: Dict[str, Any]) -> None:
        """Validate DKIM flags (t= tag)"""
        if 't' in tags:
            flags = set(tags['t'])
            if 'y' in flags:
                result["status"] = "warning"
                result["issues"].append("Testing mode (t=y) enabled")
                result["recommendations"].append("Remove testing flag in production")
            
            if 's' in flags:
                result["status"] = "warning"
                result["issues"].append("Strict subdomain policy (t=s) may cause delivery issues")
                result["recommendations"].append("Ensure you understand subdomain signing requirements")
    
    def _validate_rsa_key(self, public_key: str, result: Dict[str, Any]) -> None:
        """Validate RSA key length (approximate)"""
        try:
            # Remove whitespace and count base64 chars
            clean_key = re.sub(r'\s+', '', public_key)
            key_length = len(clean_key) * 6 // 8  # Approximate bytes
            
            if key_length < 1024:
                result["status"] = "invalid"
                result["issues"].append(f"RSA key too short (~{key_length} bytes)")
                result["recommendations"].append("Use RSA keys of at least 1024 bits (2048 recommended)")
            result["key_length"] = key_length
        except Exception:
            logger.warning("Could not estimate RSA key length", exc_info=True)
    
    def _validate_record_length(self, dkim_value: str, result: Dict[str, Any]) -> None:
        """Check DKIM record length"""
        if len(dkim_value) > self.MAX_RECORD_LENGTH:
            result["status"] = "warning"
            result["issues"].append(
                f"Record length ({len(dkim_value)} chars) exceeds DNS TXT record limits"
            )
            result["recommendations"].append(
                "Your DNS provider may need to split this record"
            )
    
    def _finalize_recommendations(self, result: Dict[str, Any]) -> None:
        """Add final recommendations based on issues found"""
        if not result["issues"]:
            result["recommendations"].append("DKIM configuration is optimal")
        
        # Security recommendations
        if 'h' in result['tags'] and 'sha256' not in result['tags']['h']:
            result["recommendations"].append(
                "Consider adding SHA-256 to your hash algorithms for better security"
            )