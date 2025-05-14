import dns.resolver
import dns.exception
import logging
import re
from typing import List, Dict, Optional, Tuple, Set
from enum import Enum

logger = logging.getLogger(__name__)

class DomainScanner:
    """DNS scanner for email deliverability checks"""
    
    # Common DKIM selectors by provider
    COMMON_SELECTORS = {
        "gmail.com": ["google", "default", "20161025", "20200123"],
        "outlook.com": ["selector1", "selector2"],
        "office365.com": ["selector1", "selector2"],
        "yahoo.com": ["s1024", "s2048"],
        "zoho.com": ["zoho", "zmail"],
        "protonmail.ch": ["protonmail", "protonmail2", "protonmail3"],
        "mailchimp.com": ["k1"],
        "sendgrid.net": ["s1", "s2", "m1"],
        "amazonses.com": ["amazonses"],
        "mailgun.org": ["mx", "k1"],
        # Generic common selectors
        "generic": ["default", "dkim", "mail", "email", "selector", "key", "k1", "domainkey"]
    }
    
    # Email provider detection patterns
    EMAIL_PROVIDERS = {
        r"google|gmail|googlemail": "Google Workspace",
        r"outlook|office365|microsoft": "Microsoft 365",
        r"yahoo": "Yahoo Mail",
        r"zoho": "Zoho Mail",
        r"protonmail": "ProtonMail",
        r"mailchimp": "Mailchimp",
        r"sendgrid": "SendGrid",
        r"amazonses|aws": "Amazon SES",
        r"mailgun": "Mailgun",
        r"postmark": "Postmark",
        r"sparkpost": "SparkPost"
    }

    def __init__(self, domain: str):
        self.domain = domain
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = 5.0
        self.resolver.lifetime = 10.0
        self.email_provider = None
        self.detected_dkim_selector = None
        
    async def scan_all(self) -> Dict:
        """
        Perform a complete scan of the domain
        Returns all scan results
        """
        # Update task status with each step
        results = {}
        
        try:
            # Step 1: Check MX records and detect email provider
            self.update_status("Checking MX records...")
            mx_records = await self.scan_mx_records()
            results["mx"] = mx_records
            
            # Step 2: Detect email provider from MX records
            self.update_status("Detecting email provider...")
            self.email_provider = self.detect_provider_from_mx(mx_records)
            results["email_provider"] = self.email_provider
            
            # Step 3: Check SPF record
            self.update_status("Checking SPF record...")
            spf_result = await self.scan_spf()
            results["spf"] = spf_result
            
            # If no provider detected from MX, try from SPF
            if not self.email_provider and spf_result and "value" in spf_result:
                provider = self.detect_provider_from_spf(spf_result["value"])
                if provider:
                    self.email_provider = provider
                    results["email_provider"] = provider
            
            # Step 4: Auto-detect DKIM selector
            self.update_status("Attempting to detect DKIM selector...")
            dkim_selector = await self.detect_dkim_selector()
            results["dkim_selector"] = dkim_selector
            self.detected_dkim_selector = dkim_selector
            
            # Step 5: Check DKIM record with detected selector
            if dkim_selector:
                self.update_status(f"Checking DKIM record with selector '{dkim_selector}'...")
                dkim_result = await self.scan_dkim(dkim_selector)
                results["dkim"] = dkim_result
            else:
                results["dkim"] = {
                    "status": "unknown",
                    "issues": ["No DKIM selector could be automatically detected"]
                }
            
            # Step 6: Check DMARC record
            self.update_status("Checking DMARC record...")
            dmarc_result = await self.scan_dmarc()
            results["dmarc"] = dmarc_result
            
            # Final step: Calculate overall status
            self.update_status("Analyzing results...")
            overall_status = self.calculate_overall_status(results)
            results["overall_status"] = overall_status
            
            return results
            
        except Exception as e:
            logger.error(f"Error during domain scan: {str(e)}")
            return {"error": str(e), "status": "failed"}
    
    def update_status(self, message: str):
        """Update scan status - this will be used by the task queue"""
        logger.info(f"Scan status for {self.domain}: {message}")
        # In a real implementation, this would update the task status
        # self.current_task.update_state(state='STARTED', meta={'current_step': message})
    
    async def scan_mx_records(self) -> List[Dict]:
        """Scan MX records for the domain"""
        try:
            mx_records = []
            answers = self.resolver.resolve(self.domain, 'MX')
            
            for rdata in answers:
                mx_records.append({
                    "priority": rdata.preference,
                    "value": str(rdata.exchange).rstrip('.')
                })
            
            return sorted(mx_records, key=lambda x: x["priority"])
        except dns.resolver.NoAnswer:
            return []
        except dns.resolver.NXDOMAIN:
            return []
        except Exception as e:
            logger.error(f"Error scanning MX records: {str(e)}")
            return []
    
    def detect_provider_from_mx(self, mx_records: List[Dict]) -> Optional[str]:
        """Detect email provider from MX records"""
        if not mx_records:
            return None
        
        # Combine all MX values into a single string for pattern matching
        mx_string = " ".join([record["value"].lower() for record in mx_records])
        
        # Try to match against known patterns
        for pattern, provider in self.EMAIL_PROVIDERS.items():
            if re.search(pattern, mx_string):
                return provider
        
        # If no match, return the primary MX domain
        primary_mx = mx_records[0]["value"].lower()
        return f"Custom ({primary_mx})"
    
    def detect_provider_from_spf(self, spf_value: str) -> Optional[str]:
        """Try to detect email provider from SPF record"""
        spf_lower = spf_value.lower()
        
        for pattern, provider in self.EMAIL_PROVIDERS.items():
            if re.search(pattern, spf_lower):
                return provider
        
        return None
    
    async def scan_spf(self) -> Dict:
        """Scan SPF record for the domain"""
        try:
            answers = self.resolver.resolve(self.domain, 'TXT')
            
            for rdata in answers:
                txt_string = "".join(s.decode() for s in rdata.strings)
                if txt_string.startswith('v=spf1'):
                    # Analyze SPF record for issues
                    issues = self.analyze_spf(txt_string)
                    
                    return {
                        "status": "error" if issues else "valid",
                        "value": txt_string,
                        "issues": issues
                    }
            
            return {
                "status": "missing",
                "issues": ["No SPF record found"]
            }
        except Exception as e:
            logger.error(f"Error scanning SPF record: {str(e)}")
            return {
                "status": "error",
                "issues": [f"Error scanning SPF record: {str(e)}"]
            }
    
    def analyze_spf(self, spf_record: str) -> List[str]:
        """Analyze SPF record for common issues"""
        issues = []
        
        # Check for missing all mechanism
        if not re.search(r'[\s][-~?+]?all', spf_record):
            issues.append("Missing 'all' mechanism (should end with -all, ~all, ?all, or +all)")
        
        # Check for overly permissive all
        if "+all" in spf_record:
            issues.append("Using '+all' allows any server to send as your domain (highly insecure)")
        
        # Check for excessive lookups (max 10 DNS lookups)
        includes = len(re.findall(r'include:', spf_record))
        exists = len(re.findall(r'exists:', spf_record))
        redirects = 1 if "redirect=" in spf_record else 0
        mx_lookups = len(re.findall(r'mx[:\s]', spf_record))
        a_lookups = len(re.findall(r'a[:\s]', spf_record))
        ptr_lookups = len(re.findall(r'ptr[:\s]', spf_record))
        
        total_lookups = includes + exists + redirects + mx_lookups + a_lookups + ptr_lookups
        
        if total_lookups > 10:
            issues.append(f"SPF record has too many DNS lookups ({total_lookups}), maximum is 10")
        
        # Check for unnecessary ptr mechanism (performance issue)
        if "ptr" in spf_record:
            issues.append("Using 'ptr' mechanism is not recommended (performance impact)")
        
        return issues
    
    async def detect_dkim_selector(self) -> Optional[str]:
        """Attempt to automatically detect DKIM selector"""
        # Start with selectors specific to detected provider
        selectors_to_try = []
        
        # If we detected a provider, use its selectors first
        if self.email_provider:
            for provider_pattern, provider_selectors in self.COMMON_SELECTORS.items():
                if re.search(provider_pattern, self.email_provider.lower()):
                    selectors_to_try.extend(provider_selectors)
        
        # Then try generic selectors
        selectors_to_try.extend(self.COMMON_SELECTORS["generic"])
        
        # Remove duplicates while preserving order
        selectors_to_try = list(dict.fromkeys(selectors_to_try))
        
        # Try each selector
        for selector in selectors_to_try:
            try:
                # Try to resolve DKIM record
                dkim_domain = f"{selector}._domainkey.{self.domain}"
                self.update_status(f"Trying DKIM selector: {selector}")
                
                answers = self.resolver.resolve(dkim_domain, 'TXT')
                for rdata in answers:
                    txt_string = "".join(s.decode() for s in rdata.strings)
                    if "v=dkim1" in txt_string.lower():
                        return selector
            except Exception:
                # Continue to next selector if this one failed
                continue
        
        return None
    
    async def scan_dkim(self, selector: str) -> Dict:
        """Scan DKIM record for a specific selector"""
        dkim_domain = f"{selector}._domainkey.{self.domain}"
        
        try:
            answers = self.resolver.resolve(dkim_domain, 'TXT')
            
            for rdata in answers:
                txt_string = "".join(s.decode() for s in rdata.strings)
                if "v=dkim1" in txt_string.lower():
                    # Analyze DKIM record for issues
                    issues = self.analyze_dkim(txt_string)
                    
                    return {
                        "status": "error" if issues else "valid",
                        "value": txt_string,
                        "selector": selector,
                        "issues": issues
                    }
            
            return {
                "status": "missing",
                "selector": selector,
                "issues": [f"No valid DKIM record found for selector '{selector}'"]
            }
        except dns.resolver.NXDOMAIN:
            return {
                "status": "missing",
                "selector": selector,
                "issues": [f"No DKIM record found for selector '{selector}'"]
            }
        except Exception as e:
            logger.error(f"Error scanning DKIM record: {str(e)}")
            return {
                "status": "error",
                "selector": selector,
                "issues": [f"Error scanning DKIM record: {str(e)}"]
            }
    
    def analyze_dkim(self, dkim_record: str) -> List[str]:
        """Analyze DKIM record for common issues"""
        issues = []
        
        # Check for required tags
        if "v=dkim1" not in dkim_record.lower():
            issues.append("Missing required 'v=DKIM1' version tag")
        
        if not re.search(r'[;\s]p=', dkim_record):
            issues.append("Missing required 'p=' public key tag")
        
        # Check for empty public key
        if re.search(r'p=[;\s]', dkim_record) or "p=;" in dkim_record:
            issues.append("Empty public key detected (p= with no value)")
        
        # Check for testing mode
        if "t=y" in dkim_record.lower():
            issues.append("DKIM is in testing mode (t=y)")
        
        return issues
    
    async def scan_dmarc(self) -> Dict:
        """Scan DMARC record for the domain"""
        dmarc_domain = f"_dmarc.{self.domain}"
        
        try:
            answers = self.resolver.resolve(dmarc_domain, 'TXT')
            
            for rdata in answers:
                txt_string = "".join(s.decode() for s in rdata.strings)
                if txt_string.startswith('v=DMARC1'):
                    # Analyze DMARC record for issues
                    issues = self.analyze_dmarc(txt_string)
                    
                    return {
                        "status": "error" if issues else "valid",
                        "value": txt_string,
                        "issues": issues
                    }
            
            return {
                "status": "missing",
                "issues": ["No DMARC record found"]
            }
        except dns.resolver.NXDOMAIN:
            return {
                "status": "missing",
                "issues": ["No DMARC record found"]
            }
        except Exception as e:
            logger.error(f"Error scanning DMARC record: {str(e)}")
            return {
                "status": "error",
                "issues": [f"Error scanning DMARC record: {str(e)}"]
            }
    
    def analyze_dmarc(self, dmarc_record: str) -> List[str]:
        """Analyze DMARC record for common issues"""
        issues = []
        
        # Check for required tags
        if not re.search(r'p=[pnr]', dmarc_record):
            issues.append("Missing required 'p=' policy tag")
        
        # Check for weak policy
        if "p=none" in dmarc_record.lower():
            issues.append("DMARC policy is set to 'none', which only monitors and doesn't enforce")
        
        # Check for missing RUA tag (reporting)
        if not re.search(r'rua=', dmarc_record):
            issues.append("Missing 'rua=' tag for aggregate reports")
        
        # Check if using subdomain policy different from main policy
        has_main_policy = re.search(r'p=(reject|quarantine|none)', dmarc_record.lower())
        has_subdomain_policy = re.search(r'sp=(reject|quarantine|none)', dmarc_record.lower())
        
        if has_main_policy and has_subdomain_policy:
            main_policy = has_main_policy.group(1)
            subdomain_policy = has_subdomain_policy.group(1)
            
            if main_policy == "reject" and subdomain_policy != "reject":
                issues.append(f"Subdomain policy ({subdomain_policy}) is weaker than main policy (reject)")
        
        return issues
    
    def calculate_overall_status(self, results: Dict) -> Dict:
        """Calculate overall email deliverability status"""
        status_counts = {
            "valid": 0,
            "missing": 0,
            "error": 0,
            "total": 3  # SPF, DKIM, DMARC
        }
        
        # Count statuses
        for record_type in ["spf", "dkim", "dmarc"]:
            if record_type in results and "status" in results[record_type]:
                status = results[record_type]["status"]
                if status in status_counts:
                    status_counts[status] += 1
        
        # Calculate percentage
        if status_counts["total"] > 0:
            score = (status_counts["valid"] / status_counts["total"]) * 100
        else:
            score = 0
        
        # Determine overall status
        if score == 100:
            overall = "excellent"
        elif score >= 66:
            overall = "good"
        elif score >= 33:
            overall = "fair"
        else:
            overall = "poor"
        
        return {
            "score": score,
            "status": overall,
            "valid_count": status_counts["valid"],
            "missing_count": status_counts["missing"],
            "error_count": status_counts["error"]
        }


# EmailProvider.GOOGLE_WORKSPACE: [],
# EmailProvider.MICROSOFT_365: ["selector1", "selector2"],
# EmailProvider.EXCHANGE_ONLINE: ["selector1", "selector2"],
# EmailProvider.AMAZON_SES: ["amazonses"],
# EmailProvider.MAILCHIMP: ["k1", "k2", "k3"],
# EmailProvider.SENDGRID: ["s1", "s2", "m1"],
# EmailProvider.MAILGUN: ["mx", "smtp", "pic", "k1"],
# EmailProvider.POSTMARK: ["20150623", "pm"],
# EmailProvider.ZOHO: ["zoho", "zmail"],
# EmailProvider.PROTONMAIL: [],
# EmailProvider.FASTMAIL: ["fm1", "fm2", "fm3"],
