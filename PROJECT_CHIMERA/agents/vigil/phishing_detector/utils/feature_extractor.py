"""
URL Feature Extraction Utility
Extracts 44 features from URLs for phishing detection
"""

import re
import tldextract
import numpy as np
from urllib.parse import urlparse, parse_qs
from typing import Dict, Any

from .constants import PHISHING_KEYWORDS, HIGH_RISK_TLDS, LEGITIMATE_TLDS


class URLFeatureExtractor:
    """Extracts features from URLs for phishing detection"""
    
    def __init__(self):
        self.phishing_keywords = PHISHING_KEYWORDS
        self.high_risk_tlds = HIGH_RISK_TLDS
        self.legitimate_tlds = LEGITIMATE_TLDS
    
    def extract_features(self, url: str) -> Dict[str, Any]:
        """
        Extract all 44 features from a URL
        
        Args:
            url: URL string
        
        Returns:
            Dictionary of features
        """
        features = {}
        
        # Basic URL features
        features['url_length'] = len(url)
        features['is_https'] = 1 if url.startswith('https://') else 0
        features['is_http'] = 1 if url.startswith('http://') else 0
        
        # Parse URL components
        parsed = urlparse(url)
        extracted = tldextract.extract(url)
        
        # Domain features
        domain = extracted.domain + '.' + extracted.suffix if extracted.suffix else extracted.domain
        features['domain_length'] = len(domain)
        features['tld'] = extracted.suffix.lower() if extracted.suffix else ''
        
        # TLD features
        features['is_high_risk_tld'] = 1 if extracted.suffix.lower() in self.high_risk_tlds else 0
        features['is_legitimate_tld'] = 1 if extracted.suffix.lower() in self.legitimate_tlds else 0
        features['tld_encoded'] = self._encode_tld(extracted.suffix)
        
        # Subdomain features
        subdomains = extracted.subdomain.split('.') if extracted.subdomain else []
        features['num_subdomains'] = len(subdomains)
        features['has_subdomain'] = 1 if extracted.subdomain else 0
        
        # Path features
        path = parsed.path
        features['path_length'] = len(path)
        features['has_path'] = 1 if path and path != '/' else 0
        
        # Query features
        query = parsed.query
        features['has_query'] = 1 if query else 0
        features['num_params'] = len(parse_qs(query))
        
        # Character analysis
        features['num_digits'] = sum(c.isdigit() for c in url)
        features['num_letters'] = sum(c.isalpha() for c in url)
        features['num_special_chars'] = sum(not c.isalnum() for c in url)
        
        # Ratios
        features['digit_ratio'] = features['num_digits'] / len(url) if url else 0
        features['letter_ratio'] = features['num_letters'] / len(url) if url else 0
        features['special_char_ratio'] = features['num_special_chars'] / len(url) if url else 0
        
        # Keyword detection
        url_lower = url.lower()
        keyword_count = sum(1 for keyword in self.phishing_keywords if keyword in url_lower)
        features['phishing_keyword_count'] = keyword_count
        features['phishing_keyword_ratio'] = keyword_count / len(url_lower.split()) if url_lower.split() else 0
        
        # IP address detection
        features['uses_ip_address'] = 1 if self._contains_ip_address(url) else 0
        
        # Suspicious patterns
        features['has_suspicious_symbols'] = 1 if re.search(r'[@%&\*]', url) else 0
        features['has_double_slash'] = 1 if '//' in parsed.path else 0
        
        # SSL/TLS features (simplified)
        features['has_ssl'] = features['is_https']
        
        # URL depth
        features['url_depth'] = path.count('/') if path else 0
        
        # Short URL detection
        features['is_shortened'] = 1 if any(service in url for service in ['bit.ly', 'tinyurl', 'goo.gl']) else 0
        
        # Entropy (simplified)
        features['entropy'] = self._calculate_entropy(domain)
        
        # Additional features for model compatibility
        features['is_https'] = features['is_https']  # Duplicate for model
        features['is_http'] = features['is_http']    # Duplicate for model
        features['num_special_chars'] = features['num_special_chars']
        features['special_char_ratio'] = features['special_char_ratio']
        features['letter_ratio'] = features['letter_ratio']
        features['has_subdomain'] = features['has_subdomain']
        
        # Ensure we have exactly 44 features
        features = self._ensure_44_features(features)
        
        return features
    
    def _encode_tld(self, tld: str) -> int:
        """Encode TLD to numeric value"""
        if not tld:
            return 0
        tld = tld.lower()
        # Simple hash-based encoding
        return hash(tld) % 1000
    
    def _contains_ip_address(self, url: str) -> bool:
        """Check if URL contains IP address"""
        ip_patterns = [
            r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',
            r'\[([0-9a-fA-F:]+)\]'  # IPv6
        ]
        for pattern in ip_patterns:
            if re.search(pattern, url):
                return True
        return False
    
    def _calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy of a string"""
        if not text:
            return 0.0
        
        # Count character frequencies
        freq = {}
        for char in text:
            freq[char] = freq.get(char, 0) + 1
        
        # Calculate entropy
        entropy = 0.0
        length = len(text)
        for count in freq.values():
            probability = count / length
            entropy -= probability * np.log2(probability)
        
        return entropy
    
    def _ensure_44_features(self, features: Dict) -> Dict:
        """Ensure exactly 44 features for model compatibility"""
        expected_features = [
            'url_length', 'domain_length', 'path_length', 'num_subdomains',
            'num_digits', 'num_letters', 'num_special_chars', 'digit_ratio',
            'letter_ratio', 'special_char_ratio', 'phishing_keyword_count',
            'phishing_keyword_ratio', 'is_https', 'is_http', 'has_path',
            'has_query', 'num_params', 'has_subdomain', 'is_high_risk_tld',
            'is_legitimate_tld', 'tld_encoded', 'uses_ip_address',
            'has_suspicious_symbols', 'has_double_slash', 'has_ssl',
            'url_depth', 'is_shortened', 'entropy'
        ]
        
        # Add any missing features with default value 0
        for feature in expected_features:
            if feature not in features:
                features[feature] = 0
        
        return features