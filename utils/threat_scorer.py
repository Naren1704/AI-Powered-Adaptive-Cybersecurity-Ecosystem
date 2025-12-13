"""
Threat Scoring Utility
Calculates risk scores (0-100) for phishing threats
"""

import re
from typing import Dict, Any
from urllib.parse import urlparse

from .constants import PHISHING_KEYWORDS, HIGH_RISK_TLDS


class ThreatScorer:
    """Calculates risk scores for phishing threats"""
    
    def __init__(self):
        self.phishing_keywords = PHISHING_KEYWORDS
        self.high_risk_tlds = HIGH_RISK_TLDS
    
    def calculate_risk_score(self, url: str, probability: float, features: Dict = None) -> int:
        """
        Calculate comprehensive risk score (0-100)
        
        Args:
            url: URL string
            probability: Model prediction probability (0-1)
            features: Extracted features (optional)
        
        Returns:
            Risk score from 0-100
        """
        if features is None:
            features = self._quick_extract_features(url)
        
        base_score = int(probability * 60)  # 0-60 points from model probability
        
        # Add points for various risk factors
        risk_score = base_score
        
        # TLD risk (0-10 points)
        if features.get('is_high_risk_tld', 0) == 1:
            risk_score += 10
        
        # Keyword risk (0-15 points)
        keyword_count = features.get('phishing_keyword_count', 0)
        risk_score += min(keyword_count * 3, 15)
        
        # URL structure risk (0-10 points)
        if features.get('uses_ip_address', 0) == 1:
            risk_score += 10
        elif features.get('url_length', 0) > 150:
            risk_score += 5
        elif features.get('num_subdomains', 0) > 3:
            risk_score += 3
        
        # Character pattern risk (0-5 points)
        if features.get('special_char_ratio', 0) > 0.3:
            risk_score += 5
        
        # Cap at 100
        return min(risk_score, 100)
    
    def _quick_extract_features(self, url: str) -> Dict[str, Any]:
        """Quick feature extraction for scoring"""
        features = {
            'is_high_risk_tld': 0,
            'phishing_keyword_count': 0,
            'uses_ip_address': 0,
            'url_length': len(url),
            'num_subdomains': 0,
            'special_char_ratio': 0
        }
        
        # Check TLD
        try:
            tld = url.split('.')[-1].split('/')[0].lower()
            features['is_high_risk_tld'] = 1 if tld in self.high_risk_tlds else 0
        except:
            pass
        
        # Count phishing keywords
        url_lower = url.lower()
        features['phishing_keyword_count'] = sum(
            1 for keyword in self.phishing_keywords if keyword in url_lower
        )
        
        # Check for IP address
        ip_pattern = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
        features['uses_ip_address'] = 1 if re.search(ip_pattern, url) else 0
        
        # Count subdomains
        try:
            parsed = urlparse(url)
            if parsed.netloc:
                subdomains = parsed.netloc.split('.')
                features['num_subdomains'] = max(0, len(subdomains) - 2)
        except:
            pass
        
        # Calculate special character ratio
        special_chars = sum(1 for c in url if not c.isalnum())
        features['special_char_ratio'] = special_chars / len(url) if url else 0
        
        return features
    
    def get_risk_level(self, score: int) -> str:
        """
        Convert numeric score to risk level
        
        Args:
            score: Risk score (0-100)
        
        Returns:
            Risk level string
        """
        if score >= 80:
            return "CRITICAL"
        elif score >= 60:
            return "HIGH"
        elif score >= 40:
            return "MEDIUM"
        elif score >= 20:
            return "LOW"
        else:
            return "MINIMAL"
    
    def generate_recommendation(self, score: int, url: str = None) -> str:
        """
        Generate recommendation based on risk score
        
        Args:
            score: Risk score (0-100)
            url: Optional URL for context
        
        Returns:
            Recommendation string
        """
        level = self.get_risk_level(score)
        
        recommendations = {
            "CRITICAL": "⚠️ **IMMEDIATE ACTION REQUIRED** - Do not visit this URL. This is highly likely to be a phishing attempt.",
            "HIGH": "⚠️ **HIGH RISK** - Avoid this URL. Strong indicators of phishing detected.",
            "MEDIUM": "⚠️ **CAUTION ADVISED** - This URL shows suspicious characteristics. Proceed with extreme caution.",
            "LOW": "⚠️ **LOW RISK** - Some minor indicators detected. Verify the source before proceeding.",
            "MINIMAL": "✅ **LIKELY SAFE** - No significant phishing indicators detected."
        }
        
        return recommendations.get(level, "Risk assessment unavailable")