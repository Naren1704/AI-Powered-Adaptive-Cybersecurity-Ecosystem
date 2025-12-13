"""
Main Phishing Detector Wrapper Class
Combines URL and Email detection models with unified interface
"""

import joblib
import numpy as np
import pandas as pd
from typing import Dict, Any, Optional, Union
from datetime import datetime
import warnings
warnings.filterwarnings('ignore')

from .utils.feature_extractor import URLFeatureExtractor
from .utils.text_preprocessor import EmailTextPreprocessor
from .utils.threat_scorer import ThreatScorer
from .utils.constants import PHISHING_KEYWORDS, HIGH_RISK_TLDS


class PhishingDetector:
    """
    Unified phishing detection system for URLs and Emails
    
    Attributes:
        url_model: Random Forest model for URL detection
        email_model: TF-IDF + Naive Bayes pipeline for email detection
        url_features: List of feature columns expected by URL model
        tld_encoder: LabelEncoder for TLD processing
        threshold: Decision threshold for phishing classification
        extractor: URL feature extraction utility
        preprocessor: Email text preprocessing utility
        scorer: Risk scoring utility
    """
    
    def __init__(self, threshold: float = 0.35):
        """
        Initialize the phishing detector
        
        Args:
            threshold: Probability threshold for phishing classification (0-1)
        """
        self.threshold = threshold
        self.initialized = False
        self.models_loaded = False
        self.initialize_detector()
    
    def initialize_detector(self):
        """Load all models and initialize components"""
        try:
            # Load the unified wrapper if it exists
            try:
                self.detector = joblib.load('final_phishing_detector.pkl')
                self.models_loaded = True
                print("✓ Loaded unified phishing detector")
                return
            except FileNotFoundError:
                # Fall back to individual models
                print("⚠ Unified detector not found, loading individual models...")
            
            # Load URL model components
            self.url_model = joblib.load('url_model/new_phishing_model.pkl')
            self.url_features = joblib.load('url_model/new_feature_columns.pkl')
            self.tld_encoder = joblib.load('url_model/new_tld_encoder.pkl')
            
            # Load email model
            self.email_model = joblib.load('email_model/phishing_email_classifier.pkl')
            
            # Initialize utilities
            self.extractor = URLFeatureExtractor()
            self.preprocessor = EmailTextPreprocessor()
            self.scorer = ThreatScorer()
            
            self.models_loaded = True
            print("✓ Phishing detector initialized successfully")
            print(f"  - URL Model: {self.url_model.__class__.__name__}")
            print(f"  - Email Model: {self.email_model.__class__.__name__}")
            print(f"  - Threshold: {self.threshold}")
            
        except Exception as e:
            print(f"✗ Failed to initialize phishing detector: {str(e)}")
            self.models_loaded = False
            raise
    
    def predict_url(self, url: str) -> Dict[str, Any]:
        """
        Predict if a URL is phishing
        
        Args:
            url: URL string to analyze
        
        Returns:
            Dictionary with prediction results
        """
        if not self.models_loaded:
            return self._error_response("Models not loaded")
        
        try:
            # Extract features
            features = self.extractor.extract_features(url)
            
            # Create DataFrame with correct column order
            feature_df = pd.DataFrame([features])
            
            # Ensure all expected columns exist
            for col in self.url_features:
                if col not in feature_df.columns:
                    feature_df[col] = 0
            
            feature_df = feature_df[self.url_features]
            
            # Get prediction probability
            probability = float(self.url_model.predict_proba(feature_df)[0, 1])
            
            # Make decision
            is_phishing = probability >= self.threshold
            
            # Calculate risk score
            risk_score = self.scorer.calculate_risk_score(url, probability, features)
            
            # Get detection reasons
            reasons = self._get_detection_reasons(features, probability)
            
            return {
                'success': True,
                'url': url,
                'prediction': 'PHISHING' if is_phishing else 'LEGITIMATE',
                'phishing_probability': round(probability, 4),
                'risk_score': risk_score,
                'is_phishing': is_phishing,
                'confidence': 'HIGH' if probability > 0.8 else 'MEDIUM' if probability > 0.5 else 'LOW',
                'detection_reasons': reasons,
                'timestamp': datetime.now().isoformat(),
                'model_version': '1.0'
            }
            
        except Exception as e:
            return self._error_response(f"URL prediction failed: {str(e)}")
    
    def predict_email(self, email_text: str) -> Dict[str, Any]:
        """
        Predict if an email is phishing
        
        Args:
            email_text: Email content string
        
        Returns:
            Dictionary with prediction results
        """
        if not self.models_loaded:
            return self._error_response("Models not loaded")
        
        try:
            # Preprocess text
            processed_text = self.preprocessor.preprocess(email_text)
            
            # Get prediction probability
            probability = float(self.email_model.predict_proba([processed_text])[0, 1])
            
            # Make decision
            is_phishing = probability >= self.threshold
            
            # Calculate risk score (different scale for emails)
            risk_score = int(min(probability * 100, 100))
            
            # Get detected keywords
            detected_keywords = self._extract_suspicious_keywords(email_text)
            
            return {
                'success': True,
                'prediction': 'PHISHING' if is_phishing else 'SAFE',
                'phishing_probability': round(probability, 4),
                'risk_score': risk_score,
                'is_phishing': is_phishing,
                'confidence': round(probability, 2),
                'detected_keywords': detected_keywords,
                'timestamp': datetime.now().isoformat(),
                'model_version': '1.0'
            }
            
        except Exception as e:
            return self._error_response(f"Email prediction failed: {str(e)}")
    
    def batch_predict_urls(self, urls: list) -> Dict[str, Any]:
        """
        Predict phishing status for multiple URLs
        
        Args:
            urls: List of URL strings
        
        Returns:
            Dictionary with batch results
        """
        results = []
        for url in urls:
            result = self.predict_url(url)
            results.append(result)
        
        # Calculate batch statistics
        phishing_count = sum(1 for r in results if r.get('is_phishing', False))
        
        return {
            'success': True,
            'total_urls': len(urls),
            'phishing_count': phishing_count,
            'safe_count': len(urls) - phishing_count,
            'phishing_rate': round(phishing_count / len(urls) * 100, 2),
            'results': results,
            'timestamp': datetime.now().isoformat()
        }
    
    def _get_detection_reasons(self, features: Dict, probability: float) -> list:
        """Extract reasons for phishing detection"""
        reasons = []
        
        # Check TLD
        if features.get('is_high_risk_tld', 0) == 1:
            reasons.append(f"High-risk TLD detected: {features.get('tld', 'unknown')}")
        
        # Check phishing keywords
        if features.get('phishing_keyword_count', 0) > 0:
            reasons.append(f"Contains {features['phishing_keyword_count']} phishing keywords")
        
        # Check URL length
        if features.get('url_length', 0) > 150:
            reasons.append("Suspiciously long URL")
        
        # Check special characters
        if features.get('special_char_ratio', 0) > 0.3:
            reasons.append("High special character ratio")
        
        # Check if uses IP address
        if features.get('uses_ip_address', 0) == 1:
            reasons.append("Uses IP address instead of domain")
        
        # High probability reason
        if probability > 0.9:
            reasons.append("Very high phishing probability (>{:.0%})".format(0.9))
        
        return reasons if reasons else ["No specific indicators detected"]
    
    def _extract_suspicious_keywords(self, text: str) -> list:
        """Extract suspicious keywords from email text"""
        text_lower = text.lower()
        detected = []
        
        for keyword in PHISHING_KEYWORDS:
            if keyword in text_lower:
                detected.append(keyword)
        
        return detected
    
    def _error_response(self, message: str) -> Dict[str, Any]:
        """Generate error response"""
        return {
            'success': False,
            'error': message,
            'timestamp': datetime.now().isoformat()
        }
    
    def get_status(self) -> Dict[str, Any]:
        """Get detector status information"""
        return {
            'initialized': self.models_loaded,
            'threshold': self.threshold,
            'url_features_count': len(self.url_features) if self.models_loaded else 0,
            'phishing_keywords': len(PHISHING_KEYWORDS),
            'high_risk_tlds': len(HIGH_RISK_TLDS),
            'version': '1.0'
        }


# Unified interface function
def create_phishing_detector(config: Dict = None) -> PhishingDetector:
    """
    Factory function to create phishing detector
    
    Args:
        config: Optional configuration dictionary
    
    Returns:
        PhishingDetector instance
    """
    if config and 'threshold' in config:
        return PhishingDetector(threshold=config['threshold'])
    return PhishingDetector()