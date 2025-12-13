"""
Unit tests for URL phishing detection
"""

import unittest
import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from detector import PhishingDetector
from utils.feature_extractor import URLFeatureExtractor


class TestURLPhishingDetection(unittest.TestCase):
    """Test cases for URL phishing detection"""
    
    def setUp(self):
        """Initialize detector for testing"""
        self.detector = PhishingDetector(threshold=0.35)
        self.extractor = URLFeatureExtractor()
        
        # Test URLs
        self.phishing_urls = [
            "http://secure-verify-account-login.xyz/login.php",
            "https://paypal-verify-account.cc/secure/update",
            "http://192.168.1.1/login.php?user=admin",
            "https://free-gift-card-reward.top/claim"
        ]
        
        self.legitimate_urls = [
            "https://github.com/login",
            "https://www.google.com/search",
            "https://stackoverflow.com/questions",
            "https://docs.python.org/3/"
        ]
    
    def test_detector_initialization(self):
        """Test that detector initializes correctly"""
        self.assertTrue(self.detector.models_loaded)
        self.assertIsNotNone(self.detector.url_model)
        self.assertIsNotNone(self.detector.email_model)
    
    def test_feature_extraction(self):
        """Test URL feature extraction"""
        url = "https://secure-login.verify-account.xyz/login.php?user=test"
        features = self.extractor.extract_features(url)
        
        # Check essential features
        self.assertIn('url_length', features)
        self.assertIn('is_https', features)
        self.assertIn('is_high_risk_tld', features)
        self.assertIn('phishing_keyword_count', features)
        
        # Verify specific values
        self.assertEqual(features['is_high_risk_tld'], 1)  # .xyz is high-risk
        self.assertGreater(features['phishing_keyword_count'], 0)
    
    def test_phishing_url_detection(self):
        """Test detection of phishing URLs"""
        for url in self.phishing_urls:
            result = self.detector.predict_url(url)
            
            self.assertTrue(result['success'])
            self.assertEqual(result['prediction'], 'PHISHING')
            self.assertGreater(result['phishing_probability'], 0.35)
            self.assertGreater(result['risk_score'], 40)
    
    def test_legitimate_url_detection(self):
        """Test detection of legitimate URLs"""
        for url in self.legitimate_urls:
            result = self.detector.predict_url(url)
            
            self.assertTrue(result['success'])
            self.assertEqual(result['prediction'], 'LEGITIMATE')
            self.assertLess(result['phishing_probability'], 0.35)
            self.assertLess(result['risk_score'], 40)
    
    def test_batch_prediction(self):
        """Test batch URL prediction"""
        urls = self.phishing_urls[:2] + self.legitimate_urls[:2]
        result = self.detector.batch_predict_urls(urls)
        
        self.assertTrue(result['success'])
        self.assertEqual(result['total_urls'], 4)
        self.assertEqual(result['phishing_count'], 2)
        self.assertEqual(result['safe_count'], 2)
    
    def test_error_handling(self):
        """Test error handling for invalid input"""
        # Test empty URL
        result = self.detector.predict_url("")
        self.assertFalse(result['success'])
        self.assertIn('error', result)
        
        # Test malformed URL
        result = self.detector.predict_url("not-a-valid-url")
        self.assertFalse(result['success'])
    
    def test_risk_scoring(self):
        """Test risk score calculation"""
        url = "http://secure-login.xyz/login.php"
        result = self.detector.predict_url(url)
        
        self.assertIn('risk_score', result)
        self.assertIsInstance(result['risk_score'], int)
        self.assertGreaterEqual(result['risk_score'], 0)
        self.assertLessEqual(result['risk_score'], 100)
        
        # Score should correlate with probability
        self.assertGreater(result['risk_score'], result['phishing_probability'] * 50)


if __name__ == '__main__':
    unittest.main()