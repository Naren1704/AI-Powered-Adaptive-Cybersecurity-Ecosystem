"""
Phishing Detection Module for VIGIL Agent
Provides URL and Email phishing detection capabilities
"""

from .detector import PhishingDetector
from .utils.feature_extractor import URLFeatureExtractor
from .utils.text_preprocessor import EmailTextPreprocessor
from .utils.threat_scorer import ThreatScorer

__version__ = "1.0.0"
__all__ = [
    'PhishingDetector',
    'URLFeatureExtractor',
    'EmailTextPreprocessor',
    'ThreatScorer'
]