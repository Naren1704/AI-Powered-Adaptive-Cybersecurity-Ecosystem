"""
Email Text Preprocessing Utility
Cleans and prepares email text for phishing detection
"""

import re
import string
from typing import List
import nltk
from nltk.corpus import stopwords
from nltk.tokenize import word_tokenize

try:
    nltk.data.find('tokenizers/punkt')
except LookupError:
    nltk.download('punkt', quiet=True)

try:
    nltk.data.find('corpora/stopwords')
except LookupError:
    nltk.download('stopwords', quiet=True)


class EmailTextPreprocessor:
    """Preprocesses email text for phishing detection"""
    
    def __init__(self):
        self.stop_words = set(stopwords.words('english'))
        # Keep important negation words
        self.stop_words.difference_update({'not', 'no', 'nor', 'never'})
    
    def preprocess(self, text: str) -> str:
        """
        Preprocess email text
        
        Args:
            text: Raw email text
        
        Returns:
            Cleaned text string
        """
        if not text:
            return ""
        
        # Convert to lowercase
        text = text.lower()
        
        # Remove URLs
        text = self._remove_urls(text)
        
        # Remove email addresses
        text = self._remove_emails(text)
        
        # Remove phone numbers
        text = self._remove_phone_numbers(text)
        
        # Remove special characters but keep some punctuation for context
        text = re.sub(r'[^\w\s.!?]', ' ', text)
        
        # Remove extra whitespace
        text = ' '.join(text.split())
        
        # Tokenize and remove stopwords
        tokens = word_tokenize(text)
        tokens = [token for token in tokens if token not in self.stop_words]
        
        # Remove single characters (except 'a' and 'i')
        tokens = [token for token in tokens if len(token) > 1 or token in ['a', 'i']]
        
        # Remove numbers
        tokens = [token for token in tokens if not token.isdigit()]
        
        return ' '.join(tokens)
    
    def _remove_urls(self, text: str) -> str:
        """Remove URLs from text"""
        url_pattern = r'https?://\S+|www\.\S+'
        return re.sub(url_pattern, '', text)
    
    def _remove_emails(self, text: str) -> str:
        """Remove email addresses from text"""
        email_pattern = r'\S+@\S+'
        return re.sub(email_pattern, '', text)
    
    def _remove_phone_numbers(self, text: str) -> str:
        """Remove phone numbers from text"""
        phone_pattern = r'\+?\d[\d\s\-\(\)]{7,}\d'
        return re.sub(phone_pattern, '', text)
    
    def extract_suspicious_patterns(self, text: str) -> List[str]:
        """
        Extract suspicious patterns from email text
        
        Args:
            text: Email text
        
        Returns:
            List of suspicious patterns found
        """
        patterns = []
        text_lower = text.lower()
        
        # Urgency patterns
        urgency_keywords = ['urgent', 'immediately', 'asap', '24 hours', 'today', 'now']
        if any(keyword in text_lower for keyword in urgency_keywords):
            patterns.append('urgency_tactics')
        
        # Threat patterns
        threat_keywords = ['suspended', 'locked', 'terminated', 'closed', 'expire']
        if any(keyword in text_lower for keyword in threat_keywords):
            patterns.append('account_threats')
        
        # Request patterns
        request_keywords = ['verify', 'confirm', 'update', 'validate', 'click', 'login']
        if any(keyword in text_lower for keyword in request_keywords):
            patterns.append('verification_requests')
        
        # Financial patterns
        financial_keywords = ['bank', 'paypal', 'payment', 'credit card', 'billing', 'invoice']
        if any(keyword in text_lower for keyword in financial_keywords):
            patterns.append('financial_terms')
        
        # Reward patterns
        reward_keywords = ['free', 'gift', 'prize', 'won', 'reward', 'bonus', 'offer']
        if any(keyword in text_lower for keyword in reward_keywords):
            patterns.append('reward_scams')
        
        # Personal info requests
        personal_keywords = ['password', 'ssn', 'social security', 'account number', 'pin']
        if any(keyword in text_lower for keyword in personal_keywords):
            patterns.append('personal_info_request')
        
        return patterns