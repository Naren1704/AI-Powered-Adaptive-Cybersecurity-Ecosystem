"""
Constants for Phishing Detection
Keywords, TLDs, and configuration values
"""

# High-risk TLDs often used in phishing
HIGH_RISK_TLDS = {
    'xyz', 'cc', 'tk', 'ml', 'ga', 'cf', 'gq', 'top', 'loan', 'win',
    'bid', 'date', 'download', 'party', 'review', 'science', 'stream',
    'trade', 'webcam', 'work', 'accountant', 'bar', 'buzz', 'click',
    'country', 'cricket', 'faith', 'gdn', 'men', 'racing', 'rest',
    'site', 'space', 'tech', 'uno', 'website', 'xin', 'zip'
}

# Legitimate/common TLDs
LEGITIMATE_TLDS = {
    'com', 'org', 'net', 'edu', 'gov', 'mil', 'io', 'co', 'ai',
    'uk', 'us', 'ca', 'au', 'de', 'fr', 'jp', 'cn', 'in', 'br'
}

# Phishing keywords commonly found in malicious URLs/emails
PHISHING_KEYWORDS = [
    # Account-related
    'login', 'signin', 'verify', 'account', 'secure', 'password', 'auth',
    'authentication', 'confirm', 'validation', 'update', 'recover',
    
    # Financial
    'bank', 'paypal', 'payment', 'billing', 'invoice', 'credit',
    'card', 'transfer', 'transaction', 'refund', 'money', 'cash',
    
    # Urgency/Threat
    'urgent', 'immediate', 'alert', 'warning', 'suspended', 'locked',
    'expire', 'terminate', 'unauthorized', 'compromised', 'breach',
    
    # Rewards/Scams
    'free', 'gift', 'prize', 'won', 'reward', 'bonus', 'offer',
    'claim', 'winner', 'congratulations', 'selected', 'exclusive',
    
    # Social Engineering
    'security', 'protection', 'verify', 'validate', 'confirm',
    'click', 'here', 'link', 'button', 'download', 'install',
    
    # Services
    'apple', 'microsoft', 'google', 'amazon', 'facebook', 'netflix',
    'paypal', 'ebay', 'whatsapp', 'instagram', 'twitter',
    
    # Document/File
    'document', 'invoice', 'statement', 'bill', 'receipt', 'form',
    'attachment', 'file', 'scan', 'copy'
]

# Suspicious URL patterns
SUSPICIOUS_PATTERNS = [
    r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',  # IP addresses
    r'@',  # Username in URL
    r'%\w{2}',  # URL encoded characters
    r'\.(exe|bat|cmd|msi|jar)$',  # Executable extensions
]

# Email phishing patterns
EMAIL_PHISHING_PATTERNS = {
    'greeting_mismatch': [r'Dear (?:Customer|User|Member|Valued)'],
    'generic_greeting': [r'Hello\s*(?:there|!|,)'],
    'urgency_indicators': [r'within \d+ hours?', r'immediate(?:ly)?', r'ASAP'],
    'threat_indicators': [r'account (?:will be|has been) (?:suspended|locked|closed)'],
    'action_required': [r'click (?:here|below|the link)', r'verify (?:your|my) account'],
}