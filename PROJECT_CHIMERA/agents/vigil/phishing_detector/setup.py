"""
Setup script for phishing detector
Run this to verify everything works
"""

import os
import sys

def setup_phishing_detector():
    """Setup and test the phishing detector"""
    print("🔧 Setting up Phishing Detector for VIGIL Agent...")
    
    # Create necessary directories
    dirs_to_create = [
        'agents/vigil/phishing_detector/utils',
        'agents/vigil/phishing_detector/config',
        'agents/vigil/phishing_detector/tests',
        'agents/vigil/phishing_detector/url_model',
        'agents/vigil/phishing_detector/email_model',
        'logs'
    ]
    
    for dir_path in dirs_to_create:
        os.makedirs(dir_path, exist_ok=True)
        print(f"  ✓ Created directory: {dir_path}")
    
    # Test the detector
    print("\n🧪 Testing Phishing Detector...")
    
    try:
        # Add to path
        sys.path.append('agents/vigil/phishing_detector')
        
        # Import and test
        from detector import PhishingDetector
        
        detector = PhishingDetector()
        
        # Test with sample URLs
        test_urls = [
            ("https://secure-login.verify-account.xyz/login.php", "PHISHING"),
            ("https://www.google.com", "LEGITIMATE"),
            ("http://free-gift-card.top/claim", "PHISHING"),
            ("https://github.com/login", "LEGITIMATE")
        ]
        
        for url, expected in test_urls:
            result = detector.predict_url(url)
            status = "✓" if result.get('prediction') == expected else "✗"
            print(f"  {status} {url[:50]:50} -> {result.get('prediction')} "
                  f"(Score: {result.get('risk_score', 0)})")
        
        print(f"\n✅ Phishing Detector setup complete!")
        print(f"📊 Status: {detector.get_status()}")
        
    except Exception as e:
        print(f"\n❌ Setup failed: {str(e)}")
        return False
    
    return True


if __name__ == "__main__":
    setup_phishing_detector()