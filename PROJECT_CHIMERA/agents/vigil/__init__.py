# In agents/vigil/__init__.py or vigil_agent.py
from .phishing_detector import PhishingDetector

class VigilAgent:
    def __init__(self):
        self.phishing_detector = PhishingDetector()
    
    def analyze_network_traffic(self, packet):
        # Extract URLs/emails from packet
        urls = self.extract_urls(packet)
        
        for url in urls:
            result = self.phishing_detector.predict_url(url)
            if result['is_phishing']:
                self.trigger_alert(result)
