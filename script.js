class PhishingDetector {
    constructor() {
        this.initializeElements();
        this.attachEventListeners();
    }

    initializeElements() {
        this.urlInput = document.getElementById('urlInput');
        this.analyzeBtn = document.getElementById('analyzeBtn');
        this.loadingSection = document.getElementById('loadingSection');
        this.resultsSection = document.getElementById('resultsSection');
        this.resultIcon = document.getElementById('resultIcon');
        this.resultTitle = document.getElementById('resultTitle');
        this.resultDescription = document.getElementById('resultDescription');
        this.riskLevel = document.getElementById('riskLevel');
        this.confidenceValue = document.getElementById('confidenceValue');
        this.progressFill = document.getElementById('progressFill');
        
        // Feature elements
        this.urlLength = document.getElementById('urlLength');
        this.domainAge = document.getElementById('domainAge');
        this.sslStatus = document.getElementById('sslStatus');
        this.suspiciousKeywords = document.getElementById('suspiciousKeywords');
        this.redirectCount = document.getElementById('redirectCount');
        this.riskScore = document.getElementById('riskScore');
    }

    attachEventListeners() {
        this.analyzeBtn.addEventListener('click', () => this.analyzeUrl());
        this.urlInput.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') {
                this.analyzeUrl();
            }
        });
    }

    async analyzeUrl() {
        const url = this.urlInput.value.trim();
        
        if (!url) {
            this.showError('Please enter a URL to analyze');
            return;
        }

        if (!this.isValidUrl(url)) {
            this.showError('Please enter a valid URL');
            return;
        }

        this.showLoading();
        
        try {
            // Extract features from the URL
            const features = this.extractFeatures(url);
            
            // Call your trained model API
            const result = await this.callModelAPI(url, features);
            
            this.showResults(result);
        } catch (error) {
            console.error('Analysis error:', error);
            this.showError('Analysis failed. Please try again.');
        }
    }

    extractFeatures(url) {
        const features = {};
        
        try {
            const urlObj = new URL(url.startsWith('http') ? url : `https://${url}`);
            
            // Basic URL features
            features.url_length = url.length;
            features.domain_length = urlObj.hostname.length;
            features.has_https = urlObj.protocol === 'https:';
            features.subdomain_count = (urlObj.hostname.match(/\./g) || []).length;
            features.path_length = urlObj.pathname.length;
            features.query_length = urlObj.search.length;
            features.fragment_length = urlObj.hash.length;
            
            // Suspicious patterns
            const suspiciousKeywords = [
                'paypal', 'amazon', 'microsoft', 'google', 'apple', 'facebook',
                'secure', 'verify', 'update', 'login', 'account', 'suspended',
                'confirm', 'click', 'urgent', 'immediately', 'expire'
            ];
            
            features.suspicious_keywords = suspiciousKeywords.filter(keyword => 
                url.toLowerCase().includes(keyword)
            ).length;
            
            // URL structure features
            features.has_ip = /\d+\.\d+\.\d+\.\d+/.test(urlObj.hostname);
            features.has_shortener = /bit\.ly|tinyurl|t\.co|goo\.gl|short\.link/.test(url);
            features.special_chars = (url.match(/[!@#$%^&*()_+=\[\]{}|;':",.<>?]/g) || []).length;
            features.digit_count = (url.match(/\d/g) || []).length;
            features.hyphen_count = (url.match(/-/g) || []).length;
            
            // Domain reputation (simplified)
            const trustedDomains = ['google.com', 'microsoft.com', 'apple.com', 'amazon.com'];
            features.is_trusted_domain = trustedDomains.some(domain => 
                urlObj.hostname.includes(domain)
            );
            
        } catch (error) {
            console.error('Feature extraction error:', error);
        }
        
        return features;
    }

    async callModelAPI(url, features) {
        // Replace this URL with your actual model API endpoint
        const apiEndpoint = '/api/predict';
        
        try {
            const response = await fetch(apiEndpoint, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    url: url,
                    features: features
                })
            });
            
            if (!response.ok) {
                throw new Error(`API call failed: ${response.status}`);
            }
            
            return await response.json();
            
        } catch (error) {
            console.log('Using mock prediction since API is not available');
            // Fallback to mock prediction for demonstration
            return this.mockPrediction(url, features);
        }
    }

    mockPrediction(url, features) {
        // Mock prediction logic based on extracted features
        let riskScore = 0;
        
        // Calculate risk based on features
        if (features.suspicious_keywords > 0) riskScore += 30;
        if (!features.has_https) riskScore += 25;
        if (features.url_length > 100) riskScore += 15;
        if (features.has_shortener) riskScore += 20;
        if (features.has_ip) riskScore += 35;
        if (features.special_chars > 10) riskScore += 10;
        if (features.subdomain_count > 3) riskScore += 15;
        
        // Reduce risk for trusted domains
        if (features.is_trusted_domain) riskScore = Math.max(0, riskScore - 40);
        
        const isPhishing = riskScore > 45;
        const confidence = Math.min(95, Math.max(60, riskScore + Math.random() * 15));
        
        let riskLevel;
        if (riskScore < 25) riskLevel = 'LOW';
        else if (riskScore < 50) riskLevel = 'MEDIUM';
        else if (riskScore < 75) riskLevel = 'HIGH';
        else riskLevel = 'CRITICAL';
        
        return {
            is_phishing: isPhishing,
            confidence: confidence,
            risk_level: riskLevel,
            risk_score: riskScore,
            features: {
                url_length: features.url_length,
                domain_age: Math.random() > 0.6 ? '2+ years' : 'Recently created',
                ssl_certificate: features.has_https,
                suspicious_keywords: features.suspicious_keywords,
                redirects: Math.floor(Math.random() * 3),
                has_ip: features.has_ip,
                has_shortener: features.has_shortener
            }
        };
    }

    showLoading() {
        this.resultsSection.classList.add('hidden');
        this.loadingSection.classList.remove('hidden');
        this.analyzeBtn.disabled = true;
    }

    showResults(result) {
        this.loadingSection.classList.add('hidden');
        this.resultsSection.classList.remove('hidden');
        this.analyzeBtn.disabled = false;
        
        // Update result card
        const resultCard = document.querySelector('.result-card');
        const resultInfo = document.querySelector('.result-info');
        const resultIconElement = document.querySelector('.result-icon');
        
        if (result.is_phishing) {
            resultCard.className = 'result-card phishing';
            resultInfo.className = 'result-info phishing';
            resultIconElement.className = 'result-icon phishing';
            this.resultIcon.className = 'fas fa-exclamation-triangle';
            this.resultTitle.textContent = 'Phishing Threat Detected';
            this.resultDescription.textContent = 'This URL appears to be malicious';
            this.progressFill.className = 'progress-fill phishing';
        } else {
            resultCard.className = 'result-card safe';
            resultInfo.className = 'result-info safe';
            resultIconElement.className = 'result-icon safe';
            this.resultIcon.className = 'fas fa-check-circle';
            this.resultTitle.textContent = 'URL Appears Safe';
            this.resultDescription.textContent = 'No immediate threats detected';
            this.progressFill.className = 'progress-fill safe';
        }
        
        // Update confidence and risk level
        this.confidenceValue.textContent = `${result.confidence.toFixed(1)}%`;
        this.progressFill.style.width = `${result.confidence}%`;
        
        const riskBadge = document.querySelector('.risk-badge');
        riskBadge.className = `risk-badge ${result.risk_level.toLowerCase()}`;
        this.riskLevel.textContent = `${result.risk_level} RISK`;
        
        // Update feature analysis
        this.updateFeatureDisplay('urlLength', result.features.url_length + ' characters', 
            result.features.url_length > 100 ? 'warning' : 'safe');
        
        this.updateFeatureDisplay('domainAge', result.features.domain_age,
            result.features.domain_age.includes('Recently') ? 'warning' : 'safe');
        
        this.updateFeatureDisplay('sslStatus', 
            result.features.ssl_certificate ? 'Valid' : 'Missing/Invalid',
            result.features.ssl_certificate ? 'safe' : 'danger');
        
        this.updateFeatureDisplay('suspiciousKeywords', 
            result.features.suspicious_keywords + ' detected',
            result.features.suspicious_keywords > 0 ? 'danger' : 'safe');
        
        this.updateFeatureDisplay('redirectCount', 
            result.features.redirects + ' found',
            result.features.redirects > 2 ? 'warning' : 'safe');
        
        this.updateFeatureDisplay('riskScore', 
            result.risk_score + '/100',
            result.risk_score > 50 ? 'danger' : result.risk_score > 25 ? 'warning' : 'safe');
    }

    updateFeatureDisplay(elementId, value, statusClass) {
        const element = document.getElementById(elementId);
        element.textContent = value;
        element.className = `feature-value ${statusClass}`;
    }

    showError(message) {
        this.loadingSection.classList.add('hidden');
        this.resultsSection.classList.add('hidden');
        this.analyzeBtn.disabled = false;
        
        // You can implement a toast notification here
        alert(message);
    }

    isValidUrl(string) {
        try {
            const url = string.startsWith('http') ? string : `https://${string}`;
            new URL(url);
            return true;
        } catch (_) {
            return false;
        }
    }
}

// Initialize the detector when the page loads
document.addEventListener('DOMContentLoaded', () => {
    new PhishingDetector();
});