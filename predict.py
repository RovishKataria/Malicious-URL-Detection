# B. Code for Classifying the URL
import requests
from bs4 import BeautifulSoup
import pickle
import re
from urllib.parse import urlparse

def extract_url_features(url):
    try:
        # Parse URL
        parsed = urlparse(url)
        
        features = {
            'length': len(url),
            'domain_length': len(parsed.netloc),
            'path_length': len(parsed.path),
            'subdomain_count': len(parsed.netloc.split('.')) - 1,
            'digit_count': sum(c.isdigit() for c in url),
            'letter_count': sum(c.isalpha() for c in url),
            'special_char_count': sum(not c.isalnum() for c in url),
            'has_https': int(parsed.scheme == 'https'),
            'dots_in_domain': parsed.netloc.count('.'),
            'has_suspicious_words': 0,
            'has_ip_address': int(bool(re.match(r'\d+\.\d+\.\d+\.\d+', parsed.netloc))),
        }
        
        # Check for suspicious words
        suspicious_words = ['login', 'signin', 'verify', 'secure', 'account', 'password', 'bank', 'update']
        features['has_suspicious_words'] = sum(word in url.lower() for word in suspicious_words)
        
        # Add character frequencies
        for char in ['@', '-', '_', '=', '&', ';', '%', '$', '#']:
            features[f'{char}_count'] = url.count(char)
        
        return features
    except:
        return None

def extract_html_features(soup, domain):
    try:
        features = {
            # Basic tag counts
            'script_count': len(soup.find_all('script')),
            'link_count': len(soup.find_all('a')),
            'form_count': len(soup.find_all('form')),
            'input_count': len(soup.find_all('input')),
            'iframe_count': len(soup.find_all('iframe')),
            'img_count': len(soup.find_all('img')),
            
            # Security indicators
            'password_fields': len(soup.find_all('input', {'type': 'password'})),
            'external_links': 0,
            'internal_links': 0,
            'https_links': 0,
            'suspicious_links': 0,
            
            # Content analysis
            'text_length': len(soup.get_text()),
            'title_length': len(soup.title.string) if soup.title else 0,
            'meta_tags': len(soup.find_all('meta')),
            'hidden_elements': len(soup.find_all(style=re.compile('display:\s*none'))),
        }
        
        # Analyze links
        for link in soup.find_all('a', href=True):
            href = link['href']
            if href.startswith('http'):
                parsed_href = urlparse(href)
                if parsed_href.netloc != domain:
                    features['external_links'] += 1
                else:
                    features['internal_links'] += 1
                if parsed_href.scheme == 'https':
                    features['https_links'] += 1
                
        return features
    except:
        return None

def retrive_pred(URL):
    print(f"\nAnalyzing URL: {URL}")
    try:
        # Fetch URL content
        r = requests.get(URL, timeout=10)
        soup = BeautifulSoup(r.content, 'html.parser')
        
        # Get URL features
        url_features = extract_url_features(URL)
        if not url_features:
            return "Error: Could not analyze URL structure"
            
        # Get HTML features
        domain = urlparse(URL).netloc
        html_features = extract_html_features(soup, domain)
        if not html_features:
            return "Error: Could not analyze webpage content"
            
        # Combine features
        all_features = {**url_features, **html_features}
        
        # Load model and feature names
        with open('saved_model.pkl', 'rb') as f:
            model_data = pickle.load(f)
            model = model_data['model']
            feature_names = model_data['feature_names']
        
        # Prepare features in correct order
        features = [all_features[name] for name in feature_names]
        
        # Get prediction and probabilities
        proba = model.predict_proba([features])[0]
        safe_prob = proba[0]
        malicious_prob = proba[1]
        
        print(f"Safe probability: {safe_prob:.2%}")
        print(f"Malicious probability: {malicious_prob:.2%}")
        
        # Return result with confidence score
        if malicious_prob > 0.75:
            return f"Malicious ({malicious_prob:.1%} confidence)"
        elif malicious_prob > 0.4:
            return f"Suspicious ({malicious_prob:.1%} risk)"
        else:
            return f"Safe ({safe_prob:.1%} confidence)"
            
    except Exception as e:
        print("Error in prediction:", e)
        return f"Error: {str(e)}"
