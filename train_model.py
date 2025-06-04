import pandas as pd
import requests
from bs4 import BeautifulSoup
import pickle
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import confusion_matrix, accuracy_score, classification_report
from sklearn.ensemble import RandomForestClassifier
import time
from tqdm import tqdm
import re
from urllib.parse import urlparse
import numpy as np
from concurrent.futures import ThreadPoolExecutor, as_completed
import hashlib
import os
import json
from functools import lru_cache
import warnings
from requests.exceptions import RequestException
import lxml

# Create cache directory if it doesn't exist
CACHE_DIR = 'url_cache'
os.makedirs(CACHE_DIR, exist_ok=True)

# Configure requests session for better performance
session = requests.Session()
adapter = requests.adapters.HTTPAdapter(
    pool_connections=100,
    pool_maxsize=100,
    max_retries=3,
    pool_block=False
)
session.mount('http://', adapter)
session.mount('https://', adapter)

@lru_cache(maxsize=10000)
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

def get_cached_content(url):
    """Get cached content or fetch and cache it"""
    # Create URL hash for filename
    url_hash = hashlib.md5(url.encode()).hexdigest()
    cache_file = os.path.join(CACHE_DIR, f'{url_hash}.json')
    
    # Try to load from cache
    if os.path.exists(cache_file):
        try:
            with open(cache_file, 'r') as f:
                return json.load(f)
        except:
            pass
    
    # Fetch content if not in cache
    try:
        response = session.get(url, timeout=5, verify=False)
        content = {
            'status_code': response.status_code,
            'content': response.text,
            'headers': dict(response.headers)
        }
        
        # Cache the content
        with open(cache_file, 'w') as f:
            json.dump(content, f)
        
        return content
    except RequestException:
        return None

def extract_html_features(content):
    try:
        if not content or not content.get('content'):
            return None
            
        # Use lxml parser for better performance
        soup = BeautifulSoup(content['content'], 'lxml')
        
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
                if parsed_href.netloc != urlparse(url).netloc:
                    features['external_links'] += 1
                else:
                    features['internal_links'] += 1
                if parsed_href.scheme == 'https':
                    features['https_links'] += 1
                
        return features
    except:
        return None

def process_url(url_data):
    """Process a single URL with caching"""
    url = url_data['url']
    label = url_data['label']
    
    # Extract URL features (cached)
    url_features = extract_url_features(url)
    if not url_features:
        return None
        
    # Get HTML content (cached)
    content = get_cached_content(url)
    if not content:
        return None
        
    # Extract HTML features
    html_features = extract_html_features(content)
    if not html_features:
        return None
        
    # Combine features
    all_features = {**url_features, **html_features}
    feature_list = list(all_features.values())
    feature_list.append(label)
    return feature_list

def main():
    # Disable warnings
    warnings.filterwarnings('ignore')
    requests.packages.urllib3.disable_warnings()
    
    print("Loading dataset...")
    df = pd.read_csv('malicious_phish.csv')
    
    # Map URL types to binary labels
    type_mapping = {
        'benign': 0,
        'defacement': 1,
        'phishing': 1,
        'malware': 1
    }
    
    df['label'] = df['type'].map(type_mapping)
    
    # Create a balanced sample
    sample_size_per_class = 5000
    benign_sample = df[df['type'] == 'benign'].sample(n=min(sample_size_per_class, len(df[df['type'] == 'benign'])))
    malicious_sample = df[df['type'] != 'benign'].sample(n=min(sample_size_per_class, len(df[df['type'] != 'benign'])))
    df_sample = pd.concat([benign_sample, malicious_sample])
    
    # Prepare URL data for parallel processing
    url_data_list = [{'url': row['url'], 'label': row['label']} for idx, row in df_sample.iterrows()]
    
    # Process URLs in parallel
    print("\nExtracting features from URLs...")
    features_list = []
    with ThreadPoolExecutor(max_workers=20) as executor:
        future_to_url = {executor.submit(process_url, url_data): url_data for url_data in url_data_list}
        
        for future in tqdm(as_completed(future_to_url), total=len(url_data_list)):
            result = future.result()
            if result:
                features_list.append(result)
    
    # Create feature names
    feature_names = [
        # URL features
        'url_length', 'domain_length', 'path_length', 'subdomain_count',
        'digit_count', 'letter_count', 'special_char_count', 'has_https',
        'dots_in_domain', 'has_suspicious_words', 'has_ip_address',
        '@_count', '-_count', '_count', '=_count', '&_count', ';_count',
        '%_count', '$_count', '#_count',
        # HTML features
        'script_count', 'link_count', 'form_count', 'input_count',
        'iframe_count', 'img_count', 'password_fields', 'external_links',
        'internal_links', 'https_links', 'suspicious_links', 'text_length',
        'title_length', 'meta_tags', 'hidden_elements',
        'label'
    ]
    
    # Create DataFrame
    print("\nCreating DataFrame...")
    df_features = pd.DataFrame(features_list, columns=feature_names)
    
    # Save features
    df_features.to_csv('extracted_features.csv', index=False)
    print("Features saved to 'extracted_features.csv'")
    
    # Split features and target
    X = df_features.drop('label', axis=1)
    y = df_features['label']
    
    # Split the data
    print("\nSplitting data into train and test sets...")
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.25, random_state=42)
    
    # Train the model with better parameters
    print("Training Random Forest model...")
    model = RandomForestClassifier(
        n_estimators=200,
        max_depth=20,
        min_samples_split=10,
        min_samples_leaf=4,
        class_weight='balanced',
        random_state=42,
        n_jobs=-1
    )
    
    # Perform cross-validation
    print("\nPerforming cross-validation...")
    cv_scores = cross_val_score(model, X_train, y_train, cv=5)
    print(f"Cross-validation scores: {cv_scores}")
    print(f"Average CV score: {cv_scores.mean():.3f} (+/- {cv_scores.std() * 2:.3f})")
    
    # Train final model
    model.fit(X_train, y_train)
    
    # Evaluate the model
    print("\nEvaluating model...")
    y_pred = model.predict(X_test)
    y_proba = model.predict_proba(X_test)
    
    print("\nAccuracy:", accuracy_score(y_test, y_pred))
    print("\nConfusion Matrix:\n", confusion_matrix(y_test, y_pred))
    print("\nClassification Report:\n", classification_report(y_test, y_pred))
    
    # Feature importance analysis
    feature_importance = pd.DataFrame({
        'feature': feature_names[:-1],
        'importance': model.feature_importances_
    })
    feature_importance = feature_importance.sort_values('importance', ascending=False)
    print("\nTop 15 Most Important Features:")
    print(feature_importance.head(15))
    
    # Save the model and feature names
    print("\nSaving model and feature names...")
    with open('saved_model.pkl', 'wb') as f:
        pickle.dump({'model': model, 'feature_names': feature_names[:-1]}, f)
    
    print("Training completed successfully!")

if __name__ == "__main__":
    main()
