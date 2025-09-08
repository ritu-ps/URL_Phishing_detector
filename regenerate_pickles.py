import pickle
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler

def regenerate_pickle_files():
    print("Regenerating pickle files with proper protocol...")
    
    # Create feature names that match your extract_features function
    feature_names = [
        'url_length', 'domain_length', 'has_https', 'subdomain_count', 
        'path_length', 'query_length', 'fragment_length', 'suspicious_keywords',
        'has_ip', 'has_shortener', 'special_chars', 'digit_count', 
        'hyphen_count', 'underscore_count', 'dot_count', 'slash_count',
        'is_trusted_domain'
    ]
    
    # Generate realistic sample training data
    np.random.seed(42)
    n_samples = 1000
    
    # Create realistic feature distributions
    X_train = np.zeros((n_samples, len(feature_names)))
    
    # URL length: mostly short, some long
    X_train[:, 0] = np.random.lognormal(3, 1, n_samples)  # url_length
    
    # Domain length: mostly short
    X_train[:, 1] = np.random.lognormal(2.5, 0.8, n_samples)  # domain_length
    
    # Binary features (https, ip, shortener, trusted domain)
    for col in [2, 8, 9, 16]:  # has_https, has_ip, has_shortener, is_trusted_domain
        X_train[:, col] = np.random.choice([0, 1], n_samples, p=[0.7, 0.3])
    
    # Count features (subdomains, keywords, special chars, etc.)
    for col in [3, 7, 10, 11, 12, 13, 14, 15]:  # various count features
        X_train[:, col] = np.random.poisson(2, n_samples)
    
    # Create target variable (phishing = 1, legitimate = 0)
    # Make it somewhat predictable based on features
    y_train = ((X_train[:, 0] > 100) |  # long URLs
               (X_train[:, 7] > 5) |    # many suspicious keywords
               (X_train[:, 8] == 1) |   # has IP
               (X_train[:, 9] == 1) |   # has shortener
               (X_train[:, 10] > 10))   # many special chars
    y_train = y_train.astype(int)
    
    # Add some noise
    flip_mask = np.random.random(n_samples) < 0.1
    y_train[flip_mask] = 1 - y_train[flip_mask]
    
    # Train a realistic model
    model = RandomForestClassifier(
        n_estimators=100,
        max_depth=10,
        random_state=42,
        class_weight='balanced'
    )
    model.fit(X_train, y_train)
    
    # Create and fit scaler
    scaler = StandardScaler()
    scaler.fit(X_train)
    
    # Save with protocol 4 for maximum compatibility
    with open('phishing_detector_model.pkl', 'wb') as f:
        pickle.dump(model, f, protocol=4)
    print("✅ Model saved successfully")
    
    with open('scaler.pkl', 'wb') as f:
        pickle.dump(scaler, f, protocol=4)
    print("✅ Scaler saved successfully")
    
    with open('feature_names.pkl', 'wb') as f:
        pickle.dump(feature_names, f, protocol=4)
    print("✅ Feature names saved successfully")
    
    # Test loading
    try:
        with open('phishing_detector_model.pkl', 'rb') as f:
            test_model = pickle.load(f)
        with open('scaler.pkl', 'rb') as f:
            test_scaler = pickle.load(f)
        with open('feature_names.pkl', 'rb') as f:
            test_features = pickle.load(f)
        
        print("✅ All files verified and loaded successfully!")
        print(f"Model type: {type(test_model)}")
        print(f"Feature names: {len(test_features)} features")
        print(f"Sample prediction: {test_model.predict(X_train[:1])[0]}")
        
    except Exception as e:
        print(f"❌ Verification failed: {e}")

if __name__ == "__main__":
    regenerate_pickle_files()