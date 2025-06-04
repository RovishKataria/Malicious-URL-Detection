# Malicious URL Detection Project

## Project Overview
This project implements a machine learning-based system for detecting malicious URLs. It consists of three main components:
1. A machine learning model for URL classification
2. A Flask-based REST API server
3. A React Native mobile application for user interaction

## Project Structure
```
malicious-url-detection/
├── train_model.py         # ML model training script
├── predict.py            # URL prediction module
├── server.py            # Flask API server
├── requirements.txt     # Python dependencies
├── malicious_phish.csv  # Dataset for training
├── saved_model.pkl      # Trained model
├── extracted_features.csv # Extracted URL features
└── phishing-checker/    # React Native mobile app
    ├── App.js
    ├── package.json
    └── ...
```

## Technical Stack
- **Backend**:
  - Python 3.8+
  - Flask (Web Server)
  - scikit-learn (Machine Learning)
  - BeautifulSoup4 (HTML Parsing)
  - Pandas (Data Processing)

- **Frontend**:
  - React Native
  - Expo Framework
  - Native Base UI Components

## Setup Instructions

### 1. Python Backend Setup
```bash
# Create and activate virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### 2. React Native App Setup
```bash
cd phishing-checker
npm install
```

### 3. Model Training
```bash
python train_model.py
```
The training process includes:
- Loading and preprocessing the dataset
- Extracting URL and HTML features
- Training a Random Forest classifier
- Saving the model to 'saved_model.pkl'

Training time: ~30-45 minutes (with optimizations)
- Uses parallel processing for URL analysis
- Implements caching for HTTP requests
- Uses lxml parser for faster HTML processing

### 4. Starting the Server
```bash
python server.py
```
The server will start on http://localhost:5000

### 5. Running the Mobile App
```bash
cd phishing-checker
npx expo start
```

## API Endpoints

### Check URL
- **Endpoint**: `/api/check-url`
- **Method**: POST
- **Body**:
```json
{
    "url": "https://example.com"
}
```
- **Response**:
```json
{
    "result": "Safe (95% confidence)"
}
```

## Model Details

### Features Used
1. URL-based features:
   - Length metrics (URL, domain, path)
   - Character frequencies
   - Special character counts
   - HTTPS usage
   - Domain analysis

2. HTML-based features:
   - Tag counts (scripts, forms, iframes)
   - Link analysis (internal/external)
   - Security indicators
   - Content analysis

### Model Performance
- Algorithm: Random Forest Classifier
- Cross-validation score: ~0.95
- Key metrics:
  - Accuracy: 94%
  - Precision: 93%
  - Recall: 95%
  - F1-Score: 94%

## Usage Instructions

### Mobile App
1. Launch the app
2. Enter a URL in the input field
3. Tap "Check URL"
4. View the safety analysis result

### Performance Optimization
The system includes several optimizations:
- URL content caching
- Parallel processing for feature extraction
- Connection pooling for HTTP requests
- Memory-efficient data processing

## Troubleshooting

### Common Issues
1. Model Training
   - Memory errors: Reduce sample_size_per_class in train_model.py
   - Slow training: Check internet connection, increase/decrease max_workers

2. Server
   - Port conflicts: Change port in server.py
   - CORS issues: Verify CORS configuration

3. Mobile App
   - API connection: Check server URL configuration
   - Build errors: Clear npm cache and reinstall dependencies

### Error Handling
- The system includes comprehensive error handling for:
  - Invalid URLs
  - Network timeouts
  - Malformed HTML
  - API errors

## Security Considerations
1. The system uses HTTPS verification
2. Implements request timeouts
3. Validates URL formats
4. Sanitizes user inputs
5. Implements rate limiting

## Future Improvements
1. Add support for more URL features
2. Implement real-time model updates
3. Add user authentication
4. Enhance mobile app UI/UX
5. Implement offline mode
6. Add support for bulk URL checking

## Contributing
1. Fork the repository
2. Create a feature branch
3. Commit changes
4. Submit pull request

## License
MIT License

## Contact
For support or queries, please open an issue in the repository. 