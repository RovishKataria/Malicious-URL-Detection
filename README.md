# Malicious URL Detection
This project is extension of my previous project -> [Link](https://github.com/RovishKataria/Detection-of-Malicious-Mobile-Webpages)

The dataset is downloaded from -> [Link](https://www.kaggle.com/datasets/sid321axn/malicious-urls-dataset/data)

### For running this project following things needs to be installed
1. Node.js LTS [Link](https://nodejs.org/en)

2. ngrok [Link](https://ngrok.com/downloads/windows)
    - Extract the zip and place the ngrox.exe into C:\ngrox and open terminal from this folder.
    - You need to create an account on ngrok and get you authtoken. There will be authtoken and also a command for configuring your auth token "ngrok config add-authtoken YOUR_TOKEN".
    - In the terminal run "ngrok.exe config add-authtoken YOUR_TOKEN_HERE"

3. It is better to have virtual environment created and activated before installing required libraries.
    - To install run "pip install flask requests beautifulsoup4 pandas numpy scikit-learn".

### How to run the project?
1. Open a terminal and run "python train_model.py". This creates saved_model.pkl.
    - In the same terminal run "python server.py". You will see output like "Running on http://127.0.0.1:5000/ (Press CTRL+C to quit)"

2. For running ngrok you have two options:
    - 2.1 You can run from the folder C:\ngrok
        + Open terminal from C:\ngrok (where ngrox.exe is located) and run "ngrok http 5000"

     - 2.2 You can add ngrok to you PATH (Recommended)
        + Search "Environment Variables" in the Start menu
        + Open "Edit the system environment variables"
        + Click Environment Variables
        + Under System Variables, select Path → Edit
        + Click New → Add path to the folder containing ngrok.exe (e.g., C:\ngrok)
        + Click OK and restart PowerShell
        + Now, you can run "ngrok http 5000" from another terminal.

        You will get a  outlut like "Forwarding https://f82b63c2aac9.ngrok.io -> http://localhost:5000"
        
        Replace URL "https://f82b63c2aac9.ngrok.io" in App.js :
        
        await fetch('https://f82b63c2aac9.ngrok.io/abc', data)

3. Open another terminal and install React Native CLI (is not installed) by running "npm install -g expo-cli"
    - Create a new project by running "expo init phishing-checker".
    - Select "> blank   a minimal app as clean as an empty canvas".
    
    This will create a new folder called phishing-checker with a minimal React Native app no TypeScript, just plain JavaScript.
    
    - Replace the content of the phishing-checker\App.js with App.js
    - Go to project "cd phishing-checker" and install dependencies by running
    
    "npm install @react-navigation/native @react-navigation/stack react-native-screens react-native-safe-area-context react-native-gesture-handler react-native-reanimated react-native-vector-icons".
    - Then after dependencies are installed run "npm start".
    
    This will open the Metro Bundler. Use an Android emulator or Expo Go app on your phone to test (Expo Go worked better for me)

If there are errors do check that you have pasted the exact same URL in App.js and remember to put /abc at the end of URL.
