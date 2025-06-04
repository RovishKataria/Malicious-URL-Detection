// D. Code for User Interface using React Native
import React, { useState } from 'react';
import { StyleSheet, Text, View, TextInput, TouchableOpacity, ActivityIndicator, SafeAreaView, KeyboardAvoidingView, ScrollView, Platform, Keyboard, TouchableWithoutFeedback } from 'react-native';
import { NavigationContainer } from '@react-navigation/native';
import { createStackNavigator } from '@react-navigation/stack';
import Icon from 'react-native-vector-icons/MaterialIcons';

// Replace this URL with your ngrok URL
const API_URL = 'https://cbdb-202-3-77-210.ngrok-free.app/api/check-url';  // Example: https://abc123.ngrok.io/api/check-url

function HomeScreen({ navigation }) {
  const [url, setUrl] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const validateUrl = (text) => {
    try {
      new URL(text);
      return true;
    } catch {
      return false;
    }
  };

  const cleanUrl = (url) => {
    // Remove leading/trailing whitespace and @ symbol
    return url.trim().replace(/^@+/, '');
  };

  const onButtonPress = async () => {
    if (!url) {
      setError('Please enter a URL');
      return;
    }

    const cleanedUrl = cleanUrl(url);
    if (!validateUrl(cleanedUrl)) {
      setError('Please enter a valid URL');
      return;
    }

    setError('');
    setLoading(true);

    try {
      const response = await fetch(API_URL, {
        method: 'POST',
        headers: {
          'Accept': 'application/json',
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ url: cleanedUrl })
      });
      
      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.error || 'Server error');
      }
      
      const data = await response.json();
      navigation.navigate('Result', { result: data.result });
    } catch (error) {
      setError(error.message || 'Failed to check URL');
    } finally {
      setLoading(false);
    }
  };

  return (
    <SafeAreaView style={styles.container}>
      <KeyboardAvoidingView 
        behavior={Platform.OS === "ios" ? "padding" : "height"}
        style={styles.container}
      >
        <TouchableWithoutFeedback onPress={Keyboard.dismiss}>
          <ScrollView 
            contentContainerStyle={styles.scrollContent}
            keyboardShouldPersistTaps="handled"
          >
            <View style={styles.content}>
              <Icon name="security" size={60} color="#007BFF" style={styles.icon} />
              <Text style={styles.header}>URL Phishing Checker</Text>
              <Text style={styles.subtitle}>Enter a URL to check if it's malicious</Text>
              
              <View style={styles.inputContainer}>
                <TextInput
                  style={styles.input}
                  onChangeText={text => {
                    setUrl(text);
                    setError('');
                  }}
                  value={url}
                  placeholder="https://example.com"
                  placeholderTextColor="#999"
                  autoCapitalize="none"
                  autoCorrect={false}
                  keyboardType="url"
                />
              </View>

              {error ? <Text style={styles.errorText}>{error}</Text> : null}

              <TouchableOpacity
                style={[styles.button, loading && styles.buttonDisabled]}
                onPress={onButtonPress}
                disabled={loading}
              >
                {loading ? (
                  <ActivityIndicator color="#fff" />
                ) : (
                  <Text style={styles.buttonText}>Check URL</Text>
                )}
              </TouchableOpacity>
            </View>
          </ScrollView>
        </TouchableWithoutFeedback>
      </KeyboardAvoidingView>
    </SafeAreaView>
  );
}

function ResultScreen({ route, navigation }) {
  const { result } = route.params;
  
  // Parse the result to separate status and confidence
  const parseResult = (result) => {
    const match = result.match(/(Malicious|Suspicious|Safe|Error)(.*)/);
    if (match) {
      return {
        status: match[1],
        confidence: match[2].trim().replace(/[()]/g, '')
      };
    }
    return { status: result, confidence: '' };
  };

  const { status, confidence } = parseResult(result);
  const isMalicious = status === 'Malicious';
  const isSuspicious = status === 'Suspicious';
  const isError = status === 'Error';

  const getIcon = () => {
    if (isError) return 'error';
    if (isMalicious) return 'warning';
    if (isSuspicious) return 'help';
    return 'check-circle';
  };

  const getColor = () => {
    if (isError) return '#8B0000';
    if (isMalicious) return '#FF3B30';
    if (isSuspicious) return '#FF9500';
    return '#34C759';
  };

  const getMessage = () => {
    if (isError) return result;
    if (isMalicious) return 'This URL appears to be malicious. Do not proceed!';
    if (isSuspicious) return 'This URL shows some suspicious patterns. Proceed with caution.';
    return 'This URL appears to be safe.';
  };

  return (
    <SafeAreaView style={styles.container}>
      <View style={styles.content}>
        <Icon
          name={getIcon()}
          size={80}
          color={getColor()}
          style={styles.icon}
        />
        <Text style={[styles.resultText, { color: getColor() }]}>
          {status}
        </Text>
        {confidence ? (
          <Text style={styles.confidenceText}>
            {confidence}
          </Text>
        ) : null}
        <Text style={styles.resultDescription}>
          {getMessage()}
        </Text>
        <TouchableOpacity
          style={[styles.button, styles.backButton]}
          onPress={() => navigation.goBack()}
        >
          <Text style={styles.buttonText}>Check Another URL</Text>
        </TouchableOpacity>
      </View>
    </SafeAreaView>
  );
}

const Stack = createStackNavigator();

export default function App() {
  return (
    <NavigationContainer>
      <Stack.Navigator
        screenOptions={{
          headerStyle: {
            backgroundColor: '#007BFF',
          },
          headerTintColor: '#fff',
          headerTitleStyle: {
            fontWeight: 'bold',
          },
        }}
      >
        <Stack.Screen
          name="Home"
          component={HomeScreen}
          options={{ title: 'URL Checker' }}
        />
        <Stack.Screen
          name="Result"
          component={ResultScreen}
          options={{ title: 'Results' }}
        />
      </Stack.Navigator>
    </NavigationContainer>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: '#f8f9fa',
  },
  content: {
    flex: 1,
    justifyContent: 'center',
    alignItems: 'center',
    padding: 20,
  },
  icon: {
    marginBottom: 20,
  },
  header: {
    fontSize: 28,
    fontWeight: 'bold',
    color: '#1a1a1a',
    marginBottom: 10,
    textAlign: 'center',
  },
  subtitle: {
    fontSize: 16,
    color: '#666',
    marginBottom: 30,
    textAlign: 'center',
  },
  inputContainer: {
    width: '100%',
    marginBottom: 20,
  },
  input: {
    height: 50,
    backgroundColor: '#fff',
    borderWidth: 1,
    borderColor: '#ddd',
    borderRadius: 10,
    paddingHorizontal: 15,
    fontSize: 16,
    color: '#333',
    shadowColor: '#000',
    shadowOffset: {
      width: 0,
      height: 2,
    },
    shadowOpacity: 0.1,
    shadowRadius: 3,
    elevation: 3,
  },
  button: {
    backgroundColor: '#007BFF',
    paddingVertical: 15,
    paddingHorizontal: 30,
    borderRadius: 10,
    width: '100%',
    shadowColor: '#000',
    shadowOffset: {
      width: 0,
      height: 2,
    },
    shadowOpacity: 0.1,
    shadowRadius: 3,
    elevation: 3,
  },
  buttonDisabled: {
    opacity: 0.7,
  },
  buttonText: {
    color: '#fff',
    fontSize: 18,
    fontWeight: '600',
    textAlign: 'center',
  },
  errorText: {
    color: '#FF3B30',
    marginBottom: 15,
    textAlign: 'center',
  },
  resultText: {
    fontSize: 32,
    fontWeight: 'bold',
    marginBottom: 15,
    textAlign: 'center',
  },
  resultDescription: {
    fontSize: 18,
    color: '#666',
    marginBottom: 30,
    textAlign: 'center',
  },
  malicious: {
    color: '#FF3B30',
  },
  safe: {
    color: '#34C759',
  },
  backButton: {
    marginTop: 20,
  },
  scrollContent: {
    flexGrow: 1,
    justifyContent: 'center',
  },
  confidenceText: {
    fontSize: 18,
    color: '#666',
    marginBottom: 20,
    textAlign: 'center',
  },
});
