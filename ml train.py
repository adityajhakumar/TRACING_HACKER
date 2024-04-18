import numpy as np # linear algebra
import pandas as pd # data processing, CSV file I/O (e.g. pd.read_csv)
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier
from sklearn.svm import SVC
from sklearn.metrics import jaccard_score
from sklearn.metrics import f1_score
from sklearn.metrics import log_loss
from sklearn.metrics import classification_report,confusion_matrix,accuracy_score
import sklearn.metrics as metrics
from scipy.stats import randint, uniform
import pickle
from xgboost import XGBClassifier
import pandas as pd
from urllib.parse import urlparse
from sklearn.preprocessing import StandardScaler
import warnings

# Filter out the warning about feature names
warnings.filterwarnings("ignore", message="X does not have valid feature names")

df = pd.read_csv(r"C:\Users\adity\Desktop\dataset_phishing.csv")
df.head()
df.info()
df.columns
df['status'].value_counts()
#change status into int dtype with legitimate as 0 and phishing as 1
mapping = {'legitimate':0, 'phishing':1}

df['status'] = df['status'].map(mapping)
df['status'].value_counts()
corr_matrix = df.corr(numeric_only=True)
corr_matrix
target_corr = corr_matrix['status']
target_corr
threshold=0.1
relevant_features = target_corr[abs(target_corr)>threshold].index.tolist()
relevant_features
X = df[relevant_features]
X = X.drop('status', axis=1)
y = df['status']
X.head()
y.head()
X_train, X_test, y_train, y_test = train_test_split(X,y, test_size=0.2, random_state=42)
scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train)
X_test_scaled = scaler.fit_transform(X_test)
svm = SVC()
svm.fit(X_train_scaled,y_train)
svm_predict = svm.predict(X_test_scaled)
accuracy = accuracy_score(y_test,svm_predict)
print("Accuracy:{}%".format(round(accuracy *100), 1))
svm_Accuracy_Score = accuracy_score(y_test,svm_predict)
svm_JaccardIndex = jaccard_score(y_test,svm_predict)
svm_F1_Score = f1_score(y_test,svm_predict)
svm_Log_Loss = log_loss(y_test,svm_predict)
print(f"Accuracy: {svm_Accuracy_Score}")
print(f"Jaccard Index: {svm_JaccardIndex}")
print(f"F1 Score: {svm_F1_Score}")
print(f"Log Loss: {svm_Log_Loss}")



# Function to preprocess URL
def preprocess_url(url):
    parsed_url = urlparse(url)
    # Extract relevant features from the URL
    features = [
        len(url),                                           # length_url
        len(parsed_url.hostname),                           # length_hostname
        int(parsed_url.hostname.replace('.', '').isnumeric()),  # ip (1 if numeric, 0 otherwise)
        parsed_url.hostname.count('.'),                     # nb_dots
        parsed_url.hostname.count('-'),                     # nb_hyphens
        '@' in parsed_url.netloc,                           # nb_at
        '?' in parsed_url.query,                            # nb_qm
        '&' in parsed_url.query,                            # nb_and
        '|' in parsed_url.query,                            # nb_or
        '=' in parsed_url.query,                            # nb_eq
        '_' in parsed_url.netloc,                           # nb_underscore
        '~' in parsed_url.netloc,                           # nb_tilde
        '%' in parsed_url.netloc,                           # nb_percent
        '/' in parsed_url.path,                             # nb_slash
        '*' in parsed_url.path,                             # nb_star
        ':' in parsed_url.path,                             # nb_colon
        ',' in parsed_url.path,                             # nb_comma
        ';' in parsed_url.path,                             # nb_semicolumn
        '$' in parsed_url.path,                             # nb_dollar
        ' ' in parsed_url.path,                             # nb_space
        'www' in parsed_url.netloc,                         # nb_www
        '.com' in parsed_url.netloc,                        # nb_com
        '//' in url,                                        # nb_dslash
        'http' in parsed_url.path,                          # http_in_path
        'https' in parsed_url.netloc,                       # https_token
        sum(c.isdigit() for c in url) / len(url),           # ratio_digits_url
        sum(c.isdigit() for c in parsed_url.netloc) / len(parsed_url.netloc),  # ratio_digits_host
        parsed_url.netloc.encode('idna') != parsed_url.netloc,  # punycode
        parsed_url.port != None,                            # port
        '.com' in parsed_url.path,                          # tld_in_path
        '.com' in parsed_url.netloc,                        # tld_in_subdomain
        '.' in parsed_url.netloc and parsed_url.netloc.split('.')[0] != 'www',  # abnormal_subdomain
        len(parsed_url.netloc.split('.')),                 # nb_subdomains
        parsed_url.netloc.startswith('www.') or parsed_url.netloc.endswith('.com'),  # prefix_suffix
        'random' in parsed_url.netloc or 'random' in parsed_url.path,  # random_domain
        '.php' in parsed_url.path or '.html' in parsed_url.path,  # path_extension
      
        0,  # nb_external_redirection
        0,  # length_words_raw
        0,  # char_repeat
        0,  # shortest_words_raw
        0,  # shortest_word_host
        0,  # shortest_word_path
        0,  # longest_words_raw
        0,  # longest_word_host
        0,  # longest_word_path
        0,  # avg_words_raw
        0,  # avg_word_host
        0,  # avg_word_path
    ]
    return np.array(features).reshape(1, -1)

# Load the trained SVM model
svm_model = svm  # Assuming svm is the trained SVM model
scaler = scaler  # Assuming scaler is the trained StandardScaler

# Function to predict phishing status
def predict_phishing(url):
    # Preprocess the URL
    processed_url = preprocess_url(url)
    # Scale the features
    processed_url_scaled = scaler.transform(processed_url)
    # Predict the phishing status
    prediction = svm_model.predict(processed_url_scaled)
    return prediction[0]

# Take user input for URL
user_url = input("Enter the URL to predict: ")

# Predict phishing status
prediction = predict_phishing(user_url)
if prediction == 1:
    print("The URL is classified as legitimate.")
else:
    print("The URL is classified as phishing.")
