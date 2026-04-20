# ========================= IMPORT PACKAGES ==================================

import warnings
warnings.filterwarnings("ignore")

import pandas as pd
import numpy as np

from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from sklearn.ensemble import RandomForestClassifier
from sklearn.neural_network import MLPClassifier
from sklearn import metrics

import matplotlib.pyplot as plt
import seaborn as sns




# ======================== DATA SELECTION ==================================

print("--------------------------------------")
print(" Input data ")
print("--------------------------------------")
print()

dataframe = pd.read_csv('cybersecurity_attacks.csv')
print(dataframe.head(10))


# ======================== DATA PREPROCESSING ==============================

print("----------------------------------------------")
print(" Missing Values (Before) ")
print("----------------------------------------------")
print(dataframe.isnull().sum())

dataframe.fillna("missing", inplace=True)

print("----------------------------------------------")
print(" Missing Values (After) ")
print("----------------------------------------------")
print(dataframe.isnull().sum())


# ======================== LABEL ENCODING ==================================

print("----------------------------------------------------")
print("            Before Label Encoding                   ")
print("----------------------------------------------------")
print()
print(dataframe['Traffic Type'].head(15))

label_encoders = {}

# Encode target label separately
le_label = LabelEncoder()

dataframe['Traffic Type'] = le_label.fit_transform(dataframe['Traffic Type'])

print(dataframe['Traffic Type'].head(15))



# Encode categorical features
categorical_columns = dataframe.select_dtypes(include=['object']).columns

for col in categorical_columns:
    le = LabelEncoder()
    dataframe[col] = le.fit_transform(dataframe[col].astype(str))
    label_encoders[col] = le


    
print("----------------------------------------------------")
print("            After Label Encoding                   ")
print("----------------------------------------------------")
print()
print(dataframe['Traffic Type'].head(15))
    

# ================== DATA SPLITTING ====================

X = dataframe.drop('Traffic Type', axis=1)
y = dataframe['Traffic Type']

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

print("---------------------------------------------")
print(" Data Splitting ")
print("---------------------------------------------")
print("Total samples :", dataframe.shape[0])
print("Train samples :", X_train.shape[0])
print("Test samples  :", X_test.shape[0])



#-------------------------- CLASSIFICATION  --------------------------------


# ================= XGBOOST CLASSIFIER ====================

from xgboost import XGBClassifier

xgb_model = XGBClassifier(use_label_encoder=False, eval_metric='mlogloss')

# Train
xgb_model.fit(X_train, y_train)

# Predict
y_pred_xgb = xgb_model.predict(X_train)

# Accuracy
acc_xgb = metrics.accuracy_score(y_train, y_pred_xgb) * 100

print("---------------------------------------------")
print("   Classification - XGBoost ")
print("---------------------------------------------")
print("Accuracy =", acc_xgb)
print()
print("Classification Report =\n")
print(metrics.classification_report(y_train, y_pred_xgb))



import pickle
# Save hybrid model
with open('model_hybrid.pickle', 'wb') as f:
    pickle.dump(xgb_model, f)



# ================= LSTM MODEL ====================



print("---------------------------------------------")
print("   Classification - Model Training ")
print("---------------------------------------------")

from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import LSTM, Dense
from tensorflow.keras.utils import to_categorical

# Convert to numpy
X_train_lstm = np.array(X_train)
X_test_lstm = np.array(X_test)

# Reshape to 3D (samples, timesteps, features)
X_train_lstm = X_train_lstm.reshape((X_train_lstm.shape[0], 1, X_train_lstm.shape[1]))
X_test_lstm = X_test_lstm.reshape((X_test_lstm.shape[0], 1, X_test_lstm.shape[1]))

# One-hot encode target
y_train_lstm = to_categorical(y_train)
y_test_lstm = to_categorical(y_test)

# Build model
lstm_model = Sequential()
lstm_model.add(LSTM(64, input_shape=(1, X_train.shape[1])))
lstm_model.add(Dense(64, activation='relu'))
lstm_model.add(Dense(y_train_lstm.shape[1], activation='softmax'))

# Compile
lstm_model.compile(loss='categorical_crossentropy', optimizer='adam')

# Train
lstm_model.fit(X_train_lstm, y_train_lstm, epochs=10, batch_size=32, verbose=1)

# Evaluate
loss = lstm_model.evaluate(X_test_lstm, y_test_lstm, verbose=0)

acc_lstm = 100 - loss


print("---------------------------------------------")
print("   Performance - LSTM ")
print("---------------------------------------------")
print("Accuracy =", acc_lstm ,'%')
print()
print("Loss =", loss ,'%')




## 

import seaborn as sns
sns.barplot(x=['XGBoost','LSTM'],y=[acc_xgb,acc_lstm])
plt.title("Comparison Graph")
plt.show()




