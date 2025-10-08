import numpy as np
import sys
from sklearn.metrics import classification_report
import pandas as pd
from sklearn.preprocessing import LabelEncoder, MinMaxScaler, Normalizer
import tensorflow as tf
import pickle
import json

path = 'Uploaded_files/'
val = sys.argv[1]
path += sys.argv[2]
f = open(path)
data_Validate = pd.read_csv(f)

# Replace this with your actual dataset columns
columns = [
    'Destination Port', 'Flow Duration', 'Total Fwd Packets', 'Total Backward Packets',
    # ... include all columns except Label from the query until 'Label'
    # e.g., 'Avg Fwd Segment Size', 'Avg Bwd Segment Size', ... (list all as in your dataset order)
    'Label'
]
data_Validate.columns = columns

# Encode necessary categorical columns if required
# For example, if 'Label' is categorical
label_le = LabelEncoder()
data_Validate['Label'] = label_le.fit_transform(data_Validate['Label'])

df_validate = data_Validate.copy(deep=True)
x_validate = df_validate.drop(['Label'], axis=1)
y_validate = df_validate['Label']

scaler = MinMaxScaler()
scaler.fit(x_validate)
scaled_data = scaler.transform(x_validate)
x_validate = pd.DataFrame(scaled_data, columns=x_validate.columns)

# Load models (update these paths/names if required)
if val == 'knn':
    knn_bin = pickle.load(open('knn_binary_class.sav', 'rb'))
    knn_multi = pickle.load(open('knn_multi_class.sav', 'rb'))
    x_predict_bin = knn_bin.predict(x_validate)
    x_predict_multi = knn_multi.predict(x_validate)
    df_validate['binary class'] = ['Normal' if i == 0 else 'Attack' for i in x_predict_bin]
    df_validate['multi class'] = x_predict_multi
elif val == 'rf':
    rf_bin = pickle.load(open('random_forest_binary_class.sav', 'rb'))
    rf_multi = pickle.load(open('random_forest_multi_class.sav', 'rb'))
    x_predict_bin = rf_bin.predict(x_validate)
    x_predict_multi = rf_multi.predict(x_validate)
    df_validate['binary class'] = ['Normal' if i == 0 else 'Attack' for i in x_predict_bin]
    df_validate['multi class'] = x_predict_multi
elif val == 'cnn':
    x_validate_cnn = x_validate.values
    scaler = Normalizer().fit(x_validate_cnn)
    x_validate_cnn = scaler.transform(x_validate_cnn)
    cnn_bin = tf.keras.models.load_model('latest_cnn_bin.h5')
    cnn_multi = tf.keras.models.load_model('latest_cnn_multiclass.h5')
    x_bin = np.reshape(x_validate_cnn, (x_validate_cnn.shape[0], 1, x_validate_cnn.shape[1]))
    x_multi = np.reshape(x_validate_cnn, (x_validate_cnn.shape, x_validate_cnn.shape[1], 1))
    x_predict_bin = cnn_bin.predict(x_bin, verbose=False)
    x_predict_multi = cnn_multi.predict(x_multi, verbose=False)
    l_bin = [round(j) for j in x_predict_bin]
    df_validate['binary class'] = ['Normal' if i == 0 else 'Attack' for i in l_bin]
    # Here you need your multiclass decoding logic
    # df_validate['multi class'] = your_decoded_multiclass_results
elif val == 'lstm':
    lstm_bin = tf.keras.models.load_model('lstm_latest_bin.h5')
    lstm_multi = tf.keras.models.load_model('lstm_latest_multiclass.h5')
    x_validate_lstm = x_validate.values
    scaler = Normalizer().fit(x_validate_lstm)
    x_validate_lstm = scaler.transform(x_validate_lstm)
    x_bin = np.reshape(x_validate_lstm, (x_validate_lstm.shape, 1, x_validate_lstm.shape[1]))
    x_multi = np.reshape(x_validate_lstm, (x_validate_lstm.shape, 1, x_validate_lstm.shape[1]))
    x_predict_bin = lstm_bin.predict(x_bin, verbose=False)
    x_predict_multi = lstm_multi.predict(x_multi, verbose=False)
    l_bin = [round(j) for j in x_predict_bin]
    df_validate['binary class'] = ['Normal' if i == 0 else 'Attack' for i in l_bin]
    # df_validate['multi class'] = your_decoded_multiclass_results

# Save the results back to CSV (optional)
df_validate.to_csv(path, index=False)

# Calculate counts of attack types (using multi class column)
attack_type_counts = df_validate['multi class'].value_counts().to_dict()

# Output counts to a json file for backend access
with open(f'{val}_attack_type_counts.json', 'w') as f:
    json.dump(attack_type_counts, f)

# Continue saving metrics if needed
def save_report(y_true, y_pred, filename):
    report = classification_report(y_true, y_pred, output_dict=True)
    with open(filename, 'w') as f:
        json.dump(report, f)

save_report(df_validate['binary class'], df_validate['binary class'], f'{val}_bin_report.json')
save_report(df_validate['multi class'], df_validate['multi class'], f'{val}_multi_report.json')

# Count occurrences of each attack type
attack_type_counts = pd.Series(df_validate['multi class']).value_counts().to_dict()
with open(f'{val}_attack_type_counts.json', 'w') as f:
    json.dump(attack_type_counts, f)


print('completed')
