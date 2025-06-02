import joblib
import pandas as pd
# Load the pre-trained ML models for different layers
ml_model1 = joblib.load('decision_tree_model_layer1.pkl')  # For Layer 1 classification (e.g., Darknet, Normal)
ml_model2 = joblib.load('decision_tree_model_layer2.pkl')  # For Layer 2 classification (e.g., TOR, VPN, Zeronet, Freenet, I2P)
ml_model3 = joblib.load('decision_tree_model_layer3.pkl')  # For Layer 3 classification (e.g., Audio, Browsing)

# Dictionary to store blocked IPs
blocked_ips = {}

# Custom keys for Layer 1 (based on your provided list)
custom_keys_layer1 = ['Src Port', 'Fwd IAT Min', 'Fwd PSH Flags', 'Fwd Header Len',
       'Idle Max', 'Pkt Len Max', 'Pkt Len Mean', 'Pkt Len Std',
       'FIN Flag Cnt', 'CWE Flag Count', 'ECE Flag Cnt', 'Pkt Size Avg',
       'Fwd Seg Size Avg', 'Bwd Pkts/b Avg', 'Init Fwd Win Byts',
       'Init Bwd Win Byts', 'Fwd Act Data Pkts', 'Fwd Seg Size Min',
       'Idle Mean', 'Idle Std', 'Fwd IAT Max', 'Fwd IAT Mean', 'Pkt Len Min',
       'Flow IAT Min', 'Dst Port', 'Flow Duration', 'Tot Fwd Pkts',
       'TotLen Fwd Pkts', 'Fwd Pkt Len Max', 'Fwd Pkt Len Min', 'Fwd IAT Tot',
       'Fwd Pkt Len Std', 'Bwd Pkt Len Max', 'Bwd Pkt Len Min',
       'Bwd Pkt Len Std', 'Fwd Pkt Len Mean', 'Idle Min', 'Flow IAT Max',
       'Flow IAT Mean', 'PSH Flag Cnt', 'Bwd IAT Tot', 'Pkt Len Var',
       'Bwd Seg Size Avg', 'Bwd Pkt Len Mean', 'ACK Flag Cnt', 'Protocol',
       'Bwd IAT Std', 'Flow IAT Std', 'Tot Bwd Pkts', 'Bwd Pkts/s',
       'SYN Flag Cnt', 'Bwd Header Len', 'RST Flag Cnt', 'TotLen Bwd Pkts',
       'Bwd IAT Max', 'Flow Pkts/s', 'Bwd IAT Min', 'Fwd Pkts/s', 'Active Max',
       'Active Mean', 'Fwd IAT Std', 'Active Std', 'Bwd Blk Rate Avg',
       'Fwd Pkts/b Avg', 'Active Min', 'Down/Up Ratio', 'Subflow Bwd Pkts',
       'Fwd Byts/b Avg', 'Bwd IAT Mean', 'Subflow Bwd Byts',
       'Subflow Fwd Pkts', 'Bwd Byts/b Avg', 'Subflow Fwd Byts', 'Flow Byts/s',
       'Fwd Blk Rate Avg']

# Custom keys for Layer 2 and Layer 3 (based on your provided list)
custom_keys_layer2_3 = ['Src Port', 'Idle Max', 'Pkt Len Mean', 'Pkt Len Std', 'Pkt Len Var',
       'FIN Flag Cnt', 'SYN Flag Cnt', 'PSH Flag Cnt', 'ACK Flag Cnt',
       'CWE Flag Count', 'ECE Flag Cnt', 'Pkt Len Min', 'Down/Up Ratio',
       'Fwd Seg Size Avg', 'Bwd Seg Size Avg', 'Init Fwd Win Byts',
       'Init Bwd Win Byts', 'Fwd Seg Size Min', 'Active Mean', 'Active Std',
       'Active Max', 'Idle Mean', 'Idle Std', 'Pkt Size Avg', 'Bwd PSH Flags',
       'Pkt Len Max', 'Fwd Pkt Len Mean', 'Dst Port', 'Protocol',
       'Flow Duration', 'Fwd Pkt Len Max', 'Fwd Pkt Len Min', 'Bwd IAT Tot',
       'Fwd Pkt Len Std', 'Bwd Pkt Len Max', 'Bwd Pkt Len Min',
       'Bwd Pkt Len Mean', 'Bwd Pkt Len Std', 'Flow IAT Mean', 'Flow IAT Std',
       'Idle Min', 'Flow IAT Min', 'Fwd IAT Tot', 'Fwd IAT Mean',
       'Fwd IAT Std', 'Fwd IAT Max', 'Flow IAT Max', 'Bwd IAT Max',
       'Fwd Header Len', 'Tot Fwd Pkts', 'Subflow Fwd Pkts', 'Bwd IAT Mean',
       'Bwd IAT Std', 'Bwd Header Len', 'Tot Bwd Pkts', 'Subflow Bwd Pkts',
       'TotLen Bwd Pkts', 'Subflow Bwd Byts', 'Fwd IAT Min',
       'Fwd Act Data Pkts', 'Subflow Fwd Byts', 'TotLen Fwd Pkts',
       'Active Min', 'Bwd IAT Min', 'Fwd Pkts/b Avg', 'Fwd Byts/b Avg',
       'Bwd Pkts/s', 'RST Flag Cnt', 'Fwd Blk Rate Avg', 'Bwd Pkts/b Avg',
       'Bwd Byts/b Avg', 'Fwd Pkts/s', 'Bwd Blk Rate Avg']

# Function to classify the flow at Layer 1 (Normal or Darknet)
def classify_layer1(flow):
    features_df = pd.DataFrame([[flow[key].values[0] for key in custom_keys_layer1]], columns=custom_keys_layer1)
    prediction_layer1 = ml_model1.predict(features_df)  # Classify as Normal or Darknet
    return prediction_layer1[0]  # Return the classification result (Normal or Darknet)

# Function to classify the flow at Layer 2 (Darknet subcategories)
def classify_layer2(flow):
    features_df = pd.DataFrame([[flow[key].values[0] for key in custom_keys_layer2_3]], columns=custom_keys_layer2_3)
    prediction_layer2 = ml_model2.predict(features_df)  # Classify as TOR, VPN, I2P, etc.
    return prediction_layer2[0]  # Return the classification result (TOR, VPN, I2P, etc.)

# Function to classify the flow at Layer 3 (specific traffic type within Darknet)
def classify_layer3(flow):
    features_df = pd.DataFrame([[flow[key].values[0] for key in custom_keys_layer2_3]], columns=custom_keys_layer2_3)
    prediction_layer3 = ml_model3.predict(features_df)  # Classify as Audio, Browsing, Chat, etc.
    return prediction_layer3[0]  # Return the classification result (Audio, Browsing, etc.)

# Function to classify the entire flow with all layers
def classify_flow(flow):
    # Get Layer 1 classification first
    flow_pd =  pd.DataFrame([flow])
    layer1_result = classify_layer1(flow_pd)
    if layer1_result == "Normal":
        return {'Layer 1': layer1_result, 'Layer 2': None, 'Layer 3': None}  # Return only Layer 1 (Normal traffic)
    else:
        # Further classification based on Layer 2 and Layer 3 for Darknet traffic
        layer2_result = classify_layer2(flow_pd)
        layer3_result = classify_layer3(flow_pd)  # Classify within the Darknet category
        return {'Layer 1': layer1_result, 'Layer 2': layer2_result, 'Layer 3': layer3_result}

