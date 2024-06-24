import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
from sklearn.metrics import confusion_matrix, f1_score, precision_score, recall_score

# Load the dataset
dataset_path = 'SDN-dataset.csv'
data = pd.read_csv(dataset_path)

# Define true labels (1 for attack, 0 for normal)
true_labels = np.array([0] * 1000 + [1] * 4000)

# Extract relevant features
feature_columns = ['dst[arp]', 'src[arp]', 'pkt_size', 'total_time']
data = data[feature_columns]

# Initialize parameters from the provided detection logic
window_size = 50  # Increased window size
entropy_checks = 0
consecutive_anomalies = 0
alpha = 0.1  # Tuned alpha for EWMA
initial_threshold = None
attack_log = []
drop_indices = []
blacklist = {}
anomaly_counter = 0
last_anomaly_feature = None
dropped_packets_info = {}

# Open log file
log_file = open('output_data.txt', 'w')

# Helper functions from the provided code
def calculate_entropy(window):
    feature_entropies = {}
    for feature in window.columns:
        counts = window[feature].value_counts()
        probabilities = counts / len(window)
        feature_entropy = -np.sum(probabilities * np.log2(probabilities + 1e-9))
        max_entropy = np.log2(len(counts)) if len(counts) > 1 else 1
        normalized_entropy = feature_entropy / max_entropy
        feature_entropies[feature] = normalized_entropy
    total_entropy = np.mean(list(feature_entropies.values()))
    lowest_entropy_feature = min(feature_entropies, key=feature_entropies.get)
    return total_entropy, lowest_entropy_feature

def update_ewma(current_entropy, previous_theta, alpha):
    return alpha * current_entropy + (1 - alpha) * previous_theta

def calculate_initial_threshold(normal_traffic, attack_traffic):
    normal_entropies = [calculate_entropy(normal_traffic.iloc[i:i+window_size])[0] for i in range(0, len(normal_traffic), window_size)]
    attack_entropies = [calculate_entropy(attack_traffic.iloc[i:i+window_size])[0] for i in range(0, len(attack_traffic), window_size)]

    normal_mean = np.mean(normal_entropies)
    normal_ci = 1.96 * np.std(normal_entropies) / np.sqrt(len(normal_entropies))
    attack_mean = np.mean(attack_entropies)
    attack_ci = 1.96 * np.std(attack_entropies) / np.sqrt(len(attack_entropies))
    normal_threshold = normal_mean - normal_ci
    attack_threshold = attack_mean + attack_ci
    theta = (normal_threshold + attack_threshold) / 3
    print("Initial threshold", theta)
    return theta

def procedure_3(lowest_entropy_feature, feature_value_to_drop):
    attack_type = "Unknown"
    if lowest_entropy_feature in ['dst[arp]', 'src[arp]']:
        attack_type = "IP-based attack"
    elif lowest_entropy_feature == 'pkt_size':
        attack_type = "Packet size anomaly"
    elif lowest_entropy_feature == 'total_time':
        attack_type = "Timing attack"

    log_entry = {
        'attack_type': attack_type,
        'lowest_entropy_feature': lowest_entropy_feature,
        'feature_value_to_drop': feature_value_to_drop,
        'actions': ["Dropping suspicious packets"]
    }

    attack_log.append(log_entry)
    log_file.write(f"\n*** Potential attack detected! ***\nProcedure_3 executed: {log_entry}\n")

    return log_entry

def drop_packets(blacklist, row):
    for feature, values in blacklist.items():
        if row[feature].iloc[0] in values:
            if feature not in dropped_packets_info:
                dropped_packets_info[feature] = {}
            if row[feature].iloc[0] not in dropped_packets_info[feature]:
                dropped_packets_info[feature][row[feature].iloc[0]] = []
            dropped_packets_info[feature][row[feature].iloc[0]].append(row.iloc[0].to_dict())
            return True
    return False

def calculate_metrics(true_labels, predicted_labels):
    tn, fp, fn, tp = confusion_matrix(true_labels, predicted_labels).ravel()

    sensitivity = recall_score(true_labels, predicted_labels)
    specificity = tn / (tn + fp)
    precision = precision_score(true_labels, predicted_labels)
    npv = tn / (tn + fn)
    fpr = fp / (fp + tn)
    fdr = 1 - precision
    fnr = fn / (fn + tp)
    detection_rate = tp / (tp + fn)
    f1 = f1_score(true_labels, predicted_labels)

    metrics = {
        "Metric": ["Sensitivity", "Specificity", "Precision", "Negative Predictive Value", "False Positive Rate", "False Discovery Rate", "False Negative Rate", "Detection Rate", "F1 Score"],
        "Value": [sensitivity, specificity, precision, npv, fpr, fdr, fnr, detection_rate, f1]
    }

    metrics_df = pd.DataFrame(metrics)
    print(metrics_df)
    return metrics_df

# Split the data into normal and attack traffic for threshold calculation
normal_traffic = data.iloc[:1000]
attack_traffic = data.iloc[1000:]

# Calculate initial threshold
initial_threshold = calculate_initial_threshold(normal_traffic, attack_traffic)
theta = initial_threshold

# Detection process
entropy_values = []
threshold_values = []
attack_points = []
window = pd.DataFrame(columns=feature_columns)
predicted_labels = np.zeros(len(data))

packet_count = 0
for idx, row in data.iterrows():
    row = row.to_frame().T
    if drop_packets(blacklist, row):
        predicted_labels[idx] = 1
        continue
    
    window = window._append(row, ignore_index=True)
    packet_count += 1

    if packet_count >= window_size:
        H, lowest_entropy_feature = calculate_entropy(window)
        entropy_checks += 1

        theta = update_ewma(H, theta, alpha)

        entropy_values.append(H)
        threshold_values.append(theta)

        if H < theta:
            if lowest_entropy_feature == last_anomaly_feature:
                anomaly_counter += 1
            else:
                anomaly_counter = 1
                last_anomaly_feature = lowest_entropy_feature

            if anomaly_counter >= 5:
                feature_value_to_drop = window[lowest_entropy_feature].iloc[-1]
                log_entry = procedure_3(lowest_entropy_feature, feature_value_to_drop)
                attack_points.append((len(entropy_values) - 1, lowest_entropy_feature))

                if lowest_entropy_feature in ['dst[arp]', 'src[arp]']:
                    if lowest_entropy_feature not in blacklist:
                        blacklist[lowest_entropy_feature] = []
                    blacklist[lowest_entropy_feature].append(feature_value_to_drop)
                elif lowest_entropy_feature in ['pkt_size', 'total_time']:
                    src_ips = window['src[arp]'].unique()
                    if len(src_ips) == 1:
                        src_ip = src_ips[0]
                        if 'src[arp]' not in blacklist:
                            blacklist['src[arp]'] = []
                        blacklist['src[arp]'].append(src_ip)
                
                theta = initial_threshold
                anomaly_counter = 0
                last_anomaly_feature = None

                # Mark the window as attack in the predicted labels
                predicted_labels[idx-window_size+1:idx+1] = 1

        else:
            anomaly_counter = 0
            last_anomaly_feature = None

        window = pd.DataFrame(columns=feature_columns)
        packet_count = 0

# Ensure predicted_labels length matches true_labels length
predicted_labels = predicted_labels[:len(true_labels)]

# Calculate performance metrics
metrics_df = calculate_metrics(true_labels, predicted_labels)

# Log the performance metrics to the log file
log_file.write("\n*** Performance Metrics ***\n")
log_file.write(metrics_df.to_string(index=False))

# Plotting the results
plt.figure(figsize=(12, 6))
plt.plot(entropy_values, marker='o', linestyle='-', color='b', label='Entropy')
plt.plot(threshold_values, linestyle='-', color='r', label='Dynamic Threshold')

for attack, feature in attack_points:
    plt.axvline(x=attack, color='g', linestyle='--')
    plt.text(attack, entropy_values[attack], feature, color='black', fontsize=8, rotation=90, verticalalignment='top')

plt.xlabel('Window Number')
plt.ylabel('Entropy')
plt.title('Entropy Values and Dynamic Threshold Over Time')
plt.legend()
plt.grid(True)
plt.show()

# Log the blacklist and dropped packets information
log_file.write("\n*** Blacklist and Dropped Packet Counts ***\n")
for feature, values in blacklist.items():
    drop_count = len(data[data[feature].isin(values)])
    log_file.write(f"Feature: {feature}, Values: {values}, Dropped Packets: {drop_count}\n")

log_file.write("\n*** Dropped Packets Details ***\n")
for feature, feature_values in dropped_packets_info.items():
    log_file.write(f"\nFeature: {feature}\n")
    for feature_value, packets in feature_values.items():
        log_file.write(f"Feature Value: {feature_value}\n")
        log_file.write("Initial dropped packets:\n")
        for packet in packets[:3]:
            log_file.write(f"{packet}\n")
        if len(packets) > 6:
            log_file.write("...\n")
        log_file.write("Last dropped packets:\n")
        for packet in packets[-3:]:
            log_file.write(f"{packet}\n")
        log_file.write(f"Total dropped packets for {feature_value}: {len(packets)}\n")

log_file.close()
