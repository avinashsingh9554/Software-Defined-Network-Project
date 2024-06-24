import sys
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt

# Read the dataset line by line
dataset_path = 'generated_traffic.csv'

# Extract relevant features
feature_columns = ['dst[arp]', 'src[arp]', 'pkt_size', 'total_time']

# Initialize variables
window_size = 50
entropy_checks = 0
consecutive_anomalies = 0
alpha = 0.1  # Example value for EWMA
initial_threshold = None
attack_log = []
drop_indices = []
blacklist = {}
anomaly_counter = 0
last_anomaly_feature = None

# Redirect standard output to a file for logging
log_file = open('output_data.csv', 'w')

# Calculate initial threshold based on normal and attack traffic analysis
data = pd.read_csv(dataset_path)
normal_traffic = data.iloc[:1000][feature_columns]  # Assuming first 1000 packets are normal
attack_traffic = data.iloc[1000:2000][feature_columns]  # Assuming packets from 1000 to 2000 are attack

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

    theta = (normal_threshold + attack_threshold) / 2

    return theta

def procedure_3(lowest_entropy_feature, feature_value_to_drop):
    # Analyze additional features for insights
    attack_type = "Unknown"
    if lowest_entropy_feature in ['dst[arp]', 'src[arp]']:
        attack_type = "IP-based attack"
    elif lowest_entropy_feature == 'pkt_size':
        attack_type = "Packet size anomaly"
    elif lowest_entropy_feature == 'total_time':
        attack_type = "Timing attack"

    # Log attack details
    log_entry = {
        'attack_type': attack_type,
        'lowest_entropy_feature': lowest_entropy_feature,
        'feature_value_to_drop': feature_value_to_drop,
        'actions': []
    }

    # Trigger appropriate response mechanisms
    log_entry['actions'].append("Rate limiting applied")
    log_entry['actions'].append("Dropping suspicious packets")
    log_entry['actions'].append("Notifying administrators")
    log_entry['actions'].append("Updating attack classifier model")

    attack_log.append(log_entry)
    log_file.write(f"\n*** Potential attack detected! ***\nProcedure_3 executed: {log_entry}\n")

    return log_entry

def drop_packets(blacklist, row):
    for feature, values in blacklist.items():
        if row[feature].iloc[0] in values:
            return True
    return False

initial_threshold = calculate_initial_threshold(normal_traffic, attack_traffic)
theta = initial_threshold

entropy_values = []
threshold_values = []
attack_points = []
window = pd.DataFrame(columns=feature_columns)

# Simulate packet arrival
with open(dataset_path, 'r') as file:
    reader = pd.read_csv(file, chunksize=1, iterator=True)
    packet_count = 0

    for row in reader:
        row = row[feature_columns]
        if drop_packets(blacklist, row):
            log_file.write(f"Dropped packet with feature(s) in blacklist: {row.iloc[0].to_dict()}\n")
            continue
        
        window = window._append(row, ignore_index=True)
        packet_count += 1

        if packet_count >= window_size:
            H, lowest_entropy_feature = calculate_entropy(window)
            entropy_checks += 1

            # Update EWMA for threshold
            theta = update_ewma(H, theta, alpha)

            # Log the entropy value, threshold, and feature with the lowest entropy
            entropy_values.append(H)
            threshold_values.append(theta)
            log_file.write(f"Entropy: {H}, Updated Threshold: {theta}, Lowest Entropy Feature: {lowest_entropy_feature}\n")

            # Check for potential attack
            if H < theta:
                if lowest_entropy_feature == last_anomaly_feature:
                    anomaly_counter += 1
                else:
                    anomaly_counter = 1
                    last_anomaly_feature = lowest_entropy_feature

                if anomaly_counter >= 5:
                    feature_value_to_drop = window[lowest_entropy_feature].iloc[-1]
                    
                    # Log last 5 entropy points before the attack
                    log_file.write("Last 5 entropy points before attack:\n")
                    for entropy in entropy_values[-5:]:
                        log_file.write(f"{entropy}\n")

                    log_file.write("Potential attack detected!\n")
                    log_entry = procedure_3(lowest_entropy_feature, feature_value_to_drop)

                    attack_points.append((len(entropy_values) - 1, lowest_entropy_feature))

                    # Add feature to blacklist based on specific conditions
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
                    
                    # Reset threshold to initial value
                    theta = initial_threshold
                    log_file.write("Threshold reset to initial value.\n")

                    # Reset counters
                    anomaly_counter = 0
                    last_anomaly_feature = None

            else:
                anomaly_counter = 0
                last_anomaly_feature = None

            # Reset window
            window = pd.DataFrame(columns=feature_columns)
            packet_count = 0

# Plot the entropy values and dynamic threshold
plt.figure(figsize=(12, 6))
plt.plot(entropy_values, marker='o', linestyle='-', color='b', label='Entropy')
plt.plot(threshold_values, linestyle='-', color='r', label='Dynamic Threshold')

# Add vertical dashed lines for attack points and annotate with the lowest entropy feature
for attack, feature in attack_points:
    plt.axvline(x=attack, color='g', linestyle='--')
    plt.text(attack, entropy_values[attack], feature, color='black', fontsize=8, rotation=90, verticalalignment='top')

plt.xlabel('Window Number')
plt.ylabel('Entropy')
plt.title('Entropy Values and Dynamic Threshold Over Time')
plt.legend()
plt.grid(True)
plt.show()

# Log the blacklist and dropped packet counts
log_file.write("\n*** Blacklist and Dropped Packet Counts ***\n")
for feature, values in blacklist.items():
    drop_count = len(data[data[feature].isin(values)])
    log_file.write(f"Feature: {feature}, Values: {values}, Dropped Packets: {drop_count}\n")

# Close the log file
log_file.close()
