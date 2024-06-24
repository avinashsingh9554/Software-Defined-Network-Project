import sys
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt

# Redirect standard output to a file
sys.stdout = open('output_data.csv', 'w')

# Read the dataset
data = pd.read_csv('generated_traffic.csv')

# Extract relevant features
features = data[['dst[arp]', 'src[arp]', 'pkt_size', 'total_time']]

# Initialize variables
window_size = 50
entropy_checks = 0
packet_count = 0
consecutive_anomalies = 0
alpha = 0.1  # Example value for EWMA

# Calculate initial threshold based on normal and attack traffic analysis
normal_traffic = features.iloc[:1000]  # Assuming first 1000 packets are normal
attack_traffic = features.iloc[1000:2000]  # Assuming packets from 1000 to 2000 are attack

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

    theta = (normal_threshold + attack_threshold) / 3.5

    return theta

initial_threshold = calculate_initial_threshold(normal_traffic, attack_traffic)
theta = initial_threshold

entropy_values = []
threshold_values = []
attack_points = []
lowest_entropy_features = []

# Simulate packet arrival
for index, row in features.iterrows():
    if packet_count % window_size == 0 and packet_count != 0:
        window = features.iloc[packet_count - window_size:packet_count]
        H, lowest_entropy_feature = calculate_entropy(window)
        entropy_checks += 1

        theta = update_ewma(H, theta, alpha)

        # Log the entropy value, threshold, and feature with the lowest entropy
        entropy_values.append(H)
        threshold_values.append(theta)
        print(f"Entropy: {H}, Updated Threshold: {theta}, Lowest Entropy Feature: {lowest_entropy_feature}")

        # Check for potential attack
        if H < theta:
            consecutive_anomalies += 1
            if consecutive_anomalies >= 5:
                # Call Procedure_3 (Not implemented here)
                print("Potential attack detected!")
                attack_points.append((len(entropy_values) - 1, lowest_entropy_feature))
                lowest_entropy_features.append(lowest_entropy_feature)
                consecutive_anomalies = 0
        else:
            consecutive_anomalies = 0

        # Reset window
        packet_count += 1
    else:
        packet_count += 1

# Plot the entropy values and dynamic threshold
plt.figure(figsize=(12, 6))
plt.plot(entropy_values, marker='o', linestyle='-', color='b', label='Entropy')
plt.plot(threshold_values, linestyle='-', color='r', label='Dynamic Threshold')

# Add vertical dashed lines for attack points and annotate with the lowest entropy feature
for attack, feature in attack_points:
    plt.axvline(x=attack, color='g', linestyle='--')
    plt.text(attack, entropy_values[attack], feature, color='black', fontsize=8, rotation=90, verticalalignment='bottom')

plt.xlabel('Window Number')
plt.ylabel('Entropy')
plt.title('Entropy Values and Dynamic Threshold Over Time')
plt.legend()
plt.grid(True)
plt.show()

# Close the file
sys.stdout.close()
