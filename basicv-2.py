import sys
import pandas as pd
import numpy as np
import math
import matplotlib.pyplot as plt

# Redirect standard output to a file
sys.stdout = open('output_data.csv', 'w')

# Read the dataset
data = pd.read_csv('destination_attack.csv')

# Extract relevant features
features = data[['dst[arp]', 'src[arp]', 'pkt_size', 'total_time']]

# Initialize variables
window_size = 50
entropy_checks = 0
packet_count = 0
consecutive_anomalies = 0
# previous_entropy = None
alpha = 0.1  # Example value for EWMA
initial_threshold = 0.7  # Example initial threshold
theta = initial_threshold

# Weight assignment for features (example values)
weights = {
    'dst[arp]': 3.80,
    'src[arp]': 0.10,
    'pkt_size': 0.05,
    'total_time': 0.05
}

entropy_values = []
threshold_values = []
attack_points = []

def calculate_entropy(window):
    feature_entropy = 0
    for feature in window.columns:
        # Calculate frequency of each unique value
        counts = window[feature].value_counts()
        probabilities = counts / len(window)
        feature_entropy += -np.sum(probabilities * np.log2(probabilities + 1e-9)) * weights[feature]
    return feature_entropy

def update_ewma(current_entropy, previous_theta, alpha):
    return alpha * current_entropy + (1 - alpha) * previous_theta 

# Simulate packet arrival
for index, row in features.iterrows():
    if packet_count % window_size == 0 and packet_count != 0:
        window = features.iloc[packet_count-window_size:packet_count]
        H = calculate_entropy(window)
        entropy_checks += 1
        
        # if previous_entropy is None:
        #     previous_entropy = H  # Initialize the previous entropy

        theta = update_ewma(H, theta, alpha)
        
        # Log the entropy value and the threshold
        entropy_values.append(H)
        threshold_values.append(theta)
        print(f"Entropy: {H}, Updated Threshold: {theta}")

        # Check for potential attack
        if H < theta:
            consecutive_anomalies += 1
            if consecutive_anomalies >= 5:
                # Call Procedure_3 (Not implemented here)
                print("Potential attack detected!")
                attack_points.append(len(entropy_values) - 1)
                consecutive_anomalies = 0
        else:
            consecutive_anomalies = 0

        # Update previous entropy
        previous_entropy = H

        # Reset window
        packet_count += 1

    else:
        packet_count += 1

# Plot the entropy values and dynamic threshold
plt.figure(figsize=(12, 6))
plt.plot(entropy_values, marker='o', linestyle='-', color='b', label='Entropy')
plt.plot(threshold_values, linestyle='-', color='r', label='Dynamic Threshold')

# Add vertical dashed lines for attack points
for attack in attack_points:
    plt.axvline(x=attack, color='g', linestyle='--', label='Attack Detected' if attack == attack_points[0] else "")

plt.xlabel('Window Number')
plt.ylabel('Entropy')
plt.title('Entropy Values and Dynamic Threshold Over Time')
plt.legend()
plt.grid(True)
plt.show()

# Close the file
sys.stdout.close()
