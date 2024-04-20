import collections
import math

# Function to calculate Shannon entropy using feature probabilities
def calculate_entropy(window):
    feature_counts = {}
    for feature_set in window:
        for feature in feature_set:
            feature_counts[feature] = feature_counts.get(feature, 0) + 1

    total_entries = len(window)
    entropy = 0
    for count in feature_counts.values():
        probability = count / total_entries
        if probability > 0:  # Avoid log(0)
            entropy -= probability * math.log2(probability)
    return entropy

# Function to apply EWMA with a smoothing factor for threshold calculation
def update_threshold(theta, entropy, alpha):
    new_theta = alpha * entropy + (1 - alpha) * theta
    return new_theta

class WindowManager:
    def __init__(self, window_size):
        self.window_size = window_size
        self.window = collections.deque(maxlen=window_size)

        # Feature weights (adjust based on your attack signatures)
        self.weights = {
            'd_ip': 0.3,  # Weight for destination IP
            's_ip': 0.2,  # Weight for source IP
            'pkt_size': 0.25,  # Weight for packet size
            'flow_duration': 0.25  # Weight for flow duration
        }

        self.theta = 0.5  # Initial threshold (between 0 and 1)
        self.alpha = 0.1  # EWMA smoothing factor (between 0 and 1)

    def process_packet(self, features):
        if len(self.window) == self.window_size:
            # Window is full
            entropy = calculate_entropy(self.window)
            self.theta = update_threshold(self.theta, entropy, self.alpha)

            if entropy >= self.theta:
                # Potential flow table overload attack detected
                self.handle_attack(features)
            else:
                # No attack detected
                self.window.popleft()
                self.decay_weights()

        self.window.append(features)

    # Function to decay weights of remaining entries in the window
    def decay_weights(self):
        decay_factor = 0.9  # Adjust decay factor (between 0 and 1)
        for feature, weight in self.weights.items():
            self.weights[feature] = weight * decay_factor

    def handle_attack(self, features):
        # Implement specific attack response, analysis, and classification here
        print(f"Potential Flow Table Overload Attack Detected: {features}")
        # You can extend this function to trigger rate limiting, packet dropping,
        # notifications, or update attack classifier models based on your strategy.

