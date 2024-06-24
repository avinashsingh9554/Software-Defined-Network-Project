import pandas as pd
import numpy as np
import random
import string

# Function to generate random MAC address
def random_mac():
    return "00:00:00:%02x:%02x:%02x" % (np.random.randint(0, 255), np.random.randint(0, 255), np.random.randint(0, 255))

# Function to generate random IP address
def random_ip():
    return "10.0.0.%d" % np.random.randint(1, 255)

# Define the attributes for the dataset
columns = [
    'switch', 'inport', 'outport', 'src[eth]', 'src_mac_addr(arp)', 'dst[eth]', 
    'dst_mac_addr(arp)', 'src[arp]', 'dst[arp]', 'opcode', 'packet_in_count', 
    'Protocol', 'Pkt loss', 'rtt (avg)', 'total_time', 'label', 'pkt_size'
]

# Generate random data for 5000 entries
num_entries = 5000
data = []

for i in range(num_entries):
    is_attack = i < 4000  # 80% of the entries are attack packets
    entry = [
        np.random.randint(1, 10),  # switch
        np.random.randint(1, 10),  # inport
        4294967291,                # outport (fixed value)
        random_mac(),              # src[eth] (random value)
        random_mac(),              # src_mac_addr(arp) (random value)
        'ff:ff:ff:ff:ff:ff',       # dst[eth] (fixed value)
        random_mac(),              # dst_mac_addr(arp) (random value)
        random_ip(),               # src[arp] (random value)
        '10.0.0.12' if is_attack else random_ip(),  # dst[arp] (fixed for attacks, random for normal)
        np.random.randint(1, 3),   # opcode
        1707 + i,                  # packet_in_count (incrementing value)
        np.random.randint(0, 3),   # Protocol
        np.random.randint(0, 10),  # Pkt loss
        np.random.randint(0, 100), # rtt (avg)
        np.random.randint(100000, 400000),  # total_time
        1 if is_attack else 0,     # label (1 for attack, 0 for normal)
        np.random.randint(500, 1500) # pkt_size
    ]
    data.append(entry)

# Create a DataFrame
df = pd.DataFrame(data, columns=columns)

# Save to a CSV file
df.to_csv('destination_attack.csv', index=False)

print("Dataset generated and saved to 'custom_sdn_flow_packets.csv'")
