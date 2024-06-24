import csv
import random

# Function to generate a random MAC address
def random_mac():
    return "00:" + ":".join(["%02x" % random.randint(0, 255) for _ in range(5)])

# Function to generate a random IP address
def random_ip():
    return "10.0.0." + str(random.randint(1, 255))

# Function to generate normal traffic
def generate_normal_traffic(num_packets):
    packets = []
    for i in range(num_packets):
        packet = [
            random.randint(1, 10),  # switch
            random.randint(1, 10),  # inport
            4294967291,             # outport
            random_mac(),           # src[eth]
            random_mac(),           # src_mac_addr(arp)
            "ff:ff:ff:ff:ff:ff",    # dst[eth]
            random_mac(),           # dst_mac_addr(arp)
            random_ip(),            # src[arp]
            random_ip(),            # dst[arp]
            random.randint(1, 2),   # opcode
            random.randint(1000, 2000), # packet_in_count
            random.randint(0, 2),   # Protocol
            random.randint(0, 10),  # Pkt loss
            random.randint(1, 100), # rtt (avg)
            random.randint(100000, 300000), # total_time
            1,                      # label (normal traffic)
            random.randint(500, 1500) # pkt_size
        ]
        packets.append(packet)
    return packets

# Function to generate attack traffic with same destination IP
def generate_attack_traffic_same_dst_ip(num_packets):
    packets = []
    attack_dst_ip = random_ip()
    for i in range(num_packets):
        packet = [
            random.randint(1, 10),  # switch
            random.randint(1, 10),  # inport
            4294967291,             # outport
            random_mac(),           # src[eth]
            random_mac(),           # src_mac_addr(arp)
            "ff:ff:ff:ff:ff:ff",    # dst[eth]
            random_mac(),           # dst_mac_addr(arp)
            random_ip(),            # src[arp]
            attack_dst_ip,          # dst[arp]
            random.randint(1, 2),   # opcode
            random.randint(1000, 2000), # packet_in_count
            random.randint(0, 2),   # Protocol
            random.randint(0, 10),  # Pkt loss
            random.randint(1, 100), # rtt (avg)
            random.randint(100000, 300000), # total_time
            0,                      # label (attack traffic)
            random.randint(500, 1500) # pkt_size
        ]
        packets.append(packet)
    return packets

# Function to generate attack traffic with same source IP
def generate_attack_traffic_same_src_ip(num_packets):
    packets = []
    attack_src_ip = random_ip()
    for i in range(num_packets):
        packet = [
            random.randint(1, 10),  # switch
            random.randint(1, 10),  # inport
            4294967291,             # outport
            random_mac(),           # src[eth]
            random_mac(),           # src_mac_addr(arp)
            "ff:ff:ff:ff:ff:ff",    # dst[eth]
            random_mac(),           # dst_mac_addr(arp)
            attack_src_ip,          # src[arp]
            random_ip(),            # dst[arp]
            random.randint(1, 2),   # opcode
            random.randint(1000, 2000), # packet_in_count
            random.randint(0, 2),   # Protocol
            random.randint(0, 10),  # Pkt loss
            random.randint(1, 100), # rtt (avg)
            random.randint(100000, 300000), # total_time
            0,                      # label (attack traffic)
            random.randint(500, 1500) # pkt_size
        ]
        packets.append(packet)
    return packets

# Function to generate attack traffic with same packet size
def generate_attack_traffic_same_pkt_size(num_packets):
    packets = []
    attack_pkt_size = random.randint(500, 1500)
    for i in range(num_packets):
        src_ip = random_ip() if i >= num_packets / 2 else "10.0.0.1"  # half random, half same
        packet = [
            random.randint(1, 10),  # switch
            random.randint(1, 10),  # inport
            4294967291,             # outport
            random_mac(),           # src[eth]
            random_mac(),           # src_mac_addr(arp)
            "ff:ff:ff:ff:ff:ff",    # dst[eth]
            random_mac(),           # dst_mac_addr(arp)
            src_ip,                 # src[arp]
            random_ip(),            # dst[arp]
            random.randint(1, 2),   # opcode
            random.randint(1000, 2000), # packet_in_count
            random.randint(0, 2),   # Protocol
            random.randint(0, 10),  # Pkt loss
            random.randint(1, 100), # rtt (avg)
            random.randint(100000, 300000), # total_time
            0,                      # label (attack traffic)
            attack_pkt_size         # pkt_size
        ]
        packets.append(packet)
    return packets

# Function to generate attack traffic with same flow duration
def generate_attack_traffic_same_flow_time(num_packets):
    packets = []
    attack_flow_time = random.randint(100000, 300000)
    for i in range(num_packets):
        src_ip = random_ip() if i >= num_packets / 2 else "10.0.0.1"  # half random, half same
        packet = [
            random.randint(1, 10),  # switch
            random.randint(1, 10),  # inport
            4294967291,             # outport
            random_mac(),           # src[eth]
            random_mac(),           # src_mac_addr(arp)
            "ff:ff:ff:ff:ff:ff",    # dst[eth]
            random_mac(),           # dst_mac_addr(arp)
            src_ip,                 # src[arp]
            random_ip(),            # dst[arp]
            random.randint(1, 2),   # opcode
            random.randint(1000, 2000), # packet_in_count
            random.randint(0, 2),   # Protocol
            random.randint(0, 10),  # Pkt loss
            random.randint(1, 100), # rtt (avg)
            attack_flow_time,       # total_time
            0,                      # label (attack traffic)
            random.randint(500, 1500) # pkt_size
        ]
        packets.append(packet)
    return packets

# Generate normal and attack traffic
normal_traffic = generate_normal_traffic(1000)
attack_traffic_same_dst_ip = generate_attack_traffic_same_dst_ip(1000)
attack_traffic_same_src_ip = generate_attack_traffic_same_src_ip(1000)
attack_traffic_same_pkt_size = generate_attack_traffic_same_pkt_size(1000)
attack_traffic_same_flow_time = generate_attack_traffic_same_flow_time(1000)

# Combine all traffic
all_traffic = (normal_traffic + attack_traffic_same_dst_ip + 
               attack_traffic_same_src_ip + attack_traffic_same_pkt_size + 
               attack_traffic_same_flow_time)

# Define CSV headers
headers = [
    "switch", "inport", "outport", "src[eth]", "src_mac_addr(arp)", "dst[eth]",
    "dst_mac_addr(arp)", "src[arp]", "dst[arp]", "opcode", "packet_in_count",
    "Protocol", "Pkt loss", "rtt (avg)", "total_time", "label", "pkt_size"
]

# Write to CSV file
with open("generated_traffic.csv", "w", newline='') as csvfile:
    writer = csv.writer(csvfile)
    writer.writerow(headers)
    writer.writerows(all_traffic)

print("CSV file generated successfully!")
