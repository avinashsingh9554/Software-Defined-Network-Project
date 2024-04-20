import time
from random import randint
from packet_arrival import PacketArrival

class PacketGenerator:
    def __init__(self, network):
        self.net = network
        self.host_ips = [h.IP() for h in self.net.hosts]  # Get IPs of hosts from the list

    def generate_packet(self):
        d_ip = self.host_ips[randint(0, len(self.host_ips) - 1)]  # Random destination IP
        s_ip = self.host_ips[randint(0, len(self.host_ips) - 1)]  # Random source IP
        pkt_size = randint(64, 1500)  # Random packet size between 64 and 1500 bytes
        arrival_time = time.time()  # Current time as arrival time

        return {
            'd_ip': d_ip,
            's_ip': s_ip,
            'pkt_size': pkt_size,
            'flow_duration': 0  # Initially 0, can be updated based on arrival time
        }

    def start_generating_packets(self):
        # Generate packets at a specific rate (adjust as needed)
        while True:
            packet = self.generate_packet()
            # Call PacketArrival procedure (assuming it's in a separate object/function)
            packet_arrival = PacketArrival(packet)  # Create PacketArrival object with the packet
            packet_arrival.process_packet()  # Call the process_packet function
            time.sleep(0.01)  # Generate packets every 10 milliseconds (adjust rate)

