import time
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet, ipv4
from ryu.controller.handler import set_ev_cls
from ryu.controller import ofp_event

class PacketArrival(object):
    def __init__(self):
        self.flow_stats = {}  # Dictionary to store flow IDs and their previous arrival times

    @set_ev_cls(ofp_event.EventOFPPacketIn)
    def handle_packet_in(self, ev):
        msg = ev.msg
        datapath = msg.datapath

        # Extract features from the incoming packet
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        ipv4_header = pkt.get_protocol(ipv4.ipv4)

        if ipv4_header:
            # Extract relevant features
            d_ip = ipv4_header.dst
            s_ip = ipv4_header.src
            pkt_size = ipv4_header.total_length
            t_arrival = time.time()

            # Construct a flow identifier (can be customized based on your needs)
            flow_id = (d_ip, s_ip)

            # Collect features into a dictionary
            features = {
                "d_ip": d_ip,
                "s_ip": s_ip,
                "pkt_size": pkt_size,
                "flow_duration": self.calculate_flow_duration(flow_id, t_arrival)
            }

            # Print features for debugging (replace with actual processing)
            print("Features extracted:", features)

            # ... (rest of the code for flow stats request, not required for flow duration calculation)

    def calculate_flow_duration(self, flow_id, current_arrival_time):
        # Check if flow entry exists in the dictionary
        if flow_id in self.flow_stats:
            # Flow exists, calculate duration based on previous arrival time
            previous_arrival_time = self.flow_stats[flow_id]
            flow_duration = current_arrival_time - previous_arrival_time
            self.flow_stats[flow_id] = current_arrival_time  # Update for subsequent packets
            return flow_duration
        else:
            # First packet for the flow, set initial flow duration to 0 and store arrival time
            self.flow_stats[flow_id] = current_arrival_time
            return 0

# Replace "MAIN_DISPATCHER" with the appropriate dispatcher if necessary
# set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER, flow_stats_reply_handler)

