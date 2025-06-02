import time
from threading import Thread, Lock
import csv
import requests
from scapy.sessions import DefaultSession
from .features.context.packet_direction import PacketDirection
from .features.context.packet_flow_key import get_packet_flow_key
from .flow import Flow


EXPIRED_UPDATE = 40
SENDING_INTERVAL = 1

class FlowSession(DefaultSession):
    """Creates a list of network flows."""
    
    def __init__(self, *args, **kwargs):
        self.flows = {}
        self.csv_line = 0
        self.packets_count = 0
        self.GARBAGE_COLLECT_PACKETS = 10000
        self.last_flow = None  # Variable to hold the last created or modified flow

        self.lock = Lock() 

        if self.to_csv:
            output = open(self.output_file, "w", newline="")
            self.csv_writer = csv.writer(output)
            self.csv_line = 0

        super(FlowSession, self).__init__(*args, **kwargs)

    def toPacketList(self):
        """Finalize packets when sniffer finishes."""
        self.garbage_collect()
        return super(FlowSession, self).toPacketList()

    def on_packet_received(self, packet):
        """Process packet and update the flow."""
        direction = PacketDirection.FORWARD
        count = 0

        try:
            # Get flow key for the packet
            packet_flow_key = get_packet_flow_key(packet, direction)
            flow = self.flows.get((packet_flow_key, count))
        except Exception as e:
            print(f"Error processing packet: {e}")
            return None  # Return None if there was an error processing the packet

        self.packets_count += 1
        if self.verbose:
            print(f'New packet received. Count: {self.packets_count}')

        # If no flow exists for the packet
        if flow is None:
            direction = PacketDirection.REVERSE
            packet_flow_key = get_packet_flow_key(packet, direction)
            flow = self.flows.get((packet_flow_key, count))

        if flow is None:
            # Create a new flow if none exists
            direction = PacketDirection.FORWARD
            flow = Flow(packet, direction)
            packet_flow_key = get_packet_flow_key(packet, direction)
            with self.lock:
                self.flows[(packet_flow_key, count)] = flow
                self.last_flow = flow  # Update the last flow when a new flow is created

        elif (packet.time - flow.latest_timestamp) > EXPIRED_UPDATE:
            # If the flow has expired, create a new one
            expired = EXPIRED_UPDATE
            while (packet.time - flow.latest_timestamp) > expired:
                count += 1
                expired += EXPIRED_UPDATE
                flow = self.flows.get((packet_flow_key, count))

                if flow is None:
                    flow = Flow(packet, direction)
                    with self.lock:
                        self.flows[(packet_flow_key, count)] = flow
                        self.last_flow = flow  # Update the last flow when a new flow is created
                    break

        elif "F" in str(packet.flags):  # FIN flag processing
            flow.add_packet(packet, direction)
            self.last_flow = flow  # Update the last flow after processing FIN packet
            return self.last_flow

        flow.add_packet(packet, direction)
        self.last_flow = flow  # Update the last flow after processing the packet

        if self.packets_count % self.GARBAGE_COLLECT_PACKETS == 0 or flow.duration > 120:
            self.garbage_collect()

        return self.last_flow  # Return the most recent flow

    def get_last_flow(self):
        """Return the most recently created or modified flow."""
        return self.last_flow

    def get_flows(self) -> list:
        """Return the current list of flows."""
        return list(self.flows.values())

    def write_data_csv(self):
        """Write flow data to CSV."""
        with self.lock:
            flows = list(self.flows.values())
        for flow in flows:
            data = flow.get_data()

            if self.csv_line == 0:
                self.csv_writer.writerow(data.keys())

            self.csv_writer.writerow(data.values())
            self.csv_line += 1

    def garbage_collect(self):
        """Clean up expired flows and write data to CSV if required."""
        if self.to_csv:
            self.write_data_csv()
        with self.lock:
            # Remove expired flows
            self.flows = {}
            #print("Flows Removed")


def generate_session_class(verbose, to_csv, output_file):
    """Dynamically generate a FlowSession class with specific parameters."""
    return type(
        "NewFlowSession",
        (FlowSession,),
        {
            "verbose": verbose,
            "to_csv": to_csv,
            "output_file": output_file,
        },
    )

