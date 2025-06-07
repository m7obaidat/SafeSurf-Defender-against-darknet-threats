# Intrusion Prevention System (IPS)

A real-time network intrusion prevention system that uses machine learning to detect and prevent malicious network traffic.

## Features

- Real-time network traffic monitoring and analysis
- Machine learning-based traffic classification
- Multi-layer decision tree model for accurate threat detection
- Automatic traffic logging and analysis
- Whitelist/Blacklist management
- Network flow analysis and feature extraction
- PCAP to CSV conversion utility

## Prerequisites

- Python 3.13
- Linux operating system (required for netfilterqueue)
- Root/Administrator privileges (required for packet capture)

### System Dependencies

```bash
# For Ubuntu/Debian
sudo apt-get update
sudo apt-get install -y python3-dev libnetfilter-queue-dev
```

## Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd Intrusion-Prevention-System
```

2. Install Python dependencies:
```bash
pip install -r requirements.txt
```

## Project Structure

```
.
├── src/
│   ├── features/                    # Feature extraction modules
│   │   ├── context/                # Context-related features
│   │   │   ├── packet_direction.py # Packet direction handling
│   │   │   └── packet_flow_key.py  # Flow key generation
│   │   ├── flow_bytes.py          # Flow byte statistics
│   │   ├── flag_count.py          # TCP flag counting
│   │   ├── packet_count.py        # Packet counting features
│   │   ├── packet_length.py       # Packet length analysis
│   │   ├── packet_time.py         # Time-based features
│   │   └── response_time.py       # Response time analysis
│   ├── Classifier.py               # ML model classification
│   ├── flow.py                    # Network flow handling
│   ├── flow_session.py           # Flow session management
│   ├── IPS.py                    # Main IPS implementation
│   ├── logging.py                # Traffic logging
│   └── utils.py                  # Utility functions
├── decision_tree_model_layer1.pkl  # ML model layer 1
├── decision_tree_model_layer2.pkl  # ML model layer 2
├── decision_tree_model_layer3.pkl  # ML model layer 3
├── PCAP-TO-CSV.py                 # PCAP conversion utility
└── run.py                        # Main execution script
```

## Usage

### Running the IPS

1. Start the IPS with root privileges:
```bash
sudo python3 run.py
```


## Features and Capabilities

### Network Traffic Analysis
- Packet capture and analysis
- Flow-based traffic monitoring
- Real-time feature extraction
- Statistical analysis of network flows

### Machine Learning Classification
- Multi-layer decision tree model
- Real-time traffic classification
- Automatic threat detection
- Confidence-based decision making

### Traffic Management
- Automatic traffic logging
- Whitelist/Blacklist management
- Traffic filtering and blocking
- Session tracking and analysis

## Dependencies

- numpy>=1.21.0
- scipy>=1.7.0
- scapy>=2.4.5
- netfilterqueue>=1.0.0
- redis>=4.0.0
- pandas>=1.3.0
- joblib>=1.0.0
- requests>=2.26.0
- pyflowmeter>=0.1.0
- scikit-learn>=1.0.0

## Security Considerations

- The system requires root/administrator privileges to capture and analyze network traffic
- Ensure proper security measures are in place when running the system
- Regularly update the machine learning models for optimal performance
- Monitor system logs for any potential issues

