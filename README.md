# Wi-Fi Probe Request Fingerprinting
⚠️ **This is a work in progress**
A Python tool for analyzing and fingerprinting Wi-Fi devices based on elements on their probe request. This project examines the stability and variability of information elements within probe requests to create unique device identifiers.
This project is a implementation of the methodology described in:

> Pieter Robyns, Peter Quax, and Wim Lamotte. 2017. "Non-cooperative 802.11 MAC Layer Fingerprinting and Tracking of Mobile Devices." https://doi.org/10.1155/2017/6235484

Based on the [original implementation](https://github.com/rpp0/wifi-mac-tracking) of the paper.
The aim of this project is to create device identifiers that prevail constant over time to be used for movement analysis.

## Features
- 📊 Analyzes probe request information elements for stability and variability
- 🔍 Creates unique device fingerprints using stable and variable bits
- 📈 Generates detailed statistical analysis and visualizations

## Installation

```bash
# Clone the repository
git clone https://github.com/Eldoprano/probe_request_fingerprinting

# Install dependencies
pip install -r requirements.txt
```

## Usage
### Stability and Suitability analysis
```python
from analyzer import ProbeRequestAnalyzer

# Initialize analyzer with pcap file
analyzer = ProbeRequestAnalyzer(filename="./pcaps/capture.pcap")

# Run analysis
analyzer.load_and_analyze()
analyzer.plot_results(stability_thresholds=[0.9])
```

### Fingerprinting
```python
from scapy.all import rdpcap, Dot11ProbeReq
from analyzer import BitAnalyzer
analyzer = BitAnalyzer()

# Load the pcap file
packets = rdpcap('pcaps/chamber.pcap')

# Loop through each packet
for packet in tqdm(packets):
    # Check if the packet is a ProbeRequest
    if packet.haslayer(Dot11ProbeReq):
        # Get the identifier from the packet
        identifier = analyzer.get_id(packet)
        print(f'Identifier: {identifier}')
```