import numpy as np
from collections import defaultdict
import matplotlib.pyplot as plt
from typing import Dict, List
from tqdm import tqdm
from scapy.all import PcapReader, Dot11Elt
import plotting
from bitarray import bitarray
import pandas as pd
import hashlib

# My library
from analyzer import ProbeRequestAnalyzer, BitAnalyzer

FILENAME = "./pcaps/rand_1000.pcap"
PLOT_STABILITY_THRESHOLDS = [0.9]
EXPERIMENT_STABILITY_THRESHOLDS = [0.85]
EXPERIMENT_SUITABILITY_THRESHOLDS = [0.4]
NUM_SAMPLES = 69700 # Only used for progress bar

analyzer = ProbeRequestAnalyzer(filename=FILENAME, num_samples=NUM_SAMPLES)

def plot_experiment_results(total_devices, unique_identifiers, stable_devices, unique_identifiers_count,
            stability_threshold, suitability_threshold):
    """Generate bar chart for experiment results."""
    metrics = ['Total Devices', 'Unique Identifiers', 'Devices with only 1 identifier', 'Identifiers with only 1 device']
    values = [total_devices, unique_identifiers, stable_devices, unique_identifiers_count]
    percentages = [100, (unique_identifiers / total_devices) * 100, (stable_devices / total_devices) * 100, (unique_identifiers_count / unique_identifiers) * 100]
    
    plt.figure(figsize=(10, 6))
    plt.bar(metrics, percentages, color=['blue', 'green', 'orange', 'red'])
    plt.title(f"Identification Experiment Results\n"
        f"Stability Threshold={stability_threshold}, Suitability Threshold={suitability_threshold}")
    plt.xlabel("Metrics")
    plt.ylabel("Percentages (%)")
    
    # Display percentages on top of bars
    for i, v in enumerate(percentages):
        plt.text(i, v + 0.5, f"{v:.1f}%", ha='center', fontweight='bold')
    
    plt.tight_layout()
    plt.show()

    # Save the plot
    base_filename = analyzer.filename.split('/')[-1].split('.')[0]
    plt.savefig(f"./outputs/fingerprint_{base_filename}_sta{stability_threshold}_sui{suitability_threshold}.png")

def experiment_with_identification(stability_threshold: float = 0.95, suitability_threshold: float = 0.9):
    """Run experiment with detailed analysis of identification patterns."""
    print(f"\nRunning detailed identification experiment with stability={stability_threshold}, suitability={suitability_threshold}")
    
    # Calculate suitability and create masks
    bit_analyzer = BitAnalyzer()
    suitability_data = bit_analyzer.calculate_suitability(stability_threshold)
    masks = bit_analyzer.create_masks(suitability_data, suitability_threshold)

    # print mask so that it can be copied and used in another script
    print(masks)
    
    # Enhanced tracking structures
    mac_to_identifier_counts = defaultdict(lambda: defaultdict(int))  # MAC -> {identifier: count}
    identifier_to_mac_counts = defaultdict(lambda: defaultdict(int))  # identifier -> {MAC: count}
    total_packets_per_mac = defaultdict(int)  # MAC -> total_packets
    
    # Process packets
    with PcapReader(analyzer.filename) as pcap_reader:
        for packet in tqdm(pcap_reader, desc="Testing identification", unit="frames", total=analyzer.num_samples):
            if not packet.haslayer(Dot11Elt):
                continue
                
            mac_addr = packet.addr2
            if mac_addr is None:
                continue
                
            identifier = bit_analyzer.extract_identifier(packet, masks)
            mac_to_identifier_counts[mac_addr][identifier] += 1
            identifier_to_mac_counts[identifier][mac_addr] += 1
            total_packets_per_mac[mac_addr] += 1
    
    # Create analysis tables
    mac_analysis = []
    for mac, id_counts in mac_to_identifier_counts.items():
        mac_short = mac[-5:]  # Last two hex values
        total_packets = total_packets_per_mac[mac]
        for identifier, count in id_counts.items():
            identifier_hash = hashlib.md5(identifier.encode()).hexdigest()[-4:]  # Last 4 hex values of the hash
            percentage = (count / total_packets) * 100
            mac_analysis.append({
                'MAC': mac_short,
                'Identifier': identifier_hash.upper(),
                'Occurrences': count,
                'Total_Packets': total_packets,
                'Percentage': f'{percentage:.1f}%'
            })
    
    identifier_analysis = []
    for idx, (identifier, mac_counts) in enumerate(identifier_to_mac_counts.items()):
        total_occurrences = sum(mac_counts.values())
        identifier_hash = hashlib.md5(identifier.encode()).hexdigest()[-4:]  # Last 4 hex values of the hash
        for mac, count in mac_counts.items():
            mac_short = mac[-5:]
            percentage = (count / total_occurrences) * 100
            identifier_analysis.append({
                'Identifier': identifier_hash.upper(),
                'MAC': mac_short,
                'Occurrences': count,
                'Total_Occurrences': total_occurrences,
                'Percentage': f'{percentage:.1f}%'
            })
    
    # Convert to DataFrames for better display
    mac_df = pd.DataFrame(mac_analysis)
    identifier_df = pd.DataFrame(identifier_analysis)
    
    # Filter identifiers out rare cases that appear less than 10% of the time
    total_devices = len(mac_to_identifier_counts)
    significant_identifiers = {id for id, mac_counts in identifier_to_mac_counts.items() 
                                if any(count/total_packets_per_mac[mac] >= 0.1 for mac, count in mac_counts.items())}
    unique_identifiers = len(significant_identifiers)
    stable_devices = sum(1 for mac, id_counts in mac_to_identifier_counts.items() 
                        if max(id_counts.values()) / total_packets_per_mac[mac] >= 0.9)
    unique_identifiers_count = sum(1 for id, mac_counts in identifier_to_mac_counts.items() 
                                    if len(mac_counts) == 1 and next(iter(mac_counts.values())) / total_packets_per_mac[next(iter(mac_counts.keys()))] >= 0.1)
    
    # Print summary statistics
    print("\n=== Summary Statistics ===")
    print(f"📱 Total devices: {total_devices}")
    print(f"🔑 Unique identifiers generated: {unique_identifiers}")
    print(f"🙂 Devices with stable identifier: {stable_devices} ({stable_devices/total_devices:.2%})")
    print(f"😥 Devices with multiple identifiers: {total_devices - stable_devices} ({(total_devices - stable_devices)/total_devices:.2%})")
    print(f"🙂 Identifiers matching unique device: {unique_identifiers_count} ({unique_identifiers_count/unique_identifiers:.2%})")
    print(f"😥 Identifiers matching multiple devices: {unique_identifiers - unique_identifiers_count} ({(unique_identifiers - unique_identifiers_count)/unique_identifiers:.2%})")
    
    print("\n=== MAC Address Analysis ===")
    print("Shows how many times each identifier was seen for each MAC address:")
    print(mac_df.to_string(index=False))
    
    print("\n=== Identifier Analysis ===")
    print("Shows how many times each MAC address was seen for each identifier:")
    print(identifier_df.to_string(index=False))
    
    # Plot results
    plot_experiment_results(
        total_devices, unique_identifiers, stable_devices, unique_identifiers_count,
        stability_threshold, suitability_threshold
    )
    
    return mac_to_identifier_counts, identifier_to_mac_counts


if __name__ == "__main__":
    analyzer.load_and_analyze()
    analyzer.plot_results(stability_thresholds=PLOT_STABILITY_THRESHOLDS)
    
    # Run identification experiments with different thresholds
    for stability in EXPERIMENT_STABILITY_THRESHOLDS:
        for suitability in EXPERIMENT_SUITABILITY_THRESHOLDS:
            print(f"\nRunning experiment with stability={stability}, suitability={suitability}")
            experiment_with_identification(
                stability_threshold=stability,
                suitability_threshold=suitability
            )