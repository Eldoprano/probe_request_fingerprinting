import numpy as np
from collections import defaultdict
from typing import Dict, List, Set
from tqdm import tqdm
from scapy.all import rdpcap, Dot11Elt
import plotting

class BitAnalyzer:
    def __init__(self, max_bits_per_elt: int = 1024):
        self.max_bits_per_elt = max_bits_per_elt
        # Store data as numpy arrays for better performance
        self.data: Dict[int, Dict[str, List[str]]] = defaultdict(lambda: defaultdict(list))
        
    def add_bits(self, elt_id: int, mac_addr: str, bit_data: str) -> None:
        """Store bits for a given element ID and MAC address."""
        # Pad or truncate bit_data to max_bits_per_elt
        bit_data = bit_data[:self.max_bits_per_elt].ljust(self.max_bits_per_elt, 'U')
        self.data[elt_id][mac_addr].append(bit_data)

    def calculate_variability(self) -> Dict[int, np.ndarray]:
        """
        Calculate variability (entropy) across different devices for each bit position.
        Uses base-3 logarithm as specified in the paper for tristate bits (0, 1, U).
        """
        variability_data = {}
        
        for elt_id, mac_bits in self.data.items():
            # Get one frame per device to prevent bias from talkative devices
            device_bits = [bits[0] for bits in mac_bits.values()]
            
            # Calculate entropy for each bit position
            variability_row = np.zeros(self.max_bits_per_elt)
            for bit_idx in range(self.max_bits_per_elt):
                bit_values = [bits[bit_idx] for bits in device_bits]
                # Count occurrences of each possible value (0, 1, U)
                counts = {'0': 0, '1': 0, 'U': 0}
                for val in bit_values:
                    counts[val] += 1
                
                # Calculate probabilities and entropy
                total = len(bit_values)
                entropy = 0
                for count in counts.values():
                    if count > 0:
                        p = count / total
                        entropy -= p * np.log(p) / np.log(3)  # Use base-3 logarithm
                
                variability_row[bit_idx] = entropy
                
            variability_data[elt_id] = variability_row
            
        return variability_data

    def calculate_stability(self) -> Dict[int, np.ndarray]:
        """
        Calculate stability (1 - entropy) for each device's bits over multiple frames.
        """
        stability_data = {}
        
        for elt_id, mac_bits in self.data.items():
            # Calculate stability per device
            device_stabilities = []
            
            for mac_addr, frames in mac_bits.items():
                stability_row = np.zeros(self.max_bits_per_elt)
                
                for bit_idx in range(self.max_bits_per_elt):
                    bit_values = [frame[bit_idx] for frame in frames]
                    # Count occurrences of each possible value (0, 1, U)
                    counts = {'0': 0, '1': 0, 'U': 0}
                    for val in bit_values:
                        counts[val] += 1
                    
                    # Calculate entropy
                    total = len(bit_values)
                    entropy = 0
                    for count in counts.values():
                        if count > 0:
                            p = count / total
                            entropy -= p * np.log(p) / np.log(3)
                    
                    # Stability is 1 - entropy
                    stability_row[bit_idx] = 1 - entropy
                
                device_stabilities.append(stability_row)
            
            # Average stability across all devices
            stability_data[elt_id] = np.mean(device_stabilities, axis=0)
            
        return stability_data

    def calculate_suitability(self, stability_threshold: float = None) -> Dict[int, np.ndarray]:
        """
        Calculate suitability using either probabilistic or filtering approach.
        Args:
            stability_threshold: If provided, uses filtering approach with this threshold.
                               If None, uses probabilistic approach.
        """
        variability = self.calculate_variability()
        stability = self.calculate_stability()
        suitability_data = {}
        
        for elt_id in variability.keys():
            if stability_threshold is None:
                # Probabilistic approach: multiply variability and stability
                suitability_data[elt_id] = variability[elt_id] * stability[elt_id]
            else:
                # Filtering approach: use variability where stability >= threshold
                mask = stability[elt_id] >= stability_threshold
                suitability = np.zeros_like(variability[elt_id])
                suitability[mask] = variability[elt_id][mask]
                suitability_data[elt_id] = suitability
                
        return suitability_data

class ProbeRequestAnalyzer:
    def __init__(self, filename: str, num_samples: int):
        self.filename = filename
        self.num_samples = num_samples
        self.records = []
        self.bit_analyzer = BitAnalyzer()
        self.ORDER_IE_ID = 255  # Using 255 as our special IE ID for order

    def load_pcap(self):
        self.records = rdpcap(self.filename)[:self.num_samples]
        print(f"Loaded {len(self.records)} packets from {self.filename}")

    def analyze_packets(self):
        unique_macs: Set[str] = set()
        
        for packet in tqdm(self.records, desc="Analyzing packets"):
            if not packet.haslayer(Dot11Elt):
                continue
            
            mac_addr = packet.addr2
            if mac_addr is None:
                continue
                
            unique_macs.add(mac_addr)
            
            ie_order = []
            elt = packet.getlayer(Dot11Elt)
            while elt:
                elt_id = elt.ID
                field_data = bytes(elt.info)
                bit_data = ''.join(f'{byte:08b}' for byte in field_data)
                self.bit_analyzer.add_bits(elt_id, mac_addr, bit_data)
                ie_order.append(elt_id)
                elt = elt.payload.getlayer(Dot11Elt)
            
            # Add the order as a special IE
            order_bits = ''.join(f'{id:08b}' for id in ie_order)
            self.bit_analyzer.add_bits(self.ORDER_IE_ID, mac_addr, order_bits)

    def plot_results(self, stability_threshold: float = None):
        # Calculate metrics
        variability_data = self.bit_analyzer.calculate_variability()
        stability_data = self.bit_analyzer.calculate_stability()
        suitability_data = self.bit_analyzer.calculate_suitability(stability_threshold)
        
        # Create heatmaps
        plotting.make_heatmap(variability_data, name="variability_heatmap.pdf")
        plotting.make_heatmap(stability_data, name="stability_heatmap.pdf")
        plotting.make_heatmap(suitability_data, name="suitability_heatmap.pdf")

if __name__ == "__main__":
    analyzer = ProbeRequestAnalyzer("merged_two_files.pcap", 30000)
    analyzer.load_pcap()
    analyzer.analyze_packets()
    analyzer.plot_results(stability_threshold=0.7)