import numpy as np
from collections import defaultdict
from typing import Dict, List
from tqdm import tqdm
from scapy.all import PcapReader, Dot11Elt
import plotting
from bitarray import bitarray

class BitAnalyzer:
    def __init__(self, max_bits_per_elt: int = 104): # Theoretical maximum is 1024 bits, but messes up the graph
        self.max_bits_per_elt = max_bits_per_elt
        self.data: Dict[int, Dict[str, List[str]]] = defaultdict(lambda: defaultdict(list))
        
    def add_bits(self, elt_id: int, mac_addr: str, bit_data: str) -> None:
        # Truncate element data if necessary (not expected to happen) and pad with 'U'
        bit_data = bit_data[:self.max_bits_per_elt].ljust(self.max_bits_per_elt, 'U')
        self.data[elt_id][mac_addr].append(bit_data)

    # It calculates how information element data varies when sent by different devices
    def calculate_variability(self) -> Dict[int, np.ndarray]:
        variability_data = {}
        
        for elt_id, mac_bits in self.data.items():
            device_bits = [bits[0] for bits in mac_bits.values()] # It only uses the first frame from current IE for each device
            variability_row = np.zeros(self.max_bits_per_elt)
            for bit_idx in range(self.max_bits_per_elt):
                bit_values = [bits[bit_idx] for bits in device_bits]
                counts = {'0': 0, '1': 0, 'U': 0}
                for val in bit_values:
                    counts[val] += 1

                # Entropy value of 0.1 is equivalent to 98% of the data being the same
                # Entropy value of 1.0 is equivalent to 33% of the data being the same
                total = len(bit_values)
                entropy = sum(
                    -p * np.log(p) / np.log(3) for p in (count / total for count in counts.values() if count > 0)
                )
                
                variability_row[bit_idx] = entropy
                
            variability_data[elt_id] = variability_row
            
        return variability_data

    def calculate_stability(self) -> Dict[int, np.ndarray]:
        stability_data = {}
        
        for elt_id, mac_bits in self.data.items():
            device_stabilities = []
            
            for mac_addr, frames in mac_bits.items():
                stability_row = np.zeros(self.max_bits_per_elt)
                
                for bit_idx in range(self.max_bits_per_elt):
                    bit_values = [frame[bit_idx] for frame in frames]
                    counts = {'0': 0, '1': 0, 'U': 0}
                    for val in bit_values:
                        counts[val] += 1
                    
                    total = len(bit_values)
                    # Entropy value of 0.1 is equivalent to 98% of the data being the same
                    # Entropy value of 1.0 is equivalent to 33% of the data being the same
                    entropy = sum(
                        -p * np.log(p) / np.log(3) for p in (count / total for count in counts.values() if count > 0)
                    )
                    
                    stability_row[bit_idx] = 1 - entropy
                
                device_stabilities.append(stability_row)
            
            device_stabilities = np.array(device_stabilities)
            mean_stability = np.mean(device_stabilities, axis=0)
            std_error = np.std(device_stabilities, axis=0) / np.sqrt(device_stabilities.shape[0])
            
            # Calculate the minimum stability that represents 97.3% of the data
            min_stability = mean_stability - 2 * std_error
            
            stability_data[elt_id] = min_stability
        
        return stability_data
            
    def calculate_suitability(self, stability_threshold: float) -> Dict[int, np.ndarray]:
        if stability_threshold is None:
            raise ValueError("stability_threshold must be provided")
        
        variability = self.calculate_variability()
        stability = self.calculate_stability()
        suitability_data = {}
        
        for elt_id in variability.keys():
            stable_bits_mask = stability[elt_id] >= stability_threshold
            suitability = np.zeros_like(variability[elt_id])
            
            # Only calculate variability for bits that meet stability threshold
            suitability[stable_bits_mask] = variability[elt_id][stable_bits_mask]
            
            suitability_data[elt_id] = 1 - suitability
        
        return suitability_data

class ProbeRequestAnalyzer:
    def __init__(self, filename: str, num_samples: int = None):
        self.filename = filename
        self.num_samples = num_samples
        self.bit_analyzer = BitAnalyzer()
        self.ORDER_IE_ID = 253

    def load_and_analyze(self):
        unique_macs = {}
        
        with PcapReader(self.filename) as pcap_reader:
            for i, packet in enumerate(tqdm(pcap_reader, desc="Analyzing packets", unit="frames", total=self.num_samples)):
                if i >= self.num_samples:
                    break
                if not packet.haslayer(Dot11Elt):
                    continue
                
                mac_addr = packet.addr2
                if mac_addr is None:
                    continue
                    
                unique_macs[mac_addr] = None # Using a dictionary to count unique MAC addresses
                
                order_bits = ''
                info_element = packet.getlayer(Dot11Elt)
                # Go through every information element in the current packet
                while info_element:
                    element_id = info_element.ID
                    element_field_data = bytes(info_element.info)
                    
                    if element_id == 255 and element_field_data:  # Extended tag
                        extended_tag = element_field_data[0]
                        element_id += extended_tag
                        element_field_data = element_field_data[1:]  # Remove the first byte
                    
                    bit_data = bitarray()
                    bit_data.frombytes(element_field_data)
                    self.bit_analyzer.add_bits(element_id, mac_addr, bit_data.to01())
                    order_bits += f'{element_id:08b}'
                    
                    info_element = info_element.payload.getlayer(Dot11Elt)
                
                self.bit_analyzer.add_bits(self.ORDER_IE_ID, mac_addr, order_bits)
        
        print(f"Loaded and analyzed packets from {self.filename} with {len(unique_macs)} unique MAC addresses")

    def plot_results(self, stability_thresholds: List[float] = None):
        base_filename = self.filename.split('/')[-1].split('.')[0]
        
        stability_data = self.bit_analyzer.calculate_stability()
        plotting.make_heatmap(stability_data, name=f"{base_filename}_stability_heatmap", scale_min = 0.9)
        
        for threshold in stability_thresholds:
            suitability_data = self.bit_analyzer.calculate_suitability(threshold)
            plotting.make_heatmap(suitability_data, name=f"{base_filename}_suitability_heatmap{threshold}")

if __name__ == "__main__":
    analyzer = ProbeRequestAnalyzer(filename="./pcaps/merged_dataset_2.pcap", num_samples=69700)
    analyzer.load_and_analyze()
    analyzer.plot_results(stability_thresholds=[0.9, 0.95, 1])