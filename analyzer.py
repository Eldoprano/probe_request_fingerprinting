import numpy as np
from collections import defaultdict
import matplotlib.pyplot as plt
from typing import Dict, List
from tqdm import tqdm
from scapy.all import PcapReader, Dot11Elt
import plotting
from bitarray import bitarray
import hashlib

class BitAnalyzer:
    """Class to analyze the stability, variability, and suitability of bits within Wi-Fi probe requests."""
    
    def __init__(self, max_bits_per_elt: int = 104):
        """Initialize BitAnalyzer with maximum bits per element limit."""
        self.max_bits_per_elt = max_bits_per_elt
        self.data: Dict[int, Dict[str, List[str]]] = defaultdict(lambda: defaultdict(list))
        self.masks: Dict[int, List[int]] = {}
        
    def add_bits(self, elt_id: int, mac_addr: str, bit_data: str) -> None:
        """Adds bits from an information element to the data dictionary, with padding if necessary."""
        bit_data = bit_data[:self.max_bits_per_elt].ljust(self.max_bits_per_elt, 'U')
        self.data[elt_id][mac_addr].append(bit_data)

    def calculate_variability(self) -> Dict[int, np.ndarray]:
        """Calculates variability across devices for each bit position in the data dictionary."""
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
        """Calculates bit stability for each device based on entropy."""
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
        """Calculates bit suitability based on variability and stability data with a given threshold."""
        if stability_threshold is None:
            raise ValueError("stability_threshold must be provided")
        
        variability = self.calculate_variability()
        stability = self.calculate_stability()
        suitability_data = {}
        
        for elt_id in variability.keys():
            # Only calculate variability for bits that meet stability threshold
            stable_bits_mask = stability[elt_id] >= stability_threshold
            suitability = np.zeros_like(variability[elt_id])
            suitability[stable_bits_mask] = variability[elt_id][stable_bits_mask]
            suitability_data[elt_id] = suitability
        
        return suitability_data

    def create_masks(self, suitability_data: Dict[int, np.ndarray], suitability_threshold: float = 0.9) -> Dict[int, List[int]]:
        """Generates masks of suitable bit positions based on suitability threshold."""
        self.masks = {}
        
        for elt_id, suitability in suitability_data.items():
            suitable_bits = np.where(suitability >= suitability_threshold)[0]
            if len(suitable_bits) > 0:
                self.masks[elt_id] = suitable_bits.tolist()
        
        return self.masks

    def extract_identifier(self, packet, masks) -> str:
        """Extract identifier from a packet using masks calculated based on bit suitability."""
        identifier_parts = []
        order_bits = ''
        
        info_element = packet.getlayer(Dot11Elt)
        while info_element:
            element_id = info_element.ID
            element_data = bytes(info_element.info)
            
            if element_id == 255 and element_data: # Extended tag
                extended_tag = element_data[0]
                element_id += extended_tag
                element_data = element_data[1:]
            
            # Add to order bits
            order_bits += f'{element_id:08b}'
            
            if element_id in masks:
                bit_data = bitarray()
                bit_data.frombytes(element_data)
                bit_string = bit_data.to01()
                masked_bits = []
                for pos in masks[element_id]:
                    if pos < len(bit_string):
                        masked_bits.append(bit_string[pos])
                    else:
                        break  # Stop if out of range
                if masked_bits:  # Only append if there are masked bits
                    identifier_parts.append(f"{element_id}:{''.join(masked_bits)}")
            
            info_element = info_element.payload.getlayer(Dot11Elt)
        
        # Process order bits
        if 253 in masks:  # ORDER_IE_ID
            masked_order_bits = []
            for pos in masks[253]:
                if pos < len(order_bits):
                    masked_order_bits.append(order_bits[pos])
                else:
                    break  # Stop if out of range
            if masked_order_bits:  # Only append if there are masked order bits
                masked_order_bits_str = ''.join(masked_order_bits)
                identifier_parts.append(f"253:{masked_order_bits_str}")
        
        return "_".join(identifier_parts)
    
    def get_id(self, packet, masks = None) -> str:
        """Get a unique identifier for a packet based on bit masks."""
        if masks is None:
            # Use a default mask if none is provided
            masks = {1: [32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63], 50: [2, 3, 4, 5, 9, 11, 12, 14, 17, 18, 19, 20, 25, 28, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63], 45: [0, 1, 4, 5, 6, 7, 9, 11, 15, 20, 21, 32, 33, 34, 35, 36, 37, 38, 39], 127: [12, 21, 22, 23, 24, 30, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 58, 59, 60, 61, 62, 63, 65, 66, 67, 68, 69, 70, 71], 253: [26, 27, 31, 32, 33, 34, 35, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79], 191: [8, 12, 23, 37, 48, 49, 50, 52, 53, 54, 62, 69, 80, 81, 82, 84, 85, 86, 94], 107: [8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55]}
        # Return the last 8 hex characters of the SHA-256 hash of the identifier
        identifier = self.extract_identifier(packet, masks)
        identifier_hash = hashlib.sha256(identifier.encode()).hexdigest()
        return identifier_hash[-8:]
    
class ProbeRequestAnalyzer:
    """Class to analyze Wi-Fi probe requests from pcap files."""
    
    def __init__(self, filename: str, num_samples: int = None):
        self.filename = filename
        self.num_samples = num_samples
        self.bit_analyzer = BitAnalyzer()
        self.ORDER_IE_ID = 253

    def load_and_analyze(self):
        """Loads and analyzes probe requests from pcap file and adds bit data to BitAnalyzer."""
        unique_macs = {}
        frame_count = 0
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
                    
                    if element_id == 255 and element_field_data: # Extended tag
                        extended_tag = element_field_data[0]
                        element_id += extended_tag
                        element_field_data = element_field_data[1:] # Remove the first byte
                    
                    bit_data = bitarray()
                    bit_data.frombytes(element_field_data)
                    self.bit_analyzer.add_bits(element_id, mac_addr, bit_data.to01())
                    order_bits += f'{element_id:08b}'
                    
                    info_element = info_element.payload.getlayer(Dot11Elt)
                
                self.bit_analyzer.add_bits(self.ORDER_IE_ID, mac_addr, order_bits)
                frame_count += 1
        
        if self.num_samples is None or frame_count < self.num_samples:
            self.num_samples = frame_count
        print(f"Loaded and analyzed packets from {self.filename} with {len(unique_macs)} unique MAC addresses")

    def plot_results(self, stability_thresholds: List[float]):
        """Plots heatmaps for stability and suitability data based on given thresholds."""
        base_filename = self.filename.split('/')[-1].split('.')[0]
        
        stability_data = self.bit_analyzer.calculate_stability()
        plotting.make_heatmap(stability_data, name=f"heatmap_sta_{base_filename}", scale_min = 0.9)
        
        for threshold in stability_thresholds:
            suitability_data = self.bit_analyzer.calculate_suitability(threshold)
            plotting.make_heatmap(suitability_data, name=f"heatmap_sui{threshold}_{base_filename}")
