import numpy as np
from collections import defaultdict
import matplotlib.pyplot as plt
from typing import Dict, List
from tqdm import tqdm
from scapy.all import PcapReader, Dot11Elt
import plotting
from bitarray import bitarray

class BitAnalyzer:
    def __init__(self, max_bits_per_elt: int = 104): # Theoretical maximum is 1024 bits, but messes up the graph
        self.max_bits_per_elt = max_bits_per_elt
        self.data: Dict[int, Dict[str, List[str]]] = defaultdict(lambda: defaultdict(list))
        self.masks: Dict[int, List[int]] = {}
        
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
            suitability_data[elt_id] = suitability
        
        return suitability_data

    def create_masks(self, suitability_data: Dict[int, np.ndarray], suitability_threshold: float = 0.9) -> Dict[int, List[int]]:
        self.masks = {}
        
        for elt_id, suitability in suitability_data.items():
            suitable_bits = np.where(suitability >= suitability_threshold)[0]
            if len(suitable_bits) > 0:
                self.masks[elt_id] = suitable_bits.tolist()
        
        return self.masks

    def extract_identifier(self, packet, masks) -> str:
        """Extract identifier from a packet using calculated masks."""
        identifier_parts = []
        order_bits = ''
        
        info_element = packet.getlayer(Dot11Elt)
        while info_element:
            element_id = info_element.ID
            element_data = bytes(info_element.info)
            
            if element_id == 255 and element_data:  # Extended tag
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
                        break  # Stop processing further positions if out of range
                if masked_bits:  # Only append if there are masked bits
                    masked_bits_str = ''.join(masked_bits)
                    identifier_parts.append(f"{element_id}:{masked_bits_str}")
            
            info_element = info_element.payload.getlayer(Dot11Elt)
        
        # Process order bits
        if 253 in masks:  # ORDER_IE_ID
            masked_order_bits = []
            for pos in masks[253]:
                if pos < len(order_bits):
                    masked_order_bits.append(order_bits[pos])
                else:
                    break  # Stop processing further positions if out of range
            if masked_order_bits:  # Only append if there are masked order bits
                masked_order_bits_str = ''.join(masked_order_bits)
                identifier_parts.append(f"253:{masked_order_bits_str}")
        
        return "_".join(identifier_parts)

class ProbeRequestAnalyzer:
    def __init__(self, filename: str, num_samples: int = None):
        self.filename = filename
        self.num_samples = num_samples
        self.bit_analyzer = BitAnalyzer()
        self.ORDER_IE_ID = 253

    def load_and_analyze(self):
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
                frame_count += 1
        
        if self.num_samples is None or frame_count < self.num_samples:
            self.num_samples = frame_count
        print(f"Loaded and analyzed packets from {self.filename} with {len(unique_macs)} unique MAC addresses")

    def plot_results(self, stability_thresholds: List[float]):
        base_filename = self.filename.split('/')[-1].split('.')[0]
        
        stability_data = self.bit_analyzer.calculate_stability()
        plotting.make_heatmap(stability_data, name=f"{base_filename}_stability_heatmap", scale_min = 0.9)
        
        for threshold in stability_thresholds:
            suitability_data = self.bit_analyzer.calculate_suitability(threshold)
            plotting.make_heatmap(suitability_data, name=f"{base_filename}_suitability_heatmap{threshold}")

    def experiment_with_identification(self, stability_threshold: float = 0.95, suitability_threshold: float = 0.9):
        """Run experiment to test identification effectiveness and plot results."""
        print(f"\nRunning identification experiment with stability={stability_threshold}, suitability={suitability_threshold}")
        
        # Calculate suitability and create masks
        suitability_data = self.bit_analyzer.calculate_suitability(stability_threshold)
        masks = self.bit_analyzer.create_masks(suitability_data, suitability_threshold)
        
        # Test identification
        mac_to_identifiers = defaultdict(set)
        identifier_to_macs = defaultdict(set)
        
        with PcapReader(self.filename) as pcap_reader:
            for packet in tqdm(pcap_reader, desc="Testing identification", unit="frames", total=self.num_samples):
                if not packet.haslayer(Dot11Elt):
                    continue
                    
                mac_addr = packet.addr2
                if mac_addr is None:
                    continue
                    
                identifier = self.bit_analyzer.extract_identifier(packet, masks)
                mac_to_identifiers[mac_addr].add(identifier)
                identifier_to_macs[identifier].add(mac_addr)
        
        # Calculate metrics
        total_devices = len(mac_to_identifiers)
        unique_identifiers = len(identifier_to_macs)
        # Devices with only one identifier are considered stable
        stable_devices = sum(1 for ids in mac_to_identifiers.values() if len(ids) == 1)
        # Identifiers that only match one device are considered unique
        unique_identifiers_count = sum(1 for macs in identifier_to_macs.values() if len(macs) == 1)
        
        print(f"\nResults:")
        print(f"📱 Total devices: {total_devices}")
        print(f"🔑 Unique identifiers generated: {unique_identifiers}")
        print(f"🙂 Devices with stable identifier: {stable_devices} ({stable_devices/total_devices:.2%})")
        print(f"😥 Devices with more than one identifier: {total_devices - stable_devices} ({(total_devices - stable_devices)/total_devices:.2%})")
        print(f"🙂 Identifiers matching unique device: {unique_identifiers_count} ({unique_identifiers_count/unique_identifiers:.2%})")
        print(f"😥 Identifiers matching more than one device: {unique_identifiers - unique_identifiers_count} ({(unique_identifiers - unique_identifiers_count)/unique_identifiers:.2%})")
        # print("\nMasks used:")
        # for elt_id, mask in masks.items():
        #     print(f"Element {elt_id}: {len(mask)} bits - {mask}")
        
        # Plot results
        self.plot_experiment_results(
            total_devices, unique_identifiers, stable_devices, unique_identifiers_count,
            stability_threshold, suitability_threshold
        )
        
        return mac_to_identifiers, identifier_to_macs

    def plot_experiment_results(self, total_devices, unique_identifiers, stable_devices, unique_identifiers_count,
                                stability_threshold, suitability_threshold):
        """Generate bar chart for experiment results."""
        metrics = ['Total Devices', 'Unique Identifiers', 'Stable Devices', 'Unique Identifiers per Device']
        values = [total_devices, unique_identifiers, stable_devices, unique_identifiers_count]
        
        plt.figure(figsize=(10, 6))
        plt.bar(metrics, values, color=['blue', 'green', 'orange', 'red'])
        plt.title(f"Identification Experiment Results\n"
                  f"Stability Threshold={stability_threshold}, Suitability Threshold={suitability_threshold}")
        plt.xlabel("Metrics")
        plt.ylabel("Counts")
        
        # Display counts on top of bars
        for i, v in enumerate(values):
            plt.text(i, v + 0.5, str(v), ha='center', fontweight='bold')
        
        plt.tight_layout()
        plt.show()

        # Save the plot
        base_filename = self.filename.split('/')[-1].split('.')[0]
        plt.savefig(f"{base_filename}_experiment{stability_threshold}_{suitability_threshold}.png")

if __name__ == "__main__":
    analyzer = ProbeRequestAnalyzer(filename="./pcaps/rand2_5000.pcap", num_samples=69700)
    analyzer.load_and_analyze()
    analyzer.plot_results(stability_thresholds=[0.9, 0.95, 1])
    
    # Run identification experiments with different thresholds
    for stability in [0.85, 0.9, 0.95, 1.0]:
        for suitability in [0.1, 0.2, 0.3, 0.5]:
            print(f"\nRunning experiment with stability={stability}, suitability={suitability}")
            analyzer.experiment_with_identification(
                stability_threshold=stability,
                suitability_threshold=suitability
            )