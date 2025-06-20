import math
import hashlib
import time
from pickle import dumps
from secrets import randbits
from rbloom import Bloom
import struct
import secrets
from datetime import datetime, timedelta

class CascadeBlob:

    def __init__(self):
        pass

    def build_cascade(self, R, S):
        """
        Build the cascade of RBloomFilters.
        
        :param R: Set of valid credential IDs (strings).
        :param S: Set of revoked credential IDs (strings).
        :param r_hat: Padding size for valid IDs (|R| ≤ r_hat, |S| ≤ 2*r_hat).
        """
        self.MAGIC_NUMBER = b'CSD1'

        self.r_hat, self.s_hat = self.calculate_daily_crl_sizes(len(R))

        # Initialize the filters list
        self.filters = []
        # Generate 256-bit salt as a hex string
        self.salt = format(secrets.randbits(256), "064x")

        self.s_hat = 2 * self.r_hat

        # Generate padding IDs
        Pr = set()
        while len(Pr) < self.r_hat - len(R):
            new_id = format(randbits(256), '064x')
            if new_id not in R and new_id not in S:
                Pr.add(new_id)

        Ps = set()
        while len(Ps) < self.s_hat - len(S):
            new_id = format(randbits(256), '064x')
            if new_id not in R and new_id not in S and new_id not in Pr:
                Ps.add(new_id)

        # Add the padding
        R_hat = R | Pr
        S_hat = S | Ps

        p = 0.5
        p0 = math.sqrt(p) / 2

        # Generate the working sets for included and excluded IDs
        Win = R_hat.copy()
        Wex = S_hat.copy()

        # Iterate until we eliminate all false positives
        level = 0
        while len(Win) > 0:
            false_positive_rate = p0 if level == 0 else p

            # Create a new filter
            filter = Bloom(expected_items=len(Win), false_positive_rate=false_positive_rate, hash_func=self._hash_func)

            W_salted = set()
            for id in Win:
                salted_id = self._get_seasoned_id(id, level)
                W_salted.add(salted_id)

            for salted_id in W_salted:
                filter.add(salted_id)

            # Store filter
            self.filters.append({'level': level, 'filter': filter})

            W_false_positives = set()
            for id in Wex:
                salted_id = self._get_seasoned_id(id, level)
                if salted_id in filter:
                    W_false_positives.add(id)  # Collect original id

            Wex = Win.copy()
            Win = W_false_positives.copy()

            level += 1

    def is_revoked(self, id):
        """Check if an ID is revoked."""
        for filter_data in self.filters:
            level = filter_data['level']
            filter = filter_data['filter']
            salted_id = self._get_seasoned_id(id, level)
            if salted_id not in filter:
                return level % 2 == 1  # Even: valid, Odd: revoked
        if len(self.filters) % 2 == 0:
            return False
        else:
            return True

        
    def calculate_daily_crl_sizes(self, current_valid_certs : int, daily_revocation_rate : float = 0.01, safety_factor : float = 1.2):
        """
        Calculate appropriate sizes for R and S sets for a daily CRL.
        
        Parameters:
        current_valid_certs (int): Number of currently valid certificates that could be revoked
        daily_revocation_rate (float): Expected maximum daily revocation rate (e.g., 0.01 for 1%)
        safety_factor (float): Multiplier to add extra capacity for unexpected spikes
        
        Returns:
        tuple: (r_hat, s_hat) - The padded sizes for sets R and S
        """

        expected_revocations = math.ceil(current_valid_certs * daily_revocation_rate * safety_factor)
        
        r_hat = current_valid_certs - expected_revocations
        
        s_hat = 2 * r_hat
        
        return r_hat, s_hat

    def serialize_cascade(self):
        """
        Serialize the cascade filter into a binary format compatible with blob data.
        Each 32-byte field element has MSB = 0x00 for EIP-4844 compatibility.
        
        Returns:
            bytes: Serialized cascade data formatted for blob storage
        """
        data = []
        now = datetime.now()
        # Calculate midnight (next day)
        midnight = (now + timedelta(days=1)).replace(hour=0, minute=0, second=0, microsecond=0)
        # Convert to timestamp (seconds since epoch)
        midnight_timestamp = int(midnight.timestamp())
        
        # Add today's midnight timestamp
        data.append(struct.pack('>I', midnight_timestamp))
        
        # Add salt
        salt_bytes = bytes.fromhex(self.salt)
        data.append(salt_bytes)
        
        # Add number of filters
        num_filters = len(self.filters)
        data.append(struct.pack('>I', num_filters))
        
        # Add each filter
        for filter_data in self.filters:
            filter = filter_data['filter']
            bits = filter.save_bytes()
            # Add length of filter data
            length = len(bits)
            data.append(struct.pack('>I', length))
            # Add filter data
            data.append(bits)
        
        # Combine all parts
        raw_data = b''.join(data)
        
        # Convert to blob-compatible format (31 bytes data per 32-byte field element)
        blob_data = bytearray()
        BYTES_PER_ELEMENT = 32
        DATA_BYTES_PER_ELEMENT = 31  # 31 bytes of data per field element (MSB = 0x00)
        
        # Process data in 31-byte chunks
        for i in range(0, len(raw_data), DATA_BYTES_PER_ELEMENT):
            # Get chunk (up to 31 bytes)
            chunk = raw_data[i:i + DATA_BYTES_PER_ELEMENT]
            
            # Create 32-byte field element: 0x00 + data + padding if needed
            field_element = bytearray(BYTES_PER_ELEMENT)
            field_element[0] = 0x00  # MSB must be 0x00
            field_element[1:1 + len(chunk)] = chunk
            # Remaining bytes are already 0x00 from bytearray initialization
            
            blob_data.extend(field_element)
        
        return bytes(blob_data)

    def deserialize_cascade(self, data, max_age_days=1):
        """
        Deserialize binary data from blob-compatible format into a cascade filter.
        Extracts data from 32-byte field elements where MSB = 0x00.
        
        Args:
            data: Binary data or hex string representation (blob format)
            max_age_days: Maximum age in days for the data to be considered valid
        
        Returns:
            int: Timestamp if successful, -1 if expired
        """
        
        MAGIC_NUMBER = b'CSD1'  # Define magic number here or import it
        
        # Handle hex string input
        if isinstance(data, str):
            if data.startswith("0x"):
                data = data[2:]
            try:
                data = bytes.fromhex(data)
            except ValueError as e:
                raise ValueError(f"Invalid hex string: {e}")
        
        print(f"🔍 Processing {len(data)} bytes of blob data")
        
        # Step 1: Extract data from blob field elements (32-byte chunks)
        extracted_data = bytearray()
        BYTES_PER_ELEMENT = 32
        
        for i in range(0, len(data), BYTES_PER_ELEMENT):
            if i + BYTES_PER_ELEMENT <= len(data):
                field_element = data[i:i + BYTES_PER_ELEMENT]
                # Skip first byte (MSB = 0x00), extract remaining 31 bytes
                data_chunk = field_element[1:]
                extracted_data.extend(data_chunk)
            else:
                # Handle partial field element at end
                remaining = data[i:]
                if len(remaining) > 1:  # Skip MSB
                    extracted_data.extend(remaining[1:])
        
        print(f"📏 Extracted {len(extracted_data)} bytes from field elements")
        
        # Step 2: Find magic number in extracted data
        magic_offset = extracted_data.find(MAGIC_NUMBER)
        
        if magic_offset == -1:
            print("❌ Magic number not found!")
            print(f"🔍 Looking for: {MAGIC_NUMBER.hex()} ({MAGIC_NUMBER})")
            print(f"📋 Data preview: {extracted_data[:100].hex()}")
            raise ValueError(f"Magic number {MAGIC_NUMBER} not found in blob data")
        
        print(f"🔮 Magic number found at offset {magic_offset}")
        
        # Step 3: Extract cascade data (everything after magic number)
        cascade_data = extracted_data[magic_offset + len(MAGIC_NUMBER):]
        
        # Remove trailing zeros
        while cascade_data and cascade_data[-1] == 0:
            cascade_data.pop()
        
        # Convert back to bytes for processing
        cascade_bytes = bytes(cascade_data)
        
        print(f"📦 Cascade data length: {len(cascade_bytes)} bytes")
        print(f"🔢 Cascade data preview: {cascade_bytes[:50].hex()}")
        
        # Step 4: Deserialize the cascade data directly (NO MORE BLOB PROCESSING)
        # The cascade_bytes now contains your original serialized cascade data
        
        if len(cascade_bytes) < 40:  # Minimum: 4 (timestamp) + 32 (salt) + 4 (num_filters)
            raise ValueError(f"Cascade data too short: {len(cascade_bytes)} bytes")
        
        # Extract timestamp (first 4 bytes)
        offset = 0
        timestamp = struct.unpack_from('>I', cascade_bytes, offset)[0]
        print(f"📅 Timestamp: {timestamp}")
        
        # Continue with deserialization
        offset += 4
        
        # Extract salt (next 32 bytes)
        if offset + 32 > len(cascade_bytes):
            raise ValueError("Not enough data for salt")
        
        self.salt = cascade_bytes[offset:offset + 32].hex()
        print(f"🧂 Salt: {self.salt[:20]}...")
        offset += 32
        
        # Extract number of filters (4 bytes)
        if offset + 4 > len(cascade_bytes):
            raise ValueError("Not enough data for filter count")
        
        num_filters = struct.unpack_from('>I', cascade_bytes, offset)[0]
        print(f"🔢 Number of filters: {num_filters}")
        offset += 4
        
        if num_filters > 100:  # Sanity check
            raise ValueError(f"Unreasonable number of filters: {num_filters}")
        
        # Reconstruct filters
        self.filters = []
        for i in range(num_filters):
            print(f"📦 Processing filter {i+1}/{num_filters}")
            
            # Extract filter data length (4 bytes)
            if offset + 4 > len(cascade_bytes):
                raise ValueError(f"Not enough data for filter {i} length")
            
            length = struct.unpack_from('>I', cascade_bytes, offset)[0]
            print(f"   Filter {i} length: {length} bytes")
            offset += 4
            
            if length > len(cascade_bytes) - offset:
                raise ValueError(f"Filter {i} length {length} exceeds remaining data")
            
            # Extract filter data
            bits = cascade_bytes[offset:offset + length]
            offset += length
            
            # Reconstruct filter
            try:
                filter = Bloom.load_bytes(bytes(bits), self._hash_func)
                
                # Store filter
                self.filters.append({'level': i, 'filter': filter})
                print(f"   ✅ Filter {i} loaded successfully")
                
            except Exception as e:
                raise ValueError(f"Failed to load filter {i}: {e}")
        
        print(f"✅ Cascade deserialized successfully!")
        print(f"📊 Total filters loaded: {len(self.filters)}")
    
        # Return the timestamp that was embedded in the data
        return timestamp

    def _get_seasoned_id(self, id, level):
        """
        Returns the salted ID using SHA-256 hashing.
        """
        #return hashlib.sha3_256((id + str(level) + self.salt).encode()).hexdigest()
        return (id + str(level) + self.salt).encode()
    
    def _hash_func(self, obj):
        h = hashlib.sha3_256(dumps(obj)).digest()
        return int.from_bytes(h[:16], "big", signed=True)