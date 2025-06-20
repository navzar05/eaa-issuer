import math
import hashlib
import time
from pickle import dumps
from secrets import randbits
from rbloom import Bloom
import struct
import secrets
from datetime import datetime, timedelta

class Cascade:

    def __init__(self):
        self.MAGIC_NUMBER = b'CSD1'
        pass

    def build_cascade(self, R, S):

        self.r_hat, self.s_hat = self.calculate_daily_crl_sizes(len(R))

        self.filters = []
        self.salt = format(secrets.randbits(256), "064x")

        self.s_hat = 2 * self.r_hat

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

        R_hat = R | Pr
        S_hat = S | Ps

        p = 0.5
        p0 = math.sqrt(p) / 2

        Win = R_hat.copy()
        Wex = S_hat.copy()

        level = 0
        while len(Win) > 0:
            false_positive_rate = p0 if level == 0 else p

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
                    W_false_positives.add(id)

            Wex = Win.copy()
            Win = W_false_positives.copy()

            level += 1

    def is_revoked(self, id):
        for filter_data in self.filters:
            level = filter_data['level']
            filter = filter_data['filter']
            salted_id = self._get_seasoned_id(id, level)
            if salted_id not in filter:
                return level % 2 == 0
        if len(self.filters) % 2 == 0:
            return False
        else:
            return True
     
    def calculate_daily_crl_sizes(self, current_valid_certs : int, daily_revocation_rate : float = 0.01, safety_factor : float = 1.2):
        expected_revocations = math.ceil(current_valid_certs * daily_revocation_rate * safety_factor)
        
        r_hat = current_valid_certs - expected_revocations
        
        s_hat = 2 * r_hat
        
        return r_hat, s_hat

    def serialize_cascade(self):
        data = []
        
        now = datetime.now()

        midnight = (now + timedelta(days=1)).replace(hour=0, minute=0, second=0, microsecond=0)

        midnight_timestamp = int(midnight.timestamp())

        data.append(struct.pack('>I', midnight_timestamp))
        
        salt_bytes = bytes.fromhex(self.salt)
        data.append(salt_bytes)
        
        num_filters = len(self.filters)
        data.append(struct.pack('>I', num_filters))
        
        for filter_data in self.filters:
            filter = filter_data['filter']
            bits = filter.save_bytes()
            
            length = len(bits)
            data.append(struct.pack('>I', length))
            
            data.append(bits)
        
        return b''.join(data)

    def deserialize_cascade(self, data):
        if isinstance(data, str):
            if data.startswith("0x"):
                data = data[2:]
            try:
                data = bytes.fromhex(data)
            except ValueError as e:
                raise ValueError(f"Invalid hex string: {e}")
        
        offset = 0
        timestamp = struct.unpack_from('>I', data, offset)[0]

        
        offset += 4
        
        self.salt = data[offset:offset + 32].hex()
        offset += 32
        
        num_filters = struct.unpack_from('>I', data, offset)[0]
        offset += 4
        
        self.filters = []
        for i in range(num_filters):
            length = struct.unpack_from('>I', data, offset)[0]
            offset += 4
            
            bits = data[offset:offset + length]
            offset += length
            
            filter = Bloom.load_bytes(bytes(bits), self._hash_func)
            
            self.filters.append({'level': i, 'filter': filter})
        
        return timestamp
    
    def serialize_cascade_blob(self):
        data = []
        now = datetime.now()
        midnight = (now + timedelta(days=1)).replace(hour=0, minute=0, second=0, microsecond=0)
        midnight_timestamp = int(midnight.timestamp())
        
        data.append(struct.pack('>I', midnight_timestamp))
        
        salt_bytes = bytes.fromhex(self.salt)
        data.append(salt_bytes)
        
        num_filters = len(self.filters)
        data.append(struct.pack('>I', num_filters))
        
        for filter_data in self.filters:
            filter = filter_data['filter']
            bits = filter.save_bytes()
            length = len(bits)
            data.append(struct.pack('>I', length))
            data.append(bits)
        
        raw_data = b''.join(data)
        
        blob_data = bytearray()
        BYTES_PER_ELEMENT = 32
        DATA_BYTES_PER_ELEMENT = 31
        
        for i in range(0, len(raw_data), DATA_BYTES_PER_ELEMENT):
            chunk = raw_data[i:i + DATA_BYTES_PER_ELEMENT]
            
            field_element = bytearray(BYTES_PER_ELEMENT)
            field_element[0] = 0x00 
            field_element[1:1 + len(chunk)] = chunk
            
            blob_data.extend(field_element)
        
        return bytes(self.MAGIC_NUMBER + blob_data)
    
    def deserialize_cascade_blob(self, data):
        
        
        if isinstance(data, str):
            if data.startswith("0x"):
                data = data[2:]
            try:
                data = bytes.fromhex(data)
            except ValueError as e:
                raise ValueError(f"Invalid hex string: {e}")
        
        print(f" Processing {len(data)} bytes of blob data")
        
        extracted_data = bytearray()
        BYTES_PER_ELEMENT = 32
        
        for i in range(0, len(data), BYTES_PER_ELEMENT):
            if i + BYTES_PER_ELEMENT <= len(data):
                field_element = data[i:i + BYTES_PER_ELEMENT]
                data_chunk = field_element[1:]
                extracted_data.extend(data_chunk)
            else:
                remaining = data[i:]
                if len(remaining) > 1:
                    extracted_data.extend(remaining[1:])
        
        print(f" Extracted {len(extracted_data)} bytes from field elements")
    
        magic_offset = extracted_data.find(self.MAGIC_NUMBER)
        
        if magic_offset == -1:
            print(" Magic number not found!")
            print(f" Looking for: {self.MAGIC_NUMBER.hex()} ({self.MAGIC_NUMBER})")
            print(f" Data preview: {extracted_data[:100].hex()}")
            raise ValueError(f"Magic number {self.MAGIC_NUMBER} not found in blob data")
        
        print(f" Magic number found at offset {magic_offset}")
        
        cascade_data = extracted_data[magic_offset + len(self.MAGIC_NUMBER):]
        
        while cascade_data and cascade_data[-1] == 0:
            cascade_data.pop()
        
        cascade_bytes = bytes(cascade_data)
        
        print(f" Cascade data length: {len(cascade_bytes)} bytes")
        print(f" Cascade data preview: {cascade_bytes[:50].hex()}")

        if len(cascade_bytes) < 40:
            raise ValueError(f"Cascade data too short: {len(cascade_bytes)} bytes")
        
        offset = 0
        timestamp = struct.unpack_from('>I', cascade_bytes, offset)[0]
        print(f" Timestamp: {timestamp}")
        
        offset += 4
        
        if offset + 32 > len(cascade_bytes):
            raise ValueError("Not enough data for salt")
        
        self.salt = cascade_bytes[offset:offset + 32].hex()
        print(f" Salt: {self.salt[:20]}...")
        offset += 32
        
        if offset + 4 > len(cascade_bytes):
            raise ValueError("Not enough data for filter count")
        
        num_filters = struct.unpack_from('>I', cascade_bytes, offset)[0]
        print(f" Number of filters: {num_filters}")
        offset += 4
        
        if num_filters > 100:
            raise ValueError(f"Unreasonable number of filters: {num_filters}")
        
        self.filters = []
        for i in range(num_filters):
            print(f" Processing filter {i+1}/{num_filters}")
            
            if offset + 4 > len(cascade_bytes):
                raise ValueError(f"Not enough data for filter {i} length")
            
            length = struct.unpack_from('>I', cascade_bytes, offset)[0]
            print(f"   Filter {i} length: {length} bytes")
            offset += 4
            
            if length > len(cascade_bytes) - offset:
                raise ValueError(f"Filter {i} length {length} exceeds remaining data")
            
            bits = cascade_bytes[offset:offset + length]
            offset += length
            
            try:
                filter = Bloom.load_bytes(bytes(bits), self._hash_func)
                
                self.filters.append({'level': i, 'filter': filter})
                print(f"    Filter {i} loaded successfully")
                
            except Exception as e:
                raise ValueError(f"Failed to load filter {i}: {e}")
        
        print(f" Cascade deserialized successfully!")
        print(f" Total filters loaded: {len(self.filters)}")
    
        return timestamp

    def _get_seasoned_id(self, id, level):
        #return hashlib.sha3_256((id + str(level) + self.salt).encode()).hexdigest()
        return (id + str(level) + self.salt).encode()
    
    def _hash_func(self, obj):
        h = hashlib.sha3_256(dumps(obj)).digest()
        return int.from_bytes(h[:16], "big", signed=True)