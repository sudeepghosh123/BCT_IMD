from charm.toolbox.pairinggroup import PairingGroup, ZR, G1, G2, pair
from charm.toolbox.integergroup import IntegerGroup
from charm.core.engine.util import objectToBytes, bytesToObject
import hashlib
import charm.toolbox.ecgroup
import math


class IMDS_PKG:
    # Initiating the group and master key
    def __init__(self) -> None:
        # self.curve_name = 'secp256r1'
        self.group = PairingGroup('SS512')
        self.integer_group = IntegerGroup()
        self.integer_group.paramgen(512)
        self.q = self.group.order()
        print(f'Params : {self.group.param}')
        print(f'q : {self.q}')
        print(f'q_bits : {int(math.ceil(math.log2(self.q)))}')
    
    # Define the bilinear map
    def e(self, a, b):
        return pair(a, b)

    # Map to point hash function
    def H0(self, input_str):
        input_str = str(input_str)
        return self.group.hash(input_str, G1)
    
    # General hash function
    def H1(self, input_str):
        input_str = str(input_str)
        return self.group.hash(input_str, ZR)
    
    # Hash the message to G3
    def H2(self, message):
        hashed_value = self.group.hash(message, G1)
        return hashed_value
    
    # SHA256 hash string to number
    def hash_int(self, input_str):
        if type(input_str)!='bytes':
            input_str= bytes(str(input_str), 'utf-8')
        hash_object = hashlib.sha256()
        hash_object.update(input_str)
        int_hash = int(hash_object.hexdigest(), 16)
        return int_hash

    
    def generate_params(self):
        self.q = self.group.order()
        self.P = self.group.random(G1)
        self.P1 = self.group.random(G1)

        # Master secret key
        self.s = self.group.random(ZR)
        # Master public key
        self.P0 = self.s * self.P

        # Step 6: Publish public parameters
        public_parameters = {
            'q': self.q,
            'G1': G1,
            'G2': G2,
            'P': self.P,
            'P1': self.P1,
            'e': self.e,
            'H0': self.H0,
            'H1': self.H1,
            'H2': self.H2,
            'HH': self.hash_int,
            'P0': self.P0,
            's':self.s,
            'group':self.group,
            'integer_group':self.integer_group
        } 
        return public_parameters      


# pkg = IMDS_PKG()
# # Step 1: Create an integer group
# integer_group = IntegerGroup()
# integer_group.paramgen(512)

# # Step 2: Choose a random element from the integer group
# element = integer_group.random()
# element2 = integer_group.random()

# element3 = element ^ element2


# # Print the result
# print("Random Element from Integer Group:", element)
# print("Random Element from Integer Group:", element2)
# print("Random Element from Integer Group:", element3)

# a = pkg.group.random(ZR)
# b = pkg.group.random(ZR)

# print(a)
# print(b)

# res = dir(pkg.group)
# print(res)