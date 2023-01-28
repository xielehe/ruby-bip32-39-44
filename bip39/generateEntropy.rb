# -------------------
# 1. Generate Entropy
# -------------------
require 'securerandom' # library for generating bytes of entropy

bytes = SecureRandom.random_bytes(16) # 16 bytes = 128 bits (1 byte = 8 bits)
entropy = bytes.unpack("B*").join     # convert bytes to a string of bits (base2)
puts entropy 

# 10100101011110000001001000000011000001001000001000110001110000110010100010011101010111001111010110001111000000101101001010110110