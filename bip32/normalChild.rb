require 'openssl' # HMAC
require 'ecdsa'   # private key to public key

# ---------------------------------
# Normal Child Extended Private Key
# ---------------------------------
# m
# |- m/0
# |- m/1
# |- m/2
# ...

parent_chain_code  = "8b8b401d5e48e8c8ac1de1f5616cd68b18a6494afa1d7f52d38267b012b3b8d6"
parent_private_key = "d3ba84ebbc7fe777fa945fb6e81528f9da5639a47371d872ceb22f66b0e4810f"
parent_public_key  = "03b31438df24ba685e0ef4088c92b21e2efdb090a2829598fb21276ba1b5aacbe5"
i = 1 # child index number

# Prepare data and key to put through HMAC function
data = [parent_public_key].pack("H*") + [i].pack("N") # public key + index
key = [parent_chain_code].pack("H*") # chain code is key for hmac

hmac = OpenSSL::HMAC.hexdigest(OpenSSL::Digest::SHA512.new, key, data) # digest, key, data
il = hmac[0..63]  # left side of intermediate key [32 bytes]
ir = hmac[64..-1] # right side of intermediate key [32 bytes]

# Chain code is last 32 bytes
child_chain_code = ir

# Check the chain code is valid.
if child_chain_code.to_i(16) >= ECDSA::Group::Secp256k1.order
    raise "Chain code is greater than the order of the curve. Try the next index."
end

# Calculate child private key
child_private_key = (il.to_i(16) + parent_private_key.to_i(16)) % ECDSA::Group::Secp256k1.order # (il + parent_key) % n
child_private_key = child_private_key.to_s(16).rjust(64, '0') # convert to hex (and make sure it's 32 bytes long)

# Work out the corresponding public key too (optional)
child_public_key = ECDSA::Group::Secp256k1.generator.multiply_by_scalar(child_private_key.to_i(16)) # work out the public key for this too
child_public_key = ECDSA::Format::PointOctetString.encode(child_public_key, compression: true).unpack("H*")[0] # encode to compressed public key format

# Results
puts "child_chain_code:   #{child_chain_code}"  #=> 05aae71d7c080474efaab01fa79e96f4c6cfe243237780b0df4bc36106228e31
puts "child_private_key:  #{child_private_key}" #=> 39f329fedba2a68e2a804fcd9aeea4104ace9080212a52ce8b52c1fb89850c72
puts "child_public_key:   #{child_public_key}"  #=> 030204d3503024160e8303c0042930ea92a9d671de9aa139c1867353f6b6664e59