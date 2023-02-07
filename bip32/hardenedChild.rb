require 'openssl' # HMAC
require 'ecdsa'   # private key to public key

# -----------------------------------
# Hardened Child Extended Private Key
# -----------------------------------
# m
# ...
# |- m/2147483648
# |- m/2147483649
# |- m/2147483650
# ...

parent_chain_code  = "aa274c0fea984574f19fdea0aa19541ceb16165f49ff3694969320424060bae2"
parent_private_key = "4743bae8512cc178df55d1b79bff1bb82aaf849ee09f7671827852b59f0ba471"
i = 2147483648   # child index number (must between 2**31 and 2**32-1)

# Prepare data and key to put through HMAC function
data = ["00"].pack("H*") + [parent_private_key].pack("H*") + [i].pack("N")  # 0x00 + private_key + index
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

puts "child_chain_code:   #{child_chain_code}"  #=> cb3c17166cc30eb7fdd11993fb7307531372e565cd7c7136cbfa4655622bc2be
puts "child_private_key:  #{child_private_key}" #=> 7272904512add56fef94c7b4cfc62bedd0632afbad680f2eb404e95f2d84cbfa
puts "child_public_key:   #{child_public_key}"  #=> 0355cff4a963ce259b08be9a864564caca210eb4eb35fcb75712e4bba7550efd95