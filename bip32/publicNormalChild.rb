require 'openssl' # HMAC
require 'ecdsa'

# --------------------------------
# Normal Child Extended Public Key
# --------------------------------
# m -------- p
#            |- p/0
#            |- p/1
#            |- p/3

parent_chain_code = "463223aac10fb13f291a1bc76bc26003d98da661cb76df61e750c139826dea8b"
parent_public_key = "0252c616d91a2488c1fd1f0f172e98f7d1f6e51f8f389b2f8d632a8b490d5f6da9"
i = 0 # child index number

if i >= 2**31
    raise "Can't create hardened child public keys from parent public keys."
end

# Prepare data and key to put through HMAC function
key = [parent_chain_code].pack("H*")
data = [parent_public_key].pack("H*") + [i].pack("N") # 32-bit unsigned, network (big-endian) byte order

hmac = OpenSSL::HMAC.hexdigest(OpenSSL::Digest::SHA512.new, key, data)
il = hmac[0..63]  # left side of intermediate key [32 bytes]
ir = hmac[64..-1] # right side of intermediate key [32 bytes]

# Chain code is last 32 bytes
child_chain_code = hmac[64..-1]

if il.to_i(16) >= ECDSA::Group::Secp256k1.order
    raise "Result of digest is greater than the order of the curve. Try the next index."
end

# Work out the child public key
point_hmac   = ECDSA::Group::Secp256k1.generator.multiply_by_scalar(il.to_i(16))                               # convert hmac il to a point
point_public = ECDSA::Format::PointOctetString.decode([parent_public_key].pack("H*"), ECDSA::Group::Secp256k1) # convert parent_public_key to a point
point = point_hmac.add_to_point(point_public)                                                                  # point addition

if (point == ECDSA::Group::Secp256k1.infinity)
    raise "Child public key point is at point of infinitiy. Try the next index."
end

child_public_key = ECDSA::Format::PointOctetString.encode(point, compression: true).unpack("H*")[0] # encode to compress public key

puts "child_chain_code:   #{child_chain_code}"
puts "child_public_key:   #{child_public_key}"