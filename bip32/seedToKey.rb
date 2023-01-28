require 'openssl' # HMAC
require 'ecdsa'   # private key to public key

# ----
# Seed
# ----
seed = "67f93560761e20617de26e0cb84f7234aaf373ed2e66295c3d7397e6d7ebe882ea396d5d293808b0defd7edd2babd4c091ad942e6a9351e6d075a29d4df872af"
puts "seed: #{seed}"
puts

# --------------------
# Generate Master Keys
# --------------------
# seed
# |
# m

# HMAC
hmac = OpenSSL::HMAC.hexdigest(OpenSSL::Digest::SHA512.new, "Bitcoin seed", [seed].pack("H*")) # digest, key, data
master_private_key = hmac[0..63] # left side of digest
master_chain_code = hmac[64..-1] # right side of digest

# > The SHA512-HMAC function is reused because it is already part of the standard elsewhere, but it takes a key in addition to the data being hashed.
# As the key can be arbitrary, we opted to use to make sure the key derivation was Bitcoin-specific. -- Pieter Wuille

# Get Public Key (multiply generator point by private key)
master_public_key = ECDSA::Group::Secp256k1.generator.multiply_by_scalar(master_private_key.to_i(16)) # multiply generator point by private key
master_public_key = ECDSA::Format::PointOctetString.encode(master_public_key, compression: true).unpack("H*")[0] # encode to compressed public key format

puts "master_chain_code:  #{master_chain_code}"  #=> 463223aac10fb13f291a1bc76bc26003d98da661cb76df61e750c139826dea8b
puts "master_private_key: #{master_private_key}" #=> f79bb0d317b310b261a55a8ab393b4c8a1aba6fa4d08aef379caba502d5d67f9
puts "master_public_key:  #{master_public_key}"  #=> 0252c616d91a2488c1fd1f0f172e98f7d1f6e51f8f389b2f8d632a8b490d5f6da9