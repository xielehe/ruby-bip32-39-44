# -------------------
# 3. Mnemonic to Seed
# -------------------
require 'openssl'

mnemonic = "evoke anxiety humble credit travel unveil like cash oyster trade network pumpkin"
passphrase = "" # can leave this blank
puts "passphrase: #{passphrase}"

password = mnemonic
salt = "mnemonic#{passphrase}" # "mnemonic" is always used in the salt with optional passphrase appended to it
iterations = 2048
keylength = 64
digest = OpenSSL::Digest::SHA512.new

result = OpenSSL::PKCS5.pbkdf2_hmac(password, salt, iterations, keylength, digest)
seed = result.unpack("H*")[0] # convert to hexadecimal string
puts "seed: #{seed}" #=> 0155adf3aa524cd3b5e17fee130675a603e91252447b8f9803c47ac3be28000d8ae2960673dcf73301b3db5a4db1704b373278347b094e9be11319d4cf3a9764