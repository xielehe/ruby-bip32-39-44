# ----------------------
# 2. Entropy to Mnemonic
# ----------------------
entropy = "10100101011110000001001000000011000001001000001000110001110000110010100010011101010111001111010110001111000000101101001010110110"

# 1. Create checksum
require 'digest'
size = entropy.length / 32 # number of bits to take from hash of entropy (1 bit checksum for every 32 bits entropy)
sha256 = Digest::SHA256.digest([entropy].pack("B*")) # hash of entropy (in raw binary)
checksum = sha256.unpack("B*").join[0..size-1] # get desired number of bits
puts "checksum: #{checksum}"
# 2. Combine
full = entropy + checksum
puts "combined: #{full}"

# 3. Split in to strings of of 11 bits
pieces = full.scan(/.{11}/)

# 4. Get the wordlist as an array
wordlist = File.readlines("wordlist.txt")

# 5. Convert groups of bits to array of words
puts "words:"
sentence = []
pieces.each do |piece|
  i = piece.to_i(2)   # convert string of 11 bits to an integer
  word = wordlist[i]  # get the corresponding word from wordlist
  sentence << word.chomp # add to sentence (removing newline from end of word)
  puts "#{piece} #{i.to_s.rjust(4)} #{word}"
end

mnemonic = sentence.join(" ")
puts "mnemonic: #{mnemonic}" #=> "punch shock entire north file identify"
