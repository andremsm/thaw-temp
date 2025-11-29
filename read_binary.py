import mmap
import binascii
import json
import subprocess


def get_qbkey(filename: str) -> str:
	result = subprocess.run(["qbkey_argv.exe", filename], stdout=subprocess.PIPE)
	return str(result.stdout).split("Checksum: 0x")[1].split("\\")[0].lower()


def print_hex(hex: str):
	"""
	Prints the hexadecimal value in the format 0x0000000f.
	"""
	print("0x" + "%0*x" % (8, int(hex, 16)))


def format_hex(hex: str) -> str:
	"""
	Returns the hexadecimal value in the format 0000000f.
	"""
	return "%0*x" % (8, int(hex, 16))


def reverse_hex(hex_num: str) -> str:
	"""
	Returns the reversed hexadecimal value.

	Example:

	    Input:  a1b2c3d4
	    Output: d4c3b2a1
	"""
	return hex_num[6:8] + hex_num[4:6] + hex_num[2:4] + hex_num[0:2]


def length_StructItem(string: str) -> int:
	"""
	Returns the minimum number of bytes needed to store the string, which
	is the length of the StructItem.

	"""

	if type(string) == int:
		return 0 + 16

	if len(string) < 4:
		if len(string) >= 2:
			return 4 + 16
		if len(string) < 2:
			return 0 + 16
		"""
        i = 0
        while i * 4 <= len(string):
            i += 0.5
        return i * 4 + 16
        """

	i = 1
	while i * 4 <= len(string):
		i += 1
	print(len(string))
	return i * 4 + 16


def length_StructHeader(band: str, song: str, genre_int: int, file: str) -> int:
	"""
	Returns the length of the struct header, in bytes.
	"""
	length_band = length_StructItem(band)
	length_song = length_StructItem(song)
	length_genre_int = 16
	length_file = length_StructItem(file)
	if "Still Take You Home" in song:
		print(length_band)
		print(length_song)
		print(length_genre_int)
		print(length_file)

	return length_band + length_song + length_genre_int + length_file + 8


def increment_hex(hex_value: str, inc: int) -> str:
	hex_reversed = reverse_hex(hex_value)
	"""hex_reversed = reverse_hex(hex_reversed)
    print(hex_reversed+"\n\n")
    print(f"adding {int(hex_reversed, 16)} to {int(hex(inc), 16)}\n\n")
    print(f"result: {int(hex_reversed, 16) + int(hex(inc), 16)}")"""
	hex_incremented = int(hex_reversed, 16) + int(hex(inc), 16) + 4
	return reverse_hex(format_hex(hex(hex_incremented)))


def hex_plus_plus(hex_value: str) -> str:
	hex_reversed = reverse_hex(hex_value)
	hex_incremented = int(hex_reversed, 16) + 1
	return reverse_hex(format_hex(hex(hex_incremented)))


def insert_new_byte(mm: mmap.mmap, new_byte_str: str, offset: int):
	insert_byte = bytearray.fromhex(new_byte_str)
	# Read the data from the current offset to the end of the file
	data = mm[offset:]
	# Resize the memory-mapped file if necessary
	mm.resize(len(mm) + len(insert_byte))
	# Write the bytes to insert
	mm[offset : offset + 4] = insert_byte
	# Write back the previously read data
	mm[offset + 4 :] = data


def insert_full_song(mm_wad: mmap.mmap, mm_song: mmap.mmap):
	data = mm_song[0:]
	offset = len(mm_wad)
	mm_wad.resize(len(mm_wad) + len(data))
	mm_wad[offset:] = data


def string_to_hex_array(string: str) -> list:
	hex_byte = binascii.hexlify(string.encode())
	hex_str = str(hex_byte).split("'")[1]

	deconstructed_hex = []
	i = 0
	j = 8
	while j <= len(hex_str):
		deconstructed_hex.append(hex_str[i:j])
		i += 8
		j += 8
	if j - 8 != len(hex_str):
		last_chars = hex_str[i : len(hex_str)]
		while len(last_chars) < 8:
			last_chars += "00"
		deconstructed_hex.append(last_chars)
	else:
		deconstructed_hex.append("00000000")

	return deconstructed_hex


def insert_large_hex(mm: mmap.mmap, hex_str: str, offset: int) -> int:
	offset_bak = offset

	deconstructed_hex = string_to_hex_array(hex_str)
	for hex_part in deconstructed_hex:
		insert_new_byte(mm, hex_part, offset)
		offset += 4
	if offset > offset_bak:
		offset -= 4
	return offset


def padded_length(string: str) -> int:
	return len(string_to_hex_array(string)) * 4


def get_song_genre_hex(song_type: int) -> str:
	"""
	I'm presuming this value won't be higher than 9. At least for me it won't be higher than 2.
	"""
	return "0" + str(song_type) + "000000"
	pass


def update_pak_file(header_length: int):
	"""
	All updates on this file are just incrementing some specific values
	by header_length.
	"""
	with open("qb.pak.wpc", "r+b") as f:
		mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_WRITE)
		offset = 13056
		for i in range(offset, len(mm)):
			hex_byte = binascii.hexlify(bytearray(mm[offset : offset + 4]))
			hex_str = str(hex_byte).split("'")[1]

			if hex_str == "c405f5a7":
				offset += 4
				if offset == 13060:
					offset += 4
					hex_to_update_byte = binascii.hexlify(bytearray(mm[offset : offset + 4]))
					hex_to_update_str = str(hex_to_update_byte).split("'")[1]
					hex_incremented_str = increment_hex(hex_to_update_str, header_length)
					mm[offset : offset + 4] = bytearray.fromhex(hex_incremented_str)
					continue
				hex_to_update_byte = binascii.hexlify(bytearray(mm[offset : offset + 4]))
				hex_to_update_str = str(hex_to_update_byte).split("'")[1]
				hex_incremented_str = increment_hex(hex_to_update_str, header_length)
				mm[offset : offset + 4] = bytearray.fromhex(hex_incremented_str)
			if hex_str == "5f5624b5":
				offset += 4
				hex_to_update_byte = binascii.hexlify(bytearray(mm[offset : offset + 4]))
				hex_to_update_str = str(hex_to_update_byte).split("'")[1]
				hex_incremented_str = increment_hex(hex_to_update_str, header_length)
				mm[offset : offset + 4] = bytearray.fromhex(hex_incremented_str)
			offset += 4
		mm.close()


def update_pab_file(
	header_length: int, band_name: str, song_title: str, song_type: int, song_file
):
	"""# deprecated"""
	with open("qb.pab.wpc", "r+b") as f:
		mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_WRITE)

		# First update is at this offset, increment it by header_length
		offset = 768516

		hex_to_update_byte = binascii.hexlify(bytearray(mm[offset : offset + 4]))
		hex_to_update_str = str(hex_to_update_byte).split("'")[1]
		hex_incremented_str = increment_hex(hex_to_update_str, header_length)
		mm[offset : offset + 4] = bytearray.fromhex(hex_incremented_str)

		# Second update is here, increment it by 1 (number of songs)
		offset = 768940

		hex_to_update_byte = binascii.hexlify(bytearray(mm[offset : offset + 4]))
		hex_to_update_str = str(hex_to_update_byte).split("'")[1]
		hex_incremented_str = hex_plus_plus(hex_to_update_str)
		mm[offset : offset + 4] = bytearray.fromhex(hex_incremented_str)
		# Save the number of songs
		n_songs = int(reverse_hex(hex_incremented_str), 16) - 1
		# print(n_songs)

		# Several offsets (number of songs) that need to be incremented by 4
		offset = 768948
		for i in range(0, n_songs):
			# debug
			# hex_byte = binascii.hexlify(bytearray(mm[offset : offset + 4]))
			# hex_str = str(hex_byte).split("'")[1]
			# if i == 0 or i == n_songs - 1:
			# 	print(hex_str)

			hex_to_update_byte = binascii.hexlify(bytearray(mm[offset : offset + 4]))
			hex_to_update_str = str(hex_to_update_byte).split("'")[1]
			hex_incremented_str = increment_hex(hex_to_update_str, 0)
			mm[offset : offset + 4] = bytearray.fromhex(hex_incremented_str)

			offset += 4

		# Up next a new hex must be inserted, specifically:
		# previous_4bytes + (previous_4bytes - previousprevious_4bytes) + 8
		# This value represents the position of the StructHeader of the
		# new item
		hex_byte = binascii.hexlify(bytearray(mm[offset - 4 : offset]))
		prev4 = str(hex_byte).split("'")[1]
		# print(reverse_hex(prev4))
		hex_byte = binascii.hexlify(bytearray(mm[offset - 8 : offset - 4]))
		prevprev4 = reverse_hex(str(hex_byte).split("'")[1])

		parenthesis = reverse_hex(increment_hex(prev4, -int(prevprev4, 16) - 4))
		insert_str = increment_hex(prev4, int(parenthesis, 16) - 4)
		pos_StructHeader_str = insert_str
		insert_byte = bytearray.fromhex(insert_str)
		# print(insert_str)
		# print(insert_byte)
		# mm.move(offset + 4, offset, len(mm[offset:]) - 1)
		# mm[offset : offset + 4] = insert_byte

		# Read the data from the current offset to the end of the file
		data = mm[offset:]
		# Resize the memory-mapped file if necessary
		mm.resize(len(mm) + len(insert_byte))
		# Move back to the insertion point
		# mm.seek(offset)
		# Write the bytes to insert
		# mm.write(insert_byte)
		mm[offset : offset + 4] = insert_byte
		# Write back the previously read data
		# mm.write(data)
		# print(len(mm[offset + 4 :]))
		# print(len(data))
		mm[offset + 4 :] = data

		# Plus 4 here
		offset = 769212
		hex_to_update_byte = binascii.hexlify(bytearray(mm[offset : offset + 4]))
		hex_to_update_str = str(hex_to_update_byte).split("'")[1]
		hex_incremented_str = increment_hex(hex_to_update_str, 0)
		mm[offset : offset + 4] = bytearray.fromhex(hex_incremented_str)

		# Plus 4 here
		offset = 769224
		hex_to_update_byte = binascii.hexlify(bytearray(mm[offset : offset + 4]))
		hex_to_update_str = str(hex_to_update_byte).split("'")[1]
		hex_incremented_str = increment_hex(hex_to_update_str, 0)
		mm[offset : offset + 4] = bytearray.fromhex(hex_incremented_str)

		# Plus 4 here
		offset = 769228
		hex_to_update_byte = binascii.hexlify(bytearray(mm[offset : offset + 4]))
		hex_to_update_str = str(hex_to_update_byte).split("'")[1]
		hex_incremented_str = increment_hex(hex_to_update_str, 0)
		mm[offset : offset + 4] = bytearray.fromhex(hex_incremented_str)

		# Loop through each song, updating the required values
		for i in range(0, n_songs):
			hex_byte = binascii.hexlify(bytearray(mm[offset : offset + 4]))
			hex_str = str(hex_byte).split("'")[1]

			# Find the band name terminator hex: 33 25 3E A4
			while hex_str != "33253ea4":
				offset += 4
				hex_byte = binascii.hexlify(bytearray(mm[offset : offset + 4]))
				hex_str = str(hex_byte).split("'")[1]

			# Increment the two offsets that follow it by 4
			offset += 4
			hex_to_update_byte = binascii.hexlify(bytearray(mm[offset : offset + 4]))
			hex_to_update_str = str(hex_to_update_byte).split("'")[1]
			hex_incremented_str = increment_hex(hex_to_update_str, 0)
			mm[offset : offset + 4] = bytearray.fromhex(hex_incremented_str)
			offset += 4
			hex_to_update_byte = binascii.hexlify(bytearray(mm[offset : offset + 4]))
			hex_to_update_str = str(hex_to_update_byte).split("'")[1]
			hex_incremented_str = increment_hex(hex_to_update_str, 0)
			mm[offset : offset + 4] = bytearray.fromhex(hex_incremented_str)

			# Song name starts here
			offset += 4
			hex_byte = binascii.hexlify(bytearray(mm[offset : offset + 4]))
			hex_str = str(hex_byte).split("'")[1]
			# Either the string won't fill up an entire 4 byte offset, and
			# be followed by 00 03 00 00, or it does fill it up and is followed
			# by 00 00 00 00 00 03 00 00
			# Example:
			#  W  e  '  r  e     G  o  n  n  a     F  i  g  h  t
			# 57 65 27 72 65 20 47 6F 6E 6E 61 20 46 69 67 68 74 00 00 00 00 03 00 00
			# =========== =========== =========== =========== =========== ===========
			# does not fill up all 4 bytes, therefore it's followed by    00 03 00 00
			#  S  u  n     o  f     P  e  a  r  l
			# 53 75 6E 20 6F 66 20 50 65 61 72 6C 00 00 00 00 00 03 00 00
			# =========== =========== =========== =========== ===========
			# fills up all 4 bytes, therefore it's followed by 00 00 00 00 00 03 00 00
			while "00" not in hex_str:
				offset += 4
				hex_byte = binascii.hexlify(bytearray(mm[offset : offset + 4]))
				hex_str = str(hex_byte).split("'")[1]
			# Once it finds an offset that has the value 00 in it, the next one will be
			# 00 03 00 00, and the next increment (+4) will be two offsets after this one
			offset += 16
			hex_to_update_byte = binascii.hexlify(bytearray(mm[offset : offset + 4]))
			hex_to_update_str = str(hex_to_update_byte).split("'")[1]
			hex_incremented_str = increment_hex(hex_to_update_str, 0)
			mm[offset : offset + 4] = bytearray.fromhex(hex_incremented_str)
			# Next increment (+4) will be after this value: F0 74 AB F4
			# Which is +12 after the previous one
			offset += 12
			hex_to_update_byte = binascii.hexlify(bytearray(mm[offset : offset + 4]))
			hex_to_update_str = str(hex_to_update_byte).split("'")[1]
			hex_incremented_str = increment_hex(hex_to_update_str, 0)
			mm[offset : offset + 4] = bytearray.fromhex(hex_incremented_str)

			# File path must be found now. It's always music\vag\songs\SONG_FILE
			# so the hex equivalent to music\vag\songs\ must be found:
			#  m  u  s  i    c  \  v  a    g  \  s  o    n  g  s  \
			# 6D 75 73 69   63 5C 76 61   67 5C 73 6F   6E 67 73 5C
			offset += 4

			hex_byte = binascii.hexlify(bytearray(mm[offset : offset + 4]))
			musi = str(hex_byte).split("'")[1]
			hex_byte = binascii.hexlify(bytearray(mm[offset + 4 : offset + 8]))
			cva = str(hex_byte).split("'")[1]
			hex_byte = binascii.hexlify(bytearray(mm[offset + 8 : offset + 12]))
			gso = str(hex_byte).split("'")[1]
			hex_byte = binascii.hexlify(bytearray(mm[offset + 12 : offset + 16]))
			ngs = str(hex_byte).split("'")[1]

			while musi + cva + gso + ngs != "6d757369635c7661675c736f6e67735c":
				offset += 4
				hex_byte = binascii.hexlify(bytearray(mm[offset : offset + 4]))
				musi = str(hex_byte).split("'")[1]
				hex_byte = binascii.hexlify(bytearray(mm[offset + 4 : offset + 8]))
				cva = str(hex_byte).split("'")[1]
				hex_byte = binascii.hexlify(bytearray(mm[offset + 8 : offset + 12]))
				gso = str(hex_byte).split("'")[1]
				hex_byte = binascii.hexlify(bytearray(mm[offset + 12 : offset + 16]))
				ngs = str(hex_byte).split("'")[1]

			# Anything that comes after this is the file name.
			# Similarly to the song name, the string ends in 00 or is followed by
			# 00 00 00 00, and after that 00 00 01 00
			offset += 16
			hex_byte = binascii.hexlify(bytearray(mm[offset : offset + 4]))
			hex_str = str(hex_byte).split("'")[1]
			while "00" not in hex_str:
				offset += 4
				hex_byte = binascii.hexlify(bytearray(mm[offset : offset + 4]))
				hex_str = str(hex_byte).split("'")[1]

			# If this was the last song, no more updates after this point.
			if i == n_songs - 1:
				break
			# Else:

			# Hex after 00 00 01 00 must be incremented by 4
			offset += 8
			hex_to_update_byte = binascii.hexlify(bytearray(mm[offset : offset + 4]))
			hex_to_update_str = str(hex_to_update_byte).split("'")[1]
			hex_incremented_str = increment_hex(hex_to_update_str, 0)
			mm[offset : offset + 4] = bytearray.fromhex(hex_incremented_str)
			# Find this "terminator" hex: 14 5D 20 B7
			hex_byte = binascii.hexlify(bytearray(mm[offset : offset + 4]))
			hex_str = str(hex_byte).split("'")[1]
			while hex_str != "145d20b7":
				offset += 4
				hex_byte = binascii.hexlify(bytearray(mm[offset : offset + 4]))
				hex_str = str(hex_byte).split("'")[1]
			# Next 2 hexes must be incremented by 4
			offset += 4
			hex_to_update_byte = binascii.hexlify(bytearray(mm[offset : offset + 4]))
			hex_to_update_str = str(hex_to_update_byte).split("'")[1]
			hex_incremented_str = increment_hex(hex_to_update_str, 0)
			mm[offset : offset + 4] = bytearray.fromhex(hex_incremented_str)
			offset += 4
			hex_to_update_byte = binascii.hexlify(bytearray(mm[offset : offset + 4]))
			hex_to_update_str = str(hex_to_update_byte).split("'")[1]
			hex_incremented_str = increment_hex(hex_to_update_str, 0)
			mm[offset : offset + 4] = bytearray.fromhex(hex_incremented_str)
			pass

		# Inserting a new song

		# First thing that must be done, insert 00 00 01 00 at the next offset
		offset += 4
		insert_new_byte(mm, "00000100", offset)

		# Next, add 8 to the StructHeader and insert it at the next offset
		# This is the position of the band name
		offset += 4
		pos_StructHeader_inc = increment_hex(pos_StructHeader_str, 4)
		insert_new_byte(mm, pos_StructHeader_inc, offset)

		# Then, insert 00 07 00 00 followed by 14 5D 20 B7
		offset += 4
		insert_new_byte(mm, "00070000", offset)
		offset += 4
		insert_new_byte(mm, "145d20b7", offset)

		# After that, insert pos_StructHeader_inc + 0x10
		offset += 4
		pos_StructHeader_inc2 = increment_hex(pos_StructHeader_inc, 12)
		insert_new_byte(mm, pos_StructHeader_inc2, offset)

		# Then, insert pos_StructHeader_inc + the number of bytes needed to fit band_name
		offset += 4
		pos_StructHeader_inc = increment_hex(
			pos_StructHeader_inc, length_StructItem(band_name) - 4
		)
		pos_SongTitle = pos_StructHeader_inc
		insert_new_byte(mm, pos_StructHeader_inc, offset)

		# Insert the band name (some details explained in the function)
		offset += 4
		offset = insert_large_hex(mm, band_name, offset)

		# Then, insert 00 07 00 00 followed by 33 25 3e a4
		offset += 4
		insert_new_byte(mm, "00070000", offset)
		offset += 4
		insert_new_byte(mm, "33253ea4", offset)

		# Afterwards, insert pos_StructHeader_inc + 0x10
		offset += 4
		pos_StructHeader_inc = increment_hex(pos_StructHeader_inc, 12)
		insert_new_byte(mm, pos_StructHeader_inc, offset)

		# Then, insert pos_SongTitle + the number of bytes needed to fit song_title
		offset += 4
		pos_SongTitle_inc = increment_hex(pos_SongTitle, length_StructItem(song_title) - 4)
		insert_new_byte(mm, pos_SongTitle_inc, offset)

		# Insert the song title (some details explained in the function)
		offset += 4
		offset = insert_large_hex(mm, song_title, offset)

		# Insert 00 03 00 00 and 07 cc af 7c
		offset += 4
		insert_new_byte(mm, "00030000", offset)
		offset += 4
		insert_new_byte(mm, "07ccaf7c", offset)

		# Insert the song type (00 00 00 00 = punk, 01 00 00 00 = hiphip, 02 00 00 00 = rock/other)
		offset += 4
		genre = get_song_genre_hex(song_type)
		insert_new_byte(mm, genre, offset)

		# (rewrite this later) insert the position of the path to the song file, which is the position of the music type + 0x10
		offset += 4
		pos_SongTitle_inc = increment_hex(pos_SongTitle_inc, 12)
		insert_new_byte(mm, pos_SongTitle_inc, offset)

		# then insert these ints: 00 07 00 00 F0 74 AB F4
		offset += 4
		insert_new_byte(mm, "00070000", offset)
		offset += 4
		insert_new_byte(mm, "f074abf4", offset)

		# then insert path position + 10
		offset += 4
		pos_SongTitle_inc = increment_hex(pos_SongTitle_inc, 12)
		insert_new_byte(mm, pos_SongTitle_inc, offset)

		# then 00 00 00 00
		offset += 4
		insert_new_byte(mm, "00000000", offset)

		# finally, insert path to file
		offset += 4
		offset = insert_large_hex(mm, "music\\vag\\songs\\" + song_file, offset)

		# Some more updates (increments by header_length)

		while hex_str != "91d5c799":
			offset += 4
			hex_byte = binascii.hexlify(bytearray(mm[offset : offset + 4]))
			hex_str = str(hex_byte).split("'")[1]

		offset += 4
		hex_to_update_byte = binascii.hexlify(bytearray(mm[offset : offset + 4]))
		hex_to_update_str = str(hex_to_update_byte).split("'")[1]
		hex_incremented_str = increment_hex(hex_to_update_str, header_length)
		mm[offset : offset + 4] = bytearray.fromhex(hex_incremented_str)

		while hex_str != "0f000000":
			offset += 4
			hex_byte = binascii.hexlify(bytearray(mm[offset : offset + 4]))
			hex_str = str(hex_byte).split("'")[1]

		for i in range(0, 16):
			offset += 4
			hex_to_update_byte = binascii.hexlify(bytearray(mm[offset : offset + 4]))
			hex_to_update_str = str(hex_to_update_byte).split("'")[1]
			hex_incremented_str = increment_hex(hex_to_update_str, header_length)
			mm[offset : offset + 4] = bytearray.fromhex(hex_incremented_str)

		offset += 8
		hex_to_update_byte = binascii.hexlify(bytearray(mm[offset : offset + 4]))
		hex_to_update_str = str(hex_to_update_byte).split("'")[1]
		hex_incremented_str = increment_hex(hex_to_update_str, header_length)
		mm[offset : offset + 4] = bytearray.fromhex(hex_incremented_str)

		offset += 12
		hex_to_update_byte = binascii.hexlify(bytearray(mm[offset : offset + 4]))
		hex_to_update_str = str(hex_to_update_byte).split("'")[1]
		hex_incremented_str = increment_hex(hex_to_update_str, header_length)
		mm[offset : offset + 4] = bytearray.fromhex(hex_incremented_str)

		for i in range(0, 14):
			while hex_str != "00000100":
				offset += 4
				hex_byte = binascii.hexlify(bytearray(mm[offset : offset + 4]))
				hex_str = str(hex_byte).split("'")[1]

			offset += 4
			hex_to_update_byte = binascii.hexlify(bytearray(mm[offset : offset + 4]))
			hex_to_update_str = str(hex_to_update_byte).split("'")[1]
			hex_incremented_str = increment_hex(hex_to_update_str, header_length)
			mm[offset : offset + 4] = bytearray.fromhex(hex_incremented_str)

			while hex_str != "f074abf4":
				offset += 4
				hex_byte = binascii.hexlify(bytearray(mm[offset : offset + 4]))
				hex_str = str(hex_byte).split("'")[1]

			offset += 4
			hex_to_update_byte = binascii.hexlify(bytearray(mm[offset : offset + 4]))
			hex_to_update_str = str(hex_to_update_byte).split("'")[1]
			hex_incremented_str = increment_hex(hex_to_update_str, header_length)
			mm[offset : offset + 4] = bytearray.fromhex(hex_incremented_str)

		"""
		for i in range(offset, len(mm)):
			hex_byte = binascii.hexlify(bytearray(mm[offset : offset + 4]))
			hex_str = str(hex_byte).split("'")[1]
		"""

		mm.close()


global_header_length = 0


def update_wpc_file(
	header_length: int, band_name: str, song_title: str, song_type: int, song_file
):
	global global_header_length
	with open(
		"music.qb.wpc.qb.wpc.qb.wpc",
		"r+b",
	) as f:
		mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_WRITE)

		# First update is at this offset, increment it by header_length
		offset = 4

		hex_to_update_byte = binascii.hexlify(bytearray(mm[offset : offset + 4]))
		hex_to_update_str = str(hex_to_update_byte).split("'")[1]
		hex_incremented_str = increment_hex(hex_to_update_str, header_length)
		mm[offset : offset + 4] = bytearray.fromhex(hex_incremented_str)

		# Second update is here, increment it by 1 (number of songs)
		offset = 428

		hex_to_update_byte = binascii.hexlify(bytearray(mm[offset : offset + 4]))
		hex_to_update_str = str(hex_to_update_byte).split("'")[1]
		hex_incremented_str = hex_plus_plus(hex_to_update_str)
		mm[offset : offset + 4] = bytearray.fromhex(hex_incremented_str)
		# Save the number of songs
		n_songs = int(reverse_hex(hex_incremented_str), 16) - 1
		# print(n_songs)

		# Several offsets (number of songs) that need to be incremented by 4
		offset = 436
		for i in range(0, n_songs):
			# debug
			# hex_byte = binascii.hexlify(bytearray(mm[offset : offset + 4]))
			# hex_str = str(hex_byte).split("'")[1]
			# if i == 0 or i == n_songs - 1:
			# 	print(hex_str)

			hex_to_update_byte = binascii.hexlify(bytearray(mm[offset : offset + 4]))
			hex_to_update_str = str(hex_to_update_byte).split("'")[1]
			hex_incremented_str = increment_hex(hex_to_update_str, 0)
			mm[offset : offset + 4] = bytearray.fromhex(hex_incremented_str)

			offset += 4

		# Up next a new hex must be inserted, specifically:
		# previous_4bytes + (previous_4bytes - previousprevious_4bytes) + 8
		# This value represents the position of the StructHeader of the
		# new item
		# actually prev4 + headerlength?
		header_length = length_StructHeader(band, song, 2, f"music\\vag\\songs\\{song_file}")

		if global_header_length == 0:
			global_header_length = header_length
		else:
			temp = header_length
			header_length = global_header_length
			global_header_length = temp

		hex_byte = binascii.hexlify(bytearray(mm[offset - 4 : offset]))
		prev4 = str(hex_byte).split("'")[1]
		# print(reverse_hex(prev4))
		hex_byte = binascii.hexlify(bytearray(mm[offset - 8 : offset - 4]))
		prevprev4 = reverse_hex(str(hex_byte).split("'")[1])

		parenthesis = reverse_hex(increment_hex(prev4, -int(prevprev4, 16) - 4))
		print(header_length)
		print(int(parenthesis, 16))
		temp = int(parenthesis, 16)
		insert_str = increment_hex(prev4, header_length - 4)
		pos_StructHeader_str = insert_str

		insert_new_byte(mm, insert_str, offset)

		"""
		insert_byte = bytearray.fromhex(insert_str)
		# print(insert_str)
		# print(insert_byte)
		# mm.move(offset + 4, offset, len(mm[offset:]) - 1)
		# mm[offset : offset + 4] = insert_byte

		# Read the data from the current offset to the end of the file
		data = mm[offset:]
		# Resize the memory-mapped file if necessary
		mm.resize(len(mm) + len(insert_byte))
		# Move back to the insertion point
		# mm.seek(offset)
		# Write the bytes to insert
		# mm.write(insert_byte)
		mm[offset : offset + 4] = insert_byte
		# Write back the previously read data
		# mm.write(data)
		# print(len(mm[offset + 4 :]))
		# print(len(data))
		mm[offset + 4 :] = data
		"""

		# Plus 4 here
		offset += 8
		hex_to_update_byte = binascii.hexlify(bytearray(mm[offset : offset + 4]))
		hex_to_update_str = str(hex_to_update_byte).split("'")[1]
		hex_incremented_str = increment_hex(hex_to_update_str, 0)
		mm[offset : offset + 4] = bytearray.fromhex(hex_incremented_str)

		# Plus 4 here
		offset += 12
		hex_to_update_byte = binascii.hexlify(bytearray(mm[offset : offset + 4]))
		hex_to_update_str = str(hex_to_update_byte).split("'")[1]
		hex_incremented_str = increment_hex(hex_to_update_str, 0)
		mm[offset : offset + 4] = bytearray.fromhex(hex_incremented_str)

		# Plus 4 here
		offset += 4
		hex_to_update_byte = binascii.hexlify(bytearray(mm[offset : offset + 4]))
		hex_to_update_str = str(hex_to_update_byte).split("'")[1]
		hex_incremented_str = increment_hex(hex_to_update_str, 0)
		mm[offset : offset + 4] = bytearray.fromhex(hex_incremented_str)

		# Loop through each song, updating the required values
		for i in range(0, n_songs):
			hex_byte = binascii.hexlify(bytearray(mm[offset : offset + 4]))
			hex_str = str(hex_byte).split("'")[1]

			# Find the band name terminator hex: 33 25 3E A4
			while hex_str != "33253ea4":
				offset += 4
				hex_byte = binascii.hexlify(bytearray(mm[offset : offset + 4]))
				hex_str = str(hex_byte).split("'")[1]

			# Increment the two offsets that follow it by 4
			offset += 4
			hex_to_update_byte = binascii.hexlify(bytearray(mm[offset : offset + 4]))
			hex_to_update_str = str(hex_to_update_byte).split("'")[1]
			hex_incremented_str = increment_hex(hex_to_update_str, 0)
			mm[offset : offset + 4] = bytearray.fromhex(hex_incremented_str)
			offset += 4
			hex_to_update_byte = binascii.hexlify(bytearray(mm[offset : offset + 4]))
			hex_to_update_str = str(hex_to_update_byte).split("'")[1]
			hex_incremented_str = increment_hex(hex_to_update_str, 0)
			mm[offset : offset + 4] = bytearray.fromhex(hex_incremented_str)

			# Song name starts here
			offset += 4
			hex_byte = binascii.hexlify(bytearray(mm[offset : offset + 4]))
			hex_str = str(hex_byte).split("'")[1]
			# Either the string won't fill up an entire 4 byte offset, and
			# be followed by 00 03 00 00, or it does fill it up and is followed
			# by 00 00 00 00 00 03 00 00
			# Example:
			#  W  e  '  r  e     G  o  n  n  a     F  i  g  h  t
			# 57 65 27 72 65 20 47 6F 6E 6E 61 20 46 69 67 68 74 00 00 00 00 03 00 00
			# =========== =========== =========== =========== =========== ===========
			# does not fill up all 4 bytes, therefore it's followed by    00 03 00 00
			#  S  u  n     o  f     P  e  a  r  l
			# 53 75 6E 20 6F 66 20 50 65 61 72 6C 00 00 00 00 00 03 00 00
			# =========== =========== =========== =========== ===========
			# fills up all 4 bytes, therefore it's followed by 00 00 00 00 00 03 00 00
			while "00" not in hex_str:
				offset += 4
				hex_byte = binascii.hexlify(bytearray(mm[offset : offset + 4]))
				hex_str = str(hex_byte).split("'")[1]
			# Once it finds an offset that has the value 00 in it, the next one will be
			# 00 03 00 00, and the next increment (+4) will be two offsets after this one
			offset += 16
			hex_to_update_byte = binascii.hexlify(bytearray(mm[offset : offset + 4]))
			hex_to_update_str = str(hex_to_update_byte).split("'")[1]
			hex_incremented_str = increment_hex(hex_to_update_str, 0)
			mm[offset : offset + 4] = bytearray.fromhex(hex_incremented_str)
			# Next increment (+4) will be after this value: F0 74 AB F4
			# Which is +12 after the previous one
			offset += 12
			hex_to_update_byte = binascii.hexlify(bytearray(mm[offset : offset + 4]))
			hex_to_update_str = str(hex_to_update_byte).split("'")[1]
			hex_incremented_str = increment_hex(hex_to_update_str, 0)
			mm[offset : offset + 4] = bytearray.fromhex(hex_incremented_str)

			# File path must be found now. It's always music\vag\songs\SONG_FILE
			# so the hex equivalent to music\vag\songs\ must be found:
			#  m  u  s  i    c  \  v  a    g  \  s  o    n  g  s  \
			# 6D 75 73 69   63 5C 76 61   67 5C 73 6F   6E 67 73 5C
			offset += 4

			hex_byte = binascii.hexlify(bytearray(mm[offset : offset + 4]))
			musi = str(hex_byte).split("'")[1]
			hex_byte = binascii.hexlify(bytearray(mm[offset + 4 : offset + 8]))
			cva = str(hex_byte).split("'")[1]
			hex_byte = binascii.hexlify(bytearray(mm[offset + 8 : offset + 12]))
			gso = str(hex_byte).split("'")[1]
			hex_byte = binascii.hexlify(bytearray(mm[offset + 12 : offset + 16]))
			ngs = str(hex_byte).split("'")[1]

			while musi + cva + gso + ngs != "6d757369635c7661675c736f6e67735c":
				offset += 4
				hex_byte = binascii.hexlify(bytearray(mm[offset : offset + 4]))
				musi = str(hex_byte).split("'")[1]
				hex_byte = binascii.hexlify(bytearray(mm[offset + 4 : offset + 8]))
				cva = str(hex_byte).split("'")[1]
				hex_byte = binascii.hexlify(bytearray(mm[offset + 8 : offset + 12]))
				gso = str(hex_byte).split("'")[1]
				hex_byte = binascii.hexlify(bytearray(mm[offset + 12 : offset + 16]))
				ngs = str(hex_byte).split("'")[1]

			# Anything that comes after this is the file name.
			# Similarly to the song name, the string ends in 00 or is followed by
			# 00 00 00 00, and after that 00 00 01 00
			offset += 16
			hex_byte = binascii.hexlify(bytearray(mm[offset : offset + 4]))
			hex_str = str(hex_byte).split("'")[1]
			while "00" not in hex_str:
				offset += 4
				hex_byte = binascii.hexlify(bytearray(mm[offset : offset + 4]))
				hex_str = str(hex_byte).split("'")[1]

			# If this was the last song, no more updates after this point.
			if i == n_songs - 1:
				break
			# Else:

			# Hex after 00 00 01 00 must be incremented by 4
			offset += 8
			hex_to_update_byte = binascii.hexlify(bytearray(mm[offset : offset + 4]))
			hex_to_update_str = str(hex_to_update_byte).split("'")[1]
			hex_incremented_str = increment_hex(hex_to_update_str, 0)
			mm[offset : offset + 4] = bytearray.fromhex(hex_incremented_str)
			# Find this "terminating" hex: 14 5D 20 B7
			hex_byte = binascii.hexlify(bytearray(mm[offset : offset + 4]))
			hex_str = str(hex_byte).split("'")[1]
			while hex_str != "145d20b7":
				offset += 4
				hex_byte = binascii.hexlify(bytearray(mm[offset : offset + 4]))
				hex_str = str(hex_byte).split("'")[1]
			# Next 2 hexes must be incremented by 4
			offset += 4
			hex_to_update_byte = binascii.hexlify(bytearray(mm[offset : offset + 4]))
			hex_to_update_str = str(hex_to_update_byte).split("'")[1]
			hex_incremented_str = increment_hex(hex_to_update_str, 0)
			mm[offset : offset + 4] = bytearray.fromhex(hex_incremented_str)
			offset += 4
			hex_to_update_byte = binascii.hexlify(bytearray(mm[offset : offset + 4]))
			hex_to_update_str = str(hex_to_update_byte).split("'")[1]
			hex_incremented_str = increment_hex(hex_to_update_str, 0)
			mm[offset : offset + 4] = bytearray.fromhex(hex_incremented_str)
			pass

		# Inserting a new song

		# First thing that must be done, insert 00 00 01 00 at the next offset
		offset += 4
		insert_new_byte(mm, "00000100", offset)

		# Next, add 8 to the StructHeader and insert it at the next offset
		# This is the position of the band name (actually 4?) (actually 8???)
		offset += 4
		pos_StructHeader_inc = increment_hex(pos_StructHeader_str, 4)
		insert_new_byte(mm, pos_StructHeader_inc, offset)

		# Then, insert 00 07 00 00 followed by 14 5D 20 B7
		offset += 4
		insert_new_byte(mm, "00070000", offset)
		offset += 4
		insert_new_byte(mm, "145d20b7", offset)

		# After that, insert pos_StructHeader_inc + 0x10
		offset += 4
		pos_StructHeader_inc2 = increment_hex(pos_StructHeader_inc, 12)
		insert_new_byte(mm, pos_StructHeader_inc2, offset)

		# Then, insert pos_StructHeader_inc + the number of bytes needed to fit band_name
		offset += 4
		pos_StructHeader_inc = increment_hex(
			pos_StructHeader_inc, length_StructItem(band_name) - 4
		)
		pos_SongTitle = pos_StructHeader_inc
		insert_new_byte(mm, pos_StructHeader_inc, offset)

		# Insert the band name (some details explained in the function)
		offset += 4
		offset = insert_large_hex(mm, band_name, offset)

		# Then, insert 00 07 00 00 followed by 33 25 3e a4
		offset += 4
		insert_new_byte(mm, "00070000", offset)
		offset += 4
		insert_new_byte(mm, "33253ea4", offset)

		# Afterwards, insert pos_StructHeader_inc + 0x10
		offset += 4
		pos_StructHeader_inc = increment_hex(pos_StructHeader_inc, 12)
		insert_new_byte(mm, pos_StructHeader_inc, offset)

		# Then, insert pos_SongTitle + the number of bytes needed to fit song_title
		offset += 4
		pos_SongTitle_inc = increment_hex(pos_SongTitle, length_StructItem(song_title) - 4)
		insert_new_byte(mm, pos_SongTitle_inc, offset)

		# Insert the song title (some details explained in the function)
		offset += 4
		offset = insert_large_hex(mm, song_title, offset)

		# Insert 00 03 00 00 and 07 cc af 7c
		offset += 4
		insert_new_byte(mm, "00030000", offset)
		offset += 4
		insert_new_byte(mm, "07ccaf7c", offset)

		# Insert the song type (00 00 00 00 = punk, 01 00 00 00 = hiphip, 02 00 00 00 = rock/other)
		offset += 4
		genre = get_song_genre_hex(song_type)
		insert_new_byte(mm, genre, offset)

		# (rewrite this later) insert the position of the path to the song file, which is the position of the music type + 0x10
		offset += 4
		pos_SongTitle_inc = increment_hex(pos_SongTitle_inc, 12)
		insert_new_byte(mm, pos_SongTitle_inc, offset)

		# then insert these ints: 00 07 00 00 F0 74 AB F4
		offset += 4
		insert_new_byte(mm, "00070000", offset)
		offset += 4
		insert_new_byte(mm, "f074abf4", offset)

		# then insert path position + 10
		offset += 4
		pos_SongTitle_inc = increment_hex(pos_SongTitle_inc, 12)
		insert_new_byte(mm, pos_SongTitle_inc, offset)

		# then 00 00 00 00
		offset += 4
		insert_new_byte(mm, "00000000", offset)

		# finally, insert path to file
		offset += 4
		offset = insert_large_hex(mm, "music\\vag\\songs\\" + song_file, offset)

		# Some more updates (increments by header_length) (actually current header_length?)

		header_length = length_StructHeader(band, song, 2, f"music\\vag\\songs\\{song_file}")
		print(f"current header_length: {header_length}")

		while hex_str != "91d5c799":
			offset += 4
			hex_byte = binascii.hexlify(bytearray(mm[offset : offset + 4]))
			hex_str = str(hex_byte).split("'")[1]

		offset += 4
		hex_to_update_byte = binascii.hexlify(bytearray(mm[offset : offset + 4]))
		hex_to_update_str = str(hex_to_update_byte).split("'")[1]
		hex_incremented_str = increment_hex(hex_to_update_str, header_length)
		mm[offset : offset + 4] = bytearray.fromhex(hex_incremented_str)

		while hex_str != "0f000000":
			offset += 4
			hex_byte = binascii.hexlify(bytearray(mm[offset : offset + 4]))
			hex_str = str(hex_byte).split("'")[1]

		for i in range(0, 16):
			offset += 4
			hex_to_update_byte = binascii.hexlify(bytearray(mm[offset : offset + 4]))
			hex_to_update_str = str(hex_to_update_byte).split("'")[1]
			hex_incremented_str = increment_hex(hex_to_update_str, header_length)
			mm[offset : offset + 4] = bytearray.fromhex(hex_incremented_str)

		offset += 8
		hex_to_update_byte = binascii.hexlify(bytearray(mm[offset : offset + 4]))
		hex_to_update_str = str(hex_to_update_byte).split("'")[1]
		hex_incremented_str = increment_hex(hex_to_update_str, header_length)
		mm[offset : offset + 4] = bytearray.fromhex(hex_incremented_str)

		offset += 12
		hex_to_update_byte = binascii.hexlify(bytearray(mm[offset : offset + 4]))
		hex_to_update_str = str(hex_to_update_byte).split("'")[1]
		hex_incremented_str = increment_hex(hex_to_update_str, header_length)
		mm[offset : offset + 4] = bytearray.fromhex(hex_incremented_str)

		for i in range(0, 14):
			while hex_str != "00000100":
				offset += 4
				hex_byte = binascii.hexlify(bytearray(mm[offset : offset + 4]))
				hex_str = str(hex_byte).split("'")[1]

			offset += 4
			hex_to_update_byte = binascii.hexlify(bytearray(mm[offset : offset + 4]))
			hex_to_update_str = str(hex_to_update_byte).split("'")[1]
			hex_incremented_str = increment_hex(hex_to_update_str, header_length)
			mm[offset : offset + 4] = bytearray.fromhex(hex_incremented_str)

			while hex_str != "f074abf4":
				offset += 4
				hex_byte = binascii.hexlify(bytearray(mm[offset : offset + 4]))
				hex_str = str(hex_byte).split("'")[1]

			offset += 4
			hex_to_update_byte = binascii.hexlify(bytearray(mm[offset : offset + 4]))
			hex_to_update_str = str(hex_to_update_byte).split("'")[1]
			hex_incremented_str = increment_hex(hex_to_update_str, header_length)
			mm[offset : offset + 4] = bytearray.fromhex(hex_incremented_str)

		mm.close()


def convert_songs():
	print("convert songs manually i guess")
	pass


if __name__ == "__main__":
	# IMPORTANT
	# radvideo64 binkc miserybusiness.flac miserybusiness2.bik /v100 /d0 /m3.0 /l0 /p8 /r44100 /b16 /c2
	f = open("songs/songs.json")
	data = json.load(f)

	for track in data["tracks"]:
		band = track["band"]
		song = track["title"]
		filename = track["filename"]
		genre = int(track["genre"])

		print("Inserting new song:")
		print(f"\tBand:\t\t{band}")
		print(f"\tSong:\t\t{song}")
		print(f"\tFilename:\t{filename}.bik")
		print(f"\tGenre:\t\t{str(genre)}")
		qbkey = get_qbkey(filename)
		print(f"Generated QBKey: {qbkey}\n")

		with open("music_bik.dat", "r+b") as f:
			mm_dat = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_WRITE)

			hex_to_update_byte = binascii.hexlify(bytearray(mm_dat[0 : 0 + 4]))
			hex_to_update_str = str(hex_to_update_byte).split("'")[1]
			hex_incremented_str = hex_plus_plus(hex_to_update_str)
			mm_dat[0 : 0 + 4] = bytearray.fromhex(hex_incremented_str)

			# First thing: append qbkey to music_bik.dat
			print(f"Appending {qbkey} to music_bik.dat...")
			insert_new_byte(mm_dat, qbkey, len(mm_dat))

			with open("music_bik.wad", "r+b") as f:
				mm_wad = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_WRITE)
				offset_wad = hex(len(mm_wad))
				offset_wad_reverse = reverse_hex(format_hex(offset_wad))
				print(
					f"Appending {offset_wad_reverse} (reversed size of music_bik.wad) to music_bik.dat..."
				)
				insert_new_byte(mm_dat, offset_wad_reverse, len(mm_dat))

				with open(f"songs/bik/{filename}.bik", "r+b") as f:
					mm_song = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_WRITE)
					offset_song = hex(len(mm_song))
					offset_song_reverse = reverse_hex(format_hex(offset_song))
					print(
						f"Appending {offset_song_reverse} (reversed size of {filename}.bik) to music_bik.dat...\n"
					)
					insert_new_byte(mm_dat, offset_song_reverse, len(mm_dat))
					song_data = mm_song[0:]
					print(f"Appending {filename}.bik to music_bik.wad")
					print(f"Filesize: {len(mm_song)} Bytes")
					insert_full_song(mm_wad, mm_song)
					mm_song.close()
				mm_wad.close()
			mm_dat.close()

		print("Updating qb.pak.wpc values...")
		update_pak_file(length_StructHeader(band, song, genre, f"music\vag\songs\{filename}"))
		"""
		print("Updating qb.pab.wpc values...")
		update_pab_file(
			length_StructHeader(band, song, genre, f"music\vag\songs\{filename}"),
			band,
			song,
			genre,
			filename,
		)
		#input()
		"""

		update_wpc_file(
			length_StructHeader(band, song, genre, f"music\\vag\\songs\\{filename}"),
			band,
			song,
			genre,
			filename,
		)


# FORGOT THIS: in the music_bik.dat file add 1 to the first 4 byte value, in this case 6F becomes 70
# generate the qbkey, put it at the end of music_bik.dat
# go to the end of music_bik.wad, get the offset and put
# it reversed at the end of music_bik.dat
# go to the end of the song file, get the offset, and put
# it reversed at the end of music_bik.dat
# paste the entirety of the song file at the end of music_bik.wad

"""
with open("qb.pak.wpc", "rb") as f:
    mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
    offset = 0
    for j in range (0, 10000):
        hex_array = binascii.hexlify(bytearray(mm[offset : offset + 4]))
        if offset == 13064:
            print(f"{hex(offset)}:  {hex_array}")
            hex_num = str(hex_array).split("'")[1]
            print(hex_num)
            print(reverse_hex(hex_num))
            hex_reversed = reverse_hex(hex_num)
            print(hex(int(hex_reversed, 16) + int("80", 16)))
            hex_test = hex(int(hex_reversed, 16) + int("80", 16))
            #print("0x" + '%0*x' % (8,int(hex_test, 16)))
            print_hex(hex_test)
        offset += 4
        if offset > 13064:
            print(hex(increment_hex("000025d8", length_StructHeader("sample_band", "sample_song", 2, "music\vag\songs\sample_song"))))
            exit()
"""
