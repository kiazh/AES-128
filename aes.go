package main

var sBox = [256]byte{
	0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
	0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
	0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
	0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
	0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
	0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
	0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
	0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
	0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
	0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
	0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
	0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
	0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
	0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
	0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
	0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
}

var invSBox = buildInvSBox()

/*
The function take a 16 byte array and maps it onto a 4 by 4 matrix
by interpeting the input as four 4 by chunks. It places these chunks collumn
by column. It uses the column index to determin which group of 4 bytes is currently
being processed and row index to determin whcih the position within that group.
This is achived by computing the original index as col * 4 + row, which groups linear arrays
into blocks of four. The inverse function reverses this exact mapping by reading the matrix column
by column in the same order and reconstructing the original linear array.

*/

var rcon = [10]byte{
	0x01, 0x02, 0x04, 0x08,
	0x10, 0x20, 0x40, 0x80,
	0x1b, 0x36,
}

func toState(block [16]byte) [4][4]byte {
	var s [4][4]byte
	for col := 0; col < 4; col++ {
		for row := 0; row < 4; row++ {
			s[row][col] = block[col*4+row]
		}
	}
	return s
}

func fromState(s [4][4]byte) [16]byte {
	var block [16]byte
	for col := 0; col < 4; col++ {
		for row := 0; row < 4; row++ {
			block[col*4+row] = s[row][col]
		}
	}
	return block
}

/*
This step applies a nonlinear substitution to every byte in the state u
sing a fixed lookup table called the S-box. The purpose is to destroy
linear relationships between input and output, which would otherwise
 make the cipher vulnerable to algebraic and linear attacks.
*/

func subBytes(s [4][4]byte) [4][4]byte {
	var out [4][4]byte
	for r := 0; r < 4; r++ {
		for c := 0; c < 4; c++ {
			out[r][c] = sBox[s[r][c]]
		}
	}
	return out
}

func invSubBytes(s [4][4]byte) [4][4]byte {
	var out [4][4]byte
	for r := 0; r < 4; r++ {
		for c := 0; c < 4; c++ {
			out[r][c] = invSBox[s[r][c]]
		}
	}
	return out
}

/*
This function cyclically shifts each row of the state
by a different offset, with the first row unchanged,
the second shifted by one, the third by two, and the fourth by
three positions. While it appears simple, its role is essential:
it breaks the alignment of bytes within columns so that subsequent
operations can mix data across different columns.
*/

func shiftRows(s [4][4]byte) [4][4]byte {
	var out [4][4]byte

	out[0][0], out[0][1], out[0][2], out[0][3] =
		s[0][0], s[0][1], s[0][2], s[0][3]

	out[1][0], out[1][1], out[1][2], out[1][3] =
		s[1][1], s[1][2], s[1][3], s[1][0]

	out[2][0], out[2][1], out[2][2], out[2][3] =
		s[2][2], s[2][3], s[2][0], s[2][1]

	out[3][0], out[3][1], out[3][2], out[3][3] =
		s[3][3], s[3][0], s[3][1], s[3][2]

	return out
}

func invShiftRows(s [4][4]byte) [4][4]byte {
	var out [4][4]byte

	out[0][0], out[0][1], out[0][2], out[0][3] =
		s[0][0], s[0][1], s[0][2], s[0][3]

	out[1][0], out[1][1], out[1][2], out[1][3] =
		s[1][3], s[1][0], s[1][1], s[1][2]

	out[2][0], out[2][1], out[2][2], out[2][3] =
		s[2][2], s[2][3], s[2][0], s[2][1]

	out[3][0], out[3][1], out[3][2], out[3][3] =
		s[3][1], s[3][2], s[3][3], s[3][0]

	return out
}

/*
This function performs multiplication in the finite field GF(2^8),
which is fundamentally different from standard integer multiplication.
Instead of working with real numbers, AES treats bytes as polynomials
and reduces results modulo an irreducible polynomial. This ensures
that all operations remain within 8 bits while preserving algebraic
structure. The conditional XOR with 0x1b implements the modular reduction
step, which is necessary when intermediate values exceed the field size.
*/

func gmul(a, b byte) byte {
	var p byte
	for i := 0; i < 8; i++ {
		if b&0x01 != 0 {
			p ^= a
		}
		hiBit := a & 0x80
		a <<= 1
		if hiBit != 0 {
			a ^= 0x1b
		}
		b >>= 1
	}
	return p
}

/*
In this step, each column of the state is transformed using
a fixed matrix multiplication over GF(2^8). This operation
combines the four bytes of each column in such a way that
every output byte depends on all four input bytes. Its purpose
is to create strong diffusion, meaning that a small change in the
input spreads rapidly throughout the state.
*/

func mixColumns(s [4][4]byte) [4][4]byte {
	var out [4][4]byte
	for c := 0; c < 4; c++ {
		s0 := s[0][c]
		s1 := s[1][c]
		s2 := s[2][c]
		s3 := s[3][c]
		out[0][c] = gmul(2, s0) ^ gmul(3, s1) ^ s2 ^ s3
		out[1][c] = s0 ^ gmul(2, s1) ^ gmul(3, s2) ^ s3
		out[2][c] = s0 ^ s1 ^ gmul(2, s2) ^ gmul(3, s3)
		out[3][c] = gmul(3, s0) ^ s1 ^ s2 ^ gmul(2, s3)
	}
	return out
}

func invMixColumns(s [4][4]byte) [4][4]byte {
	var out [4][4]byte
	for c := 0; c < 4; c++ {
		s0 := s[0][c]
		s1 := s[1][c]
		s2 := s[2][c]
		s3 := s[3][c]
		out[0][c] = gmul(14, s0) ^ gmul(11, s1) ^ gmul(13, s2) ^ gmul(9, s3)
		out[1][c] = gmul(9, s0) ^ gmul(14, s1) ^ gmul(11, s2) ^ gmul(13, s3)
		out[2][c] = gmul(13, s0) ^ gmul(9, s1) ^ gmul(14, s2) ^ gmul(11, s3)
		out[3][c] = gmul(11, s0) ^ gmul(13, s1) ^ gmul(9, s2) ^ gmul(14, s3)
	}
	return out
}

/*
This function takes the original 16-byte key and expands
it into a sequence of round keys used throughout
the encryption process. It does this by iteratively
generating new 4-byte words from previous ones,
applying rotation, substitution via the S-box,
and the addition of round constants.
*/

func keyExpansion(key [16]byte) [11][4][4]byte {
	var w [44][4]byte

	for i := 0; i < 4; i++ {
		w[i] = [4]byte{
			key[i*4], key[i*4+1],
			key[i*4+2], key[i*4+3],
		}
	}

	for i := 4; i < 44; i++ {
		temp := w[i-1]
		if i%4 == 0 {
			temp = [4]byte{
				temp[1], temp[2], temp[3], temp[0],
			}
			temp = [4]byte{
				sBox[temp[0]], sBox[temp[1]],
				sBox[temp[2]], sBox[temp[3]],
			}
			temp[0] ^= rcon[i/4-1]
		}
		w[i][0] = w[i-4][0] ^ temp[0]
		w[i][1] = w[i-4][1] ^ temp[1]
		w[i][2] = w[i-4][2] ^ temp[2]
		w[i][3] = w[i-4][3] ^ temp[3]
	}

	var roundKeys [11][4][4]byte
	for rk := 0; rk < 11; rk++ {
		for col := 0; col < 4; col++ {
			for row := 0; row < 4; row++ {
				roundKeys[rk][row][col] = w[rk*4+col][row]
			}
		}
	}
	return roundKeys
}

/*
This function XORs the state with a round-specific key derived from the original encryption key.
It is the only step where the secret key directly influences the data, making it fundamental
to the security of AES. XOR is used because it is simple, reversible, and interacts well with
the rest of the operations.
*/

func addRoundKey(s, rk [4][4]byte) [4][4]byte {
	var out [4][4]byte
	for r := 0; r < 4; r++ {
		for c := 0; c < 4; c++ {
			out[r][c] = s[r][c] ^ rk[r][c]
		}
	}
	return out
}

func Encrypt(plaintext, key [16]byte) [16]byte {

	rks := keyExpansion(key)

	state := toState(plaintext)

	state = addRoundKey(state, rks[0])

	for round := 1; round <= 9; round++ {
		state = subBytes(state)
		state = shiftRows(state)
		state = mixColumns(state)
		state = addRoundKey(state, rks[round])
	}

	state = subBytes(state)
	state = shiftRows(state)
	state = addRoundKey(state, rks[10])

	return fromState(state)
}

func Decrypt(ciphertext, key [16]byte) [16]byte {
	rks := keyExpansion(key)
	state := toState(ciphertext)
	state = addRoundKey(state, rks[10])

	for round := 9; round >= 1; round-- {
		state = invShiftRows(state)
		state = invSubBytes(state)
		state = addRoundKey(state, rks[round])
		state = invMixColumns(state)
	}

	state = invShiftRows(state)
	state = invSubBytes(state)
	state = addRoundKey(state, rks[0])

	return fromState(state)
}

func buildInvSBox() [256]byte {
	var inv [256]byte
	for i := 0; i < 256; i++ {
		inv[sBox[i]] = byte(i)
	}
	return inv
}
