package main

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
)

func main() {
	key := [16]byte{
		0x2b, 0x7e, 0x15, 0x16,
		0x28, 0xae, 0xd2, 0xa6,
		0xab, 0xf7, 0x15, 0x88,
		0x09, 0xcf, 0x4f, 0x3c,
	}

	reader := bufio.NewReader(os.Stdin)

	fmt.Println("Press 1 for Encrypt")
	fmt.Println("Press 2 for Decrypt")
	fmt.Println("Press 3 for Known Encrypt Test")
	fmt.Print("Enter your choice: ")
	choiceLine, _ := reader.ReadString('\n')
	choiceLine = strings.TrimSpace(choiceLine)
	choice, err := strconv.Atoi(choiceLine)
	if err != nil {
		fmt.Println("Invalid choice.")
		return
	}

	switch choice {
	case 1:
		fmt.Print("Enter plaintext (16 chars): ")
		input, _ := reader.ReadString('\n')
		input = strings.TrimSpace(input)
		if len(input) != 16 {
			fmt.Println("Plaintext must be exactly 16 chars.")
			return
		}
		var plaintext [16]byte
		copy(plaintext[:], []byte(input))
		cipher := Encrypt(plaintext, key)
		fmt.Printf("Ciphertext hex: %x\n", cipher)
	case 2:
		fmt.Print("Enter ciphertext hex (32 hex chars): ")
		input, _ := reader.ReadString('\n')
		input = strings.TrimSpace(input)
		if len(input) != 32 {
			fmt.Println("Ciphertext must be exactly 32 hex chars.")
			return
		}
		decoded, ok := parseHex16(input)
		if !ok {
			fmt.Println("Invalid hex input.")
			return
		}
		plain := Decrypt(decoded, key)
		fmt.Printf("Plaintext: %s\n", string(plain[:]))
		fmt.Printf("Plaintext hex: %x\n", plain)
	case 3:
		plaintext := [16]byte{
			0x32, 0x43, 0xf6, 0xa8,
			0x88, 0x5a, 0x30, 0x8d,
			0x31, 0x31, 0x98, 0xa2,
			0xe0, 0x37, 0x07, 0x34,
		}
		cipher := Encrypt(plaintext, key)
		fmt.Printf("Result:   %x\n", cipher)
		fmt.Println("Expected: 3925841d02dc09fbdc118597196a0b32")
		expected := [16]byte{
			0x39, 0x25, 0x84, 0x1d,
			0x02, 0xdc, 0x09, 0xfb,
			0xdc, 0x11, 0x85, 0x97,
			0x19, 0x6a, 0x0b, 0x32,
		}
		if cipher == expected {
			fmt.Println("PASS")
		} else {
			fmt.Println("FAIL")
		}
	default:
		fmt.Println("Invalid choice.")
	}
}

func parseHex16(s string) ([16]byte, bool) {
	var out [16]byte
	for i := 0; i < 16; i++ {
		hi, okHi := hexNibble(s[i*2])
		lo, okLo := hexNibble(s[i*2+1])
		if !okHi || !okLo {
			return [16]byte{}, false
		}
		out[i] = hi<<4 | lo
	}
	return out, true
}

func hexNibble(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	default:
		return 0, false
	}
}
