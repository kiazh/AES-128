package main

import (
	"bufio"
	"fmt"
	"os"
)

func main() {
	key := [16]byte{
		0x2b, 0x7e, 0x15, 0x16,
		0x28, 0xae, 0xd2, 0xa6,
		0xab, 0xf7, 0x15, 0x88,
		0x09, 0xcf, 0x4f, 0x3c,
	}

	var choice int

	fmt.Println("press 1 to test encryption")
	fmt.Println("press 2 to enter your own plaintext")
	fmt.Print("Enter your choice: ")
	fmt.Scan(&choice)

	switch choice {

	case 1:
		plaintext := [16]byte{
			0x32, 0x43, 0xf6, 0xa8,
			0x88, 0x5a, 0x30, 0x8d,
			0x31, 0x31, 0x98, 0xa2,
			0xe0, 0x37, 0x07, 0x34,
		}

		cipher := Encrypt(plaintext, key)

		fmt.Printf("Result: %x\n", cipher)
		fmt.Printf("Expected: 3925841d02dc09fbdc118597196a0b32\n")

		expected := [16]byte{
			0x39, 0x25, 0x84, 0x1d,
			0x02, 0xdc, 0x09, 0xfb,
			0xdc, 0x11, 0x85, 0x97,
			0x19, 0x6a, 0x0b, 0x32,
		}

		if cipher == expected {
			fmt.Println("PASS — your AES-128 is correct!")
		} else {
			fmt.Println("FAIL — something is wrong.")
		}

	case 2:
		reader := bufio.NewReader(os.Stdin)

		fmt.Print("Enter plaintext (16 chars): ")
		input, _ := reader.ReadString('\n')

		b := []byte(input)

		if len(b) < 16 {
			fmt.Println("Must be at least 16 bytes")
			return
		}

		var plaintext [16]byte
		copy(plaintext[:], b[:16])

		cipher := Encrypt(plaintext, key)
		fmt.Printf("Encrypted: %x\n", cipher)

	default:
		fmt.Println("Invalid choice. Program will close.")
		return
	}
}
