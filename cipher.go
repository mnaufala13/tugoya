package tuya_local_sdk

import (
	"bytes"
	"crypto/aes"
	"crypto/rand"
)

/*
https://github.com/jasonacox/tinytuya/discussions/260
As a recap, the older 55AA/v3.1-v3.4 packet format looks like:

000055aaSSSSSSSSMMMMMMMMLLLLLLLL[RRRRRRRR]DD..DDCC..CC0000aa55 where:
000055aa - prefix
SSSSSSSS - 32-bit sequence number
MMMMMMMM - 32-bit Command ID
LLLLLLLL - 32-bit packet length - count every byte from the return code through (and including) the footer
[RRRRRRRR] - packets from devices have a 32-bit return code. Packets from the app/client do not have this field
DD..DD - variable length encrypted payload data
CC..CC - checksum, either 32-bit (4-byte) CRC32 for v3.1-v3.3, or 256-bit (32-byte) HMAC-SHA256 for v3.4
0000aa55 - footer
*/

const blockSize = 16

func pkcs5padding(data []byte, blockSize int) []byte {
	pLen := blockSize - len(data)%blockSize
	padding := bytes.Repeat([]byte{byte(pLen)}, pLen)
	return append(data, padding...)
}

func encryptAESWithECB(key, data []byte, padding bool) ([]byte, error) {
	var data2 = data
	if padding {
		data2 = pkcs5padding(data, blockSize)
	}

	// Create a new AES cipher with the provided key
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// Encrypt the padded data using ECB mode
	encrypted := make([]byte, len(data2))
	for i := 0; i < len(data2); i += blockSize {
		block.Encrypt(encrypted[i:i+blockSize], data2[i:i+blockSize])
	}

	return encrypted, nil
}

func decryptAESWithECB(key, data []byte) ([]byte, error) {
	// Create a new AES cipher with the provided key
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// Check if the encrypted data length is a multiple of the block size
	if len(data)%blockSize != 0 {
		// Calculate the padding length needed to align the last block
		paddingLen := blockSize - (len(data) % blockSize)

		// Append padding to the encrypted data to align the last block
		padded := append(data, bytes.Repeat([]byte{byte(0)}, paddingLen)...)

		// Perform decryption of the padded data
		decrypted := make([]byte, len(padded))
		for i := 0; i < len(padded); i += blockSize {
			block.Decrypt(decrypted[i:i+blockSize], padded[i:i+blockSize])
		}

		return decrypted, nil
	}

	// Perform decryption of the encrypted data directly
	decrypted := make([]byte, len(data))
	for i := 0; i < len(data); i += blockSize {
		block.Decrypt(decrypted[i:i+blockSize], data[i:i+blockSize])
	}
	return decrypted, nil
}

func random() []byte {
	buf := make([]byte, 16)
	// then we can call rand.Read.
	_, _ = rand.Read(buf)
	return buf
}
