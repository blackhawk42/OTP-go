package main

import(
	"fmt"
	"os"
	"bufio"
	"path/filepath"
	"io"
	"flag"
	"crypto/rand"
)

const(
	DEFAULT_CHUNK_SIZE int = 32*1024
	DEFAULT_CIPHER_EXTENSION string = "otp"
	DEFAULT_KEY_EXTENSION string = "otpk"
)

var key_infile = flag.String("d", "", "Decryption mode. Follow immediately by \"key\" file.")
var key_outfile = flag.String("o", "", "Output file to deposit the \"key\" data. Default is derivated from input filename.")
var chunk_size = flag.Int("c", DEFAULT_CHUNK_SIZE, fmt.Sprintf("Chunk size and buffer sizes (x3). Default is %d", DEFAULT_CHUNK_SIZE))

func main() {
	flag.Parse()
	
	if len(flag.Args()) == 0 {
		fmt.Fprintf(os.Stderr, "%s: Specify at least one target file\n", filepath.Base(os.Args[0]))
		os.Exit(2)
	}
	
	// Buffers. Will be used differently, depending of encryption or encryption modes.
	plain_buffer := make([]byte, *chunk_size)
	cipher_buffer := make([]byte, *chunk_size)
	key_buffer := make([]byte, *chunk_size)
	
	if *key_infile == "" { // Encryption mode, or useless decryption input, somehow
		
		rng := bufio.NewReader(rand.Reader)
		
		// Create file objects
		// Plaintext
		fplain, err := os.Open(flag.Arg(0))
		if err != nil {
			fmt.Fprintf(os.Stderr, "unexpected error while opening plaintext file\n")
			panic(err)
		}
		defer fplain.Close()
		plainReader := bufio.NewReader(fplain)
		
		// Ciphertext
		fcipher, err := os.Create( fmt.Sprintf("%s.%s", fplain.Name(), DEFAULT_CIPHER_EXTENSION) )
		if err != nil {
			fmt.Fprintf(os.Stderr, "unexpected error while creating ciphertext file\n")
			panic(err)
		}
		defer fcipher.Close()
		cipherWriter := bufio.NewWriter(fcipher)
		
		// Keyfile
		var fkey *os.File
		if *key_outfile == "" {
			fkey, err = os.Create( fmt.Sprintf("%s.%s", fplain.Name(), DEFAULT_KEY_EXTENSION) )
		} else {
			fkey, err = os.Create( *key_outfile )
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "unexpected error while creating key output file\n")
			panic(err)
		}
		defer fkey.Close()
		keyWriter := bufio.NewWriter(fkey)
		
		// "Crypto"
		
		for { // Main loop
			n, err := plainReader.Read(plain_buffer)
			//fmt.Printf("n: %d\n", n) // Debugging
			if err != nil && err != io.EOF {
				fmt.Fprintf(os.Stderr, "unexpected error while reading from plaintext\n")
				panic(err)
			}
			if n == 0 {
				break
			}
			
			_, err = rng.Read(key_buffer[:n])
			if err != nil && err != io.EOF {
				fmt.Fprintf(os.Stderr, "unexpected error while generating key\n")
				panic(err)
			}
			
			XorSlices(plain_buffer[:n], key_buffer[:n], cipher_buffer[:n])
			
			_, err = cipherWriter.Write(cipher_buffer[:n])
			if err != nil {
				fmt.Fprintf(os.Stderr, "unexpected error while writing ciphertext\n")
				panic(err)
			}
			
			_, err = keyWriter.Write(key_buffer[:n])
			if err != nil {
				fmt.Fprintf(os.Stderr, "unexpected error while writing key to file\n")
				panic(err)
			}
			
		}
	}
}

// XorSlices xors two input slices into one output, all of the same size.
func XorSlices(input1, input2, output []byte) error {
	if len(input1) != len(input2) || len(input2) != len(output) {
		return fmt.Errorf("XorSlices: arguments not of the same size")
	}
	
	for i := range output {
		output[i] = input1[i] ^ input2[i]
	}
	
	return nil
}
