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
		var plain_filename string = flag.Arg(0)
		var cipher_filename string = fmt.Sprintf("%s.%s", plain_filename, DEFAULT_CIPHER_EXTENSION)
		var key_filename string
		if *key_outfile != "" {
			key_filename = *key_outfile
		} else {
			key_filename = fmt.Sprintf("%s.%s", plain_filename, DEFAULT_KEY_EXTENSION)
		}
		
		err := encryptFiles(plain_filename, key_filename, cipher_filename,
							plain_buffer, key_buffer, cipher_buffer)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%v\n", err)
		}
	}
}

// Simple error report
type ErrorReport struct {
	Msg string
	Err error
}

func (e *ErrorReport) Error() string {
	return fmt.Sprintf("%s: %v", e.Msg, e.Err)
}

func encryptFiles(plain_filename, key_filename, cipher_filename string,
					plain_buffer, key_buffer, cipher_buffer []byte) error {
	report := &ErrorReport{Err: nil}
	
	rng := bufio.NewReader(rand.Reader)
		
	// Create file objects
	// Plaintext
	fplain, err := os.Open(plain_filename)
	if err != nil {
		report.Msg = "unexpected error while opening plaintext file"
		report.Err = err
		return report
	}
	defer fplain.Close()
	plainReader := bufio.NewReader(fplain)
	
	// Ciphertext
	fcipher, err := os.Create(cipher_filename)
	if err != nil {
		report.Msg = "unexpected error while creating ciphertext file"
		report.Err = err
		return report
	}
	defer fcipher.Close()
	cipherWriter := bufio.NewWriter(fcipher)
	
	// Keyfile
	fkey, err := os.Create(key_filename)
	if err != nil {
		report.Msg = "unexpected error while creating key output file"
		report.Err = err
		return report
	}
	defer fkey.Close()
	keyWriter := bufio.NewWriter(fkey)
	
	// "Crypto"
	
	for { // Main loop
		n, err := plainReader.Read(plain_buffer)
		//fmt.Printf("n: %d\n", n) // Debugging
		if err != nil && err != io.EOF {
			report.Msg = "unexpected error while reading from plaintext\n"
			report.Err = err
			return report
		}
		if n == 0 {
			break
		}
		
		_, err = rng.Read(key_buffer[:n])
		if err != nil && err != io.EOF {
			report.Msg = "unexpected error while generating key"
			report.Err = err
			return report
		}
		
		err = XorSlices(plain_buffer[:n], key_buffer[:n], cipher_buffer[:n])
		if err != nil {
			report.Msg = "unexpected error while xoring slices"
			report.Err = err
			return report
		}
		
		_, err = cipherWriter.Write(cipher_buffer[:n])
		if err != nil {
			report.Msg = "unexpected error while writing ciphertext\n"
			report.Err = err
			return report
		}
		
		_, err = keyWriter.Write(key_buffer[:n])
		if err != nil {
			report.Msg = "unexpected error while writing key to file"
			report.Err = err
			return report
		}
		
	}
	
	return nil
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
