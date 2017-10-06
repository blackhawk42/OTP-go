package main

import(
	"fmt"
	"os"
	"bufio"
	"path/filepath"
	"io"
	"flag"
	"crypto/rand"
	"github.com/blackhawk42/pathutils"
)

const(
	DEFAULT_CHUNK_SIZE int = 4096
	DEFAULT_IO_BUFFER_SIZE int = 16*DEFAULT_CHUNK_SIZE
	DEFAULT_CIPHER_EXTENSION string = "otp"
	DEFAULT_KEY_EXTENSION string = "otpk"
)

func main() {
	// Flags configuration
	var key_infile = flag.String("d", "", "decryption mode. Follow immediately by `key file`.")
	var outfile = flag.String("o", "", "`output file` to deposit the \"key\" data in encryption mode or \"plaintext\" data in decryption mode. Default is derivated from input filename.")
	var chunk_size = flag.Int("c", DEFAULT_CHUNK_SIZE, "chunk `size` and working buffers sizes in bytes (x3)")
	var io_buffer_size = flag.Int("b", DEFAULT_IO_BUFFER_SIZE, "`size` in bytes of I/O buffers (x3)")
	
	flag.Usage = func(){
		fmt.Fprintf(os.Stderr, "%s: %[1]s [-c chunk_size] [-d key_file] [-o output_file] input_file\n", filepath.Base(os.Args[0]))
		flag.PrintDefaults()
	}
	
	flag.Parse()
	
	if len(flag.Args()) == 0 {
		flag.Usage()
		os.Exit(2)
	}
	
	// Buffers. Will be used differently, depending of encryption or encryption modes.
	plain_buffer := make([]byte, *chunk_size)
	cipher_buffer := make([]byte, *chunk_size)
	key_buffer := make([]byte, *chunk_size)
	
	if *key_infile == "" { // Encryption mode, or useless decryption input, somehow
		
		plain_filename := flag.Arg(0)
		cipher_filename := fmt.Sprintf("%s.%s", plain_filename, DEFAULT_CIPHER_EXTENSION)
		var key_filename string
		if *outfile != "" {
			key_filename = *outfile
		} else {
			key_filename = fmt.Sprintf("%s.%s", plain_filename, DEFAULT_KEY_EXTENSION)
		}
		
		err := EncryptFiles(plain_filename, key_filename, cipher_filename,
							plain_buffer, key_buffer, cipher_buffer, *io_buffer_size)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%v\n", err)
			os.Exit(1)
		}
	} else { // Decryption mode
		
		cipher_filename := flag.Arg(0)
		key_filename := *key_infile
		var plain_filename string
		if *outfile != "" {
			plain_filename = *outfile
		} else {
			cipher_basename, ext := pathutils.Splitext(cipher_filename)
			if ext == fmt.Sprintf(".%s", DEFAULT_CIPHER_EXTENSION) {
				plain_filename = cipher_basename
			} else {
				fmt.Fprintf(os.Stderr, "Please let the input have a \"%s\" termination, or explicitly name an output\n", DEFAULT_CIPHER_EXTENSION)
				os.Exit(1)
			}
		}
		
		err := DecryptFiles(cipher_filename, key_filename, plain_filename,
							cipher_buffer, key_buffer, plain_buffer, *io_buffer_size)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%v\n", err)
			os.Exit(1)
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

// EncryptFiles takes the filename of a plaintext, a key and a ciphertext,
// buffers to work with them and xor them, writing both the key and the
// ciphertext to a file.
func EncryptFiles(plain_filename, key_filename, cipher_filename string,
					plain_buffer, key_buffer, cipher_buffer []byte, io_buffer_size int) error {
						
	rng := bufio.NewReader(rand.Reader)
		
	// Create file objects
	// Plaintext
	fplain, err := os.Open(plain_filename)
	if err != nil {
		report := &ErrorReport{}
		report.Msg = "unexpected error while opening plaintext file"
		report.Err = err
		return report
	}
	defer fplain.Close()
	plainReader := bufio.NewReaderSize(fplain, io_buffer_size)
	
	// Ciphertext
	fcipher, err := os.Create(cipher_filename)
	if err != nil {
		report := &ErrorReport{}
		report.Msg = "unexpected error while creating ciphertext file"
		report.Err = err
		return report
	}
	defer fcipher.Close()
	cipherWriter := bufio.NewWriterSize(fcipher, io_buffer_size)
	
	// Keyfile
	fkey, err := os.Create(key_filename)
	if err != nil {
		report := &ErrorReport{}
		report.Msg = "unexpected error while creating key output file"
		report.Err = err
		return report
	}
	defer fkey.Close()
	keyWriter := bufio.NewWriterSize(fkey, io_buffer_size)
	
	// "Crypto"
	
	for { // Main loop
		n, err := plainReader.Read(plain_buffer)
		if err != nil && err != io.EOF {
			report := &ErrorReport{}
			report.Msg = "unexpected error while reading from plaintext\n"
			report.Err = err
			return report
		}
		if n == 0 {
			break
		}
		
		_, err = rng.Read(key_buffer[:n])
		if err != nil && err != io.EOF {
			report := &ErrorReport{}
			report.Msg = "unexpected error while generating key"
			report.Err = err
			return report
		}
		
		err = XorSlices(plain_buffer[:n], key_buffer[:n], cipher_buffer[:n])
		if err != nil {
			report := &ErrorReport{}
			report.Msg = "unexpected error while xoring slices"
			report.Err = err
			return report
		}
		
		_, err = cipherWriter.Write(cipher_buffer[:n])
		if err != nil {
			report := &ErrorReport{}
			report.Msg = "unexpected error while writing ciphertext\n"
			report.Err = err
			return report
		}
		
		_, err = keyWriter.Write(key_buffer[:n])
		if err != nil {
			report := &ErrorReport{}
			report.Msg = "unexpected error while writing key to file"
			report.Err = err
			return report
		}
	}
	cipherWriter.Flush()
	keyWriter.Flush()
	
	return nil
}

func DecryptFiles(cipher_filename, key_filename, plain_filename string,
					cipher_buffer, key_buffer, plain_buffer []byte, io_buffer_size int) error {
	
	// Create file objects
	// Plaintext
	fcipher, err := os.Open(cipher_filename)
	if err != nil {
		report := &ErrorReport{}
		report.Msg = "unexpected error when reading ciphertext file"
		report.Err = err
		return report
	}
	defer fcipher.Close()
	cipherReader := bufio.NewReaderSize(fcipher, io_buffer_size)
	
	// Key
	fkey, err := os.Open(key_filename)
	if err != nil {
		report := &ErrorReport{}
		report.Msg = "unexpected error when reading key file"
		report.Err = err
		return report
	}
	defer fkey.Close()
	keyReader := bufio.NewReaderSize(fkey, io_buffer_size)
	
	// Plaintext
	fplain, err := os.Create(plain_filename)
	if err != nil {
		report := &ErrorReport{}
		report.Msg = "unexpected error when creating plaintext file"
		report.Err = err
		return report
	}
	defer fplain.Close()
	plainWriter := bufio.NewWriterSize(fplain, io_buffer_size)
	
	// "Crypto"
	
	for {
		n, err := cipherReader.Read(cipher_buffer)
		if err != nil && err != io.EOF {
			report := &ErrorReport{}
			report.Msg = "unexpected error while reading from ciphertext\n"
			report.Err = err
			return report
		}
		if n == 0 {
			break
		}
		
		// Note [:n]. It's the user's problem if size(key) != size(cipher)
		_, err = keyReader.Read(key_buffer[:n])
		if err != nil && err != io.EOF {
			report := &ErrorReport{}
			report.Msg = "unexpected error while reading from key file\n"
			report.Err = err
			return report
		}
		
		err = XorSlices(cipher_buffer[:n], key_buffer[:n], plain_buffer[:n])
		if err != nil {
			report := &ErrorReport{}
			report.Msg = "unexpected coring slices\n"
			report.Err = err
			return report
		}
		
		_, err = plainWriter.Write(plain_buffer[:n])
		if err != nil {
			report := &ErrorReport{}
			report.Msg = "unexpected error while writing ciphertext\n"
			report.Err = err
			return report
		}
	}
	plainWriter.Flush()
	
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
