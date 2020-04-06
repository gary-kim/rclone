package cryptomator

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/sha1"
	"encoding/base32"
	"encoding/base64"
	"io"
	"strings"
	"sync"

	"github.com/pkg/errors"
	"github.com/rclone/rclone/backend/crypt/pkcs7"
	"github.com/rclone/rclone/fs"
	"github.com/rclone/rclone/fs/accounting"
	"github.com/rfjakob/eme"
	"github.com/jacobsa/crypto/siv"
	"github.com/google/uuid"
	"golang.org/x/crypto/nacl/secretbox"
	"golang.org/x/crypto/scrypt"
)

// Constants
const (
	nameCipherBlockSize = aes.BlockSize
	fileMagic           = "RCLONE\x00\x00"
	fileMagicSize       = len(fileMagic)
	fileNonceSize       = 24
	fileHeaderSize      = fileMagicSize + fileNonceSize
	blockHeaderSize     = secretbox.Overhead
	blockDataSize       = 64 * 1024
	blockSize           = blockHeaderSize + blockDataSize
	encryptedSuffix     = ".bin" // when file name encryption is off we add this suffix to make sure the cloud provider doesn't process the file
)

// Errors returned by Cipher
var (
	ErrorBadDecryptUTF8          = errors.New("bad decryption - utf-8 invalid")
	ErrorBadDecryptControlChar   = errors.New("bad decryption - contains control chars")
	ErrorNotAMultipleOfBlocksize = errors.New("not a multiple of blocksize")
	ErrorTooShortAfterDecode     = errors.New("too short after base32 decode")
	ErrorTooLongAfterDecode      = errors.New("too long after base32 decode")
	ErrorEncryptedFileTooShort   = errors.New("file is too short to be encrypted")
	ErrorEncryptedFileBadHeader  = errors.New("file has truncated block header")
	ErrorEncryptedBadMagic       = errors.New("not an encrypted file - bad magic string")
	ErrorEncryptedBadBlock       = errors.New("failed to authenticate decrypted block - bad password?")
	ErrorBadBase32Encoding       = errors.New("bad base32 filename encoding")
	ErrorFileClosed              = errors.New("file already closed")
	ErrorNotAnEncryptedFile      = errors.New("not an encrypted file - no \"" + encryptedSuffix + "\" suffix")
	ErrorBadSeek                 = errors.New("Seek beyond end of file")
	defaultSalt                  = []byte{0xA8, 0x0D, 0xF4, 0x3A, 0x8F, 0xBD, 0x03, 0x08, 0xA7, 0xCA, 0xB8, 0x3E, 0x58, 0x1F, 0x86, 0xB1}
	obfuscQuoteRune              = '!'
)

// Global variables
var (
	fileMagicBytes = []byte(fileMagic)
)

// ReadSeekCloser is the interface of the read handles
type ReadSeekCloser interface {
	io.Reader
	io.Seeker
	io.Closer
	fs.RangeSeeker
}

// OpenRangeSeek opens the file handle at the offset with the limit given
type OpenRangeSeek func(ctx context.Context, offset, limit int64) (io.ReadCloser, error)

type masterKey struct {
	scryptSalt string
	scryptCostParam int
	scryptBlockSize int
	primaryMasterKey string
	hmacMasterKey string
	version int
}

type Cipher struct {
	key masterKey
	encryptionKey []byte
}

// newCipher initialises the Cipher.  If salt is "" then it uses a built in salt val
// IN PROGRESS
func newCipher(obj fs.Object) (*Cipher, error) {


	return c, nil
}

// getBlock gets a block from the pool of size blockSize
func (c *Cipher) getBlock() []byte {
	return c.buffers.Get().([]byte)
}

// putBlock returns a block to the pool of size blockSize
func (c *Cipher) putBlock(buf []byte) {
	if len(buf) != blockSize {
		panic("bad blocksize returned to pool")
	}
	c.buffers.Put(buf)
}

// encodeFileName encodes a filename using a modified version of
// standard base32 as described in RFC4648
//
// The standard encoding is modified in two ways
//  * it becomes lower case (no-one likes upper case filenames!)
//  * we strip the padding character `=`
func encodeFileName(in []byte) string {
	encoded := base32.HexEncoding.EncodeToString(in)
	return strings.ToLower(encoded)
}

// decodeFileName decodes a filename as encoded by encodeFileName
func decodeFileName(in string) ([]byte, error) {
	if strings.HasSuffix(in, "=") {
		return nil, ErrorBadBase32Encoding
	}
	// First figure out how many padding characters to add
	roundUpToMultipleOf8 := (len(in) + 7) &^ 7
	equals := roundUpToMultipleOf8 - len(in)
	in = strings.ToUpper(in) + "========"[:equals]
	return base32.HexEncoding.DecodeString(in)
}

// encryptSegment encrypts a path segment
//
// This uses EME with AES
//
// EME (ECB-Mix-ECB) is a wide-block encryption mode presented in the
// 2003 paper "A Parallelizable Enciphering Mode" by Halevi and
// Rogaway.
//
// This makes for determinstic encryption which is what we want - the
// same filename must encrypt to the same thing.
//
// This means that
//  * filenames with the same name will encrypt the same
//  * filenames which start the same won't have a common prefix
func (c *Cipher) encryptSegment(plaintext string) string {
	if plaintext == "" {
		return ""
	}
	paddedPlaintext := pkcs7.Pad(nameCipherBlockSize, []byte(plaintext))
	ciphertext := eme.Transform(c.block, c.nameTweak[:], paddedPlaintext, eme.DirectionEncrypt)
	return encodeFileName(ciphertext)
}

// decryptSegment decrypts a path segment
func (c *Cipher) decryptSegment(ciphertext string) (string, error) {
	if ciphertext == "" {
		return "", nil
	}
	rawCiphertext, err := decodeFileName(ciphertext)
	if err != nil {
		return "", err
	}
	if len(rawCiphertext)%nameCipherBlockSize != 0 {
		return "", ErrorNotAMultipleOfBlocksize
	}
	if len(rawCiphertext) == 0 {
		// not possible if decodeFilename() working correctly
		return "", ErrorTooShortAfterDecode
	}
	if len(rawCiphertext) > 2048 {
		return "", ErrorTooLongAfterDecode
	}
	paddedPlaintext := eme.Transform(c.block, c.nameTweak[:], rawCiphertext, eme.DirectionDecrypt)
	plaintext, err := pkcs7.Unpad(nameCipherBlockSize, paddedPlaintext)
	if err != nil {
		return "", err
	}
	return string(plaintext), err
}

// EncryptFileName encrypts a file path
func (c *Cipher) EncryptFileName(in string) string {
	if c.mode == NameEncryptionOff {
		return in + encryptedSuffix
	}
	return c.encryptFileName(in)
}

// pathToFilename gets the filename from a full path
func pathToFilename(in string) string {
	segments := strings.Split("/", in)
	return segments[len(segments) - 1]
}


// EncryptFileContents
// IN PROGRESS
func (c *Cipher) EncryptFileContents(in io.Reader) {

}

// EncryptDirName encrypts a directory path
// Returns 4 values
// cipherTextName for the name of the file to place in the directory to refer to the directory
// location for the actual location of the directory
// dirId for the directory ID to place in the file referring to the directory
// err indicating whether there was an error
// DONE
func (c *Cipher) EncryptDirName(in string, parentDirId string) (cipherTextName string, location string, err error) {
	dirIdb := []byte{}
	if in =! "" && in != "/" {
		dirIdb = uuid.New().([]byte)
	}
	// Get key
	key, err := c.getKey()
	if err != nil {
		return
	}

	cipherTextName, err = c.GetDirFilename([]byte{in}, parentDirId)
	if err != nil {
		return
	}
	location, err = c.uuidToPath(dirIdb)
	if err != nil {
		return
	}
	location = "/d/" + dirIdHash[0:2] + "/" + dirIdHash[2:]
	return
}

// GetDirFilename gets the name of the directory file from the directory name and parent directory id
// DONE
func (c *Cipher) GetDirFilename(dirName []byte, parentDirId []byte) (file string, err error) {
	ctName, err := siv.Encrypt(nil, c.encryptionKey, dirName, [][]byte{parentDirId})
	if err != nil {
		return
	}
	file = "0" + encodeFileName(ctName)
	return
}

// DecryptDirName gets the name of the directory from the name of the directory file in the remote and the parent directory id
// DONE
func (c *Cipher) DecryptDirName(filename string, parentDirId []byte) (dirName []byte, err error) {
	// remove the prepended 0 from directory files and decode it
	decodedName, err := decodeFileName(filename[1:])
	if err != nil {
		return
	}
	dirName, err = siv.Decrypt(c.encryptionKey, decodedName, [][]byte{parentDirId})
	return
}

// GetFilename gets the name of the file in a directory from the filename and directory parent Id
// DONE
func (c *Cipher) GetFilename(filename []byte, parentDirId []byte) (file string, err error) {
	ctName, err := siv.Encrypt(nil, c.encryptionKey, filename, [][]byte{parentDirId})
	if err != nil {
		return
	}
	file = encodeFileName(ctName)
	return
}

// DecryptFilename decrypts the actual filename of a file from the name of the file and the parent dirId
// DONE
func (c *Cipher) DecryptFilename(filename string, parentDirId []byte) (file []byte, err error) {
	decodedFilename, err := decodeFileName(filename)
	if err != nil {
		return
	}
	file, err = siv.Decrypt(c.encryptionKey, decodedFilename, [][]byte{parentDirId})
	if err != nil {
		return nil, err
	}
}

// DirIdToPath converts a given dirId to the path it would be at
// Done
func (c *Cipher) DirIdToPath(dirId []byte) (path string, err error) {
	dirIdEncrypted, err := siv.Encrypt(nil, c.encryptionKey, dirId, nil)
	if err != nil {
		return
	}
	dirIdHash := encodeFileName(sha1.Sum(dirIdEncrypted)[:])
	path = "/d/" + dirIdHash[0:2] + "/" + dirIdHash[2:]
	return
}

// getKey returns the encryption key as a slice of bytes
// IN PROGRESS
func (c *Cipher) getKey() ([]byte, error) {
	encKey, err := base64.StdEncoding.DecodeString(c.key.primaryMasterKey)
	if err != nil {
		return nil, err
	}
	macKey, err := base64.StdEncoding.DecodeString(c.key.hmacMasterKey)
	if err != nil {
		return nil, err
	}
	key := append(encKey, macKey...)
	return key, err
}

// setKey sets the key encryption to the given slice of bytes
// DONE
func (c *Cipher) setKey(in []byte) error {
	macKey := in[0:len(in) / 2]
	encKey := in[len(in) / 2:]
	c.primaryMasterKey = base64.StdEncoding.EncodeToString(encKey)
	c.hmacMasterKey = base64.StdEncoding.EncodeToString(macKey)
}

// nonce is an NACL secretbox nonce
type nonce [fileNonceSize]byte

// pointer returns the nonce as a *[24]byte for secretbox
func (n *nonce) pointer() *[fileNonceSize]byte {
	return (*[fileNonceSize]byte)(n)
}

// fromReader fills the nonce from an io.Reader - normally the OSes
// crypto random number generator
func (n *nonce) fromReader(in io.Reader) error {
	read, err := io.ReadFull(in, (*n)[:])
	if read != fileNonceSize {
		return errors.Wrap(err, "short read of nonce")
	}
	return nil
}

// fromBuf fills the nonce from the buffer passed in
func (n *nonce) fromBuf(buf []byte) {
	read := copy((*n)[:], buf)
	if read != fileNonceSize {
		panic("buffer to short to read nonce")
	}
}

// carry 1 up the nonce from position i
func (n *nonce) carry(i int) {
	for ; i < len(*n); i++ {
		digit := (*n)[i]
		newDigit := digit + 1
		(*n)[i] = newDigit
		if newDigit >= digit {
			// exit if no carry
			break
		}
	}
}

// increment to add 1 to the nonce
func (n *nonce) increment() {
	n.carry(0)
}

// add an uint64 to the nonce
func (n *nonce) add(x uint64) {
	carry := uint16(0)
	for i := 0; i < 8; i++ {
		digit := (*n)[i]
		xDigit := byte(x)
		x >>= 8
		carry += uint16(digit) + uint16(xDigit)
		(*n)[i] = byte(carry)
		carry >>= 8
	}
	if carry != 0 {
		n.carry(8)
	}
}

// encrypter encrypts an io.Reader on the fly
type encrypter struct {
	mu       sync.Mutex
	in       io.Reader
	c        *Cipher
	nonce    nonce
	buf      []byte
	readBuf  []byte
	bufIndex int
	bufSize  int
	err      error
}

// newEncrypter creates a new file handle encrypting on the fly
func (c *Cipher) newEncrypter(in io.Reader, nonce *nonce) (*encrypter, error) {
	fh := &encrypter{
		in:      in,
		c:       c,
		buf:     c.getBlock(),
		readBuf: c.getBlock(),
		bufSize: fileHeaderSize,
	}
	// Initialise nonce
	if nonce != nil {
		fh.nonce = *nonce
	} else {
		err := fh.nonce.fromReader(c.cryptoRand)
		if err != nil {
			return nil, err
		}
	}
	// Copy magic into buffer
	copy(fh.buf, fileMagicBytes)
	// Copy nonce into buffer
	copy(fh.buf[fileMagicSize:], fh.nonce[:])
	return fh, nil
}

// Read as per io.Reader
func (fh *encrypter) Read(p []byte) (n int, err error) {
	fh.mu.Lock()
	defer fh.mu.Unlock()

	if fh.err != nil {
		return 0, fh.err
	}
	if fh.bufIndex >= fh.bufSize {
		// Read data
		// FIXME should overlap the reads with a go-routine and 2 buffers?
		readBuf := fh.readBuf[:blockDataSize]
		n, err = io.ReadFull(fh.in, readBuf)
		if n == 0 {
			// err can't be nil since:
			// n == len(buf) if and only if err == nil.
			return fh.finish(err)
		}
		// possibly err != nil here, but we will process the
		// data and the next call to ReadFull will return 0, err
		// Write nonce to start of block
		copy(fh.buf, fh.nonce[:])
		// Encrypt the block using the nonce
		block := fh.buf
		secretbox.Seal(block[:0], readBuf[:n], fh.nonce.pointer(), &fh.c.dataKey)
		fh.bufIndex = 0
		fh.bufSize = blockHeaderSize + n
		fh.nonce.increment()
	}
	n = copy(p, fh.buf[fh.bufIndex:fh.bufSize])
	fh.bufIndex += n
	return n, nil
}

// finish sets the final error and tidies up
func (fh *encrypter) finish(err error) (int, error) {
	if fh.err != nil {
		return 0, fh.err
	}
	fh.err = err
	fh.c.putBlock(fh.buf)
	fh.buf = nil
	fh.c.putBlock(fh.readBuf)
	fh.readBuf = nil
	return 0, err
}

// Encrypt data encrypts the data stream
func (c *Cipher) EncryptData(in io.Reader) (io.Reader, error) {
	in, wrap := accounting.UnWrap(in) // unwrap the accounting off the Reader
	out, err := c.newEncrypter(in, nil)
	if err != nil {
		return nil, err
	}
	return wrap(out), nil // and wrap the accounting back on
}

// decrypter decrypts an io.ReaderCloser on the fly
type decrypter struct {
	mu           sync.Mutex
	rc           io.ReadCloser
	nonce        nonce
	initialNonce nonce
	c            *Cipher
	buf          []byte
	readBuf      []byte
	bufIndex     int
	bufSize      int
	err          error
	limit        int64 // limit of bytes to read, -1 for unlimited
	open         OpenRangeSeek
}

// newDecrypter creates a new file handle decrypting on the fly
func (c *Cipher) newDecrypter(rc io.ReadCloser) (*decrypter, error) {
	fh := &decrypter{
		rc:      rc,
		c:       c,
		buf:     c.getBlock(),
		readBuf: c.getBlock(),
		limit:   -1,
	}
	// Read file header (magic + nonce)
	readBuf := fh.readBuf[:fileHeaderSize]
	_, err := io.ReadFull(fh.rc, readBuf)
	if err == io.EOF || err == io.ErrUnexpectedEOF {
		// This read from 0..fileHeaderSize-1 bytes
		return nil, fh.finishAndClose(ErrorEncryptedFileTooShort)
	} else if err != nil {
		return nil, fh.finishAndClose(err)
	}
	// check the magic
	if !bytes.Equal(readBuf[:fileMagicSize], fileMagicBytes) {
		return nil, fh.finishAndClose(ErrorEncryptedBadMagic)
	}
	// retrieve the nonce
	fh.nonce.fromBuf(readBuf[fileMagicSize:])
	fh.initialNonce = fh.nonce
	return fh, nil
}

// newDecrypterSeek creates a new file handle decrypting on the fly
func (c *Cipher) newDecrypterSeek(ctx context.Context, open OpenRangeSeek, offset, limit int64) (fh *decrypter, err error) {
	var rc io.ReadCloser
	doRangeSeek := false
	setLimit := false
	// Open initially with no seek
	if offset == 0 && limit < 0 {
		// If no offset or limit then open whole file
		rc, err = open(ctx, 0, -1)
	} else if offset == 0 {
		// If no offset open the header + limit worth of the file
		_, underlyingLimit, _, _ := calculateUnderlying(offset, limit)
		rc, err = open(ctx, 0, int64(fileHeaderSize)+underlyingLimit)
		setLimit = true
	} else {
		// Otherwise just read the header to start with
		rc, err = open(ctx, 0, int64(fileHeaderSize))
		doRangeSeek = true
	}
	if err != nil {
		return nil, err
	}
	// Open the stream which fills in the nonce
	fh, err = c.newDecrypter(rc)
	if err != nil {
		return nil, err
	}
	fh.open = open // will be called by fh.RangeSeek
	if doRangeSeek {
		_, err = fh.RangeSeek(ctx, offset, io.SeekStart, limit)
		if err != nil {
			_ = fh.Close()
			return nil, err
		}
	}
	if setLimit {
		fh.limit = limit
	}
	return fh, nil
}

// read data into internal buffer - call with fh.mu held
func (fh *decrypter) fillBuffer() (err error) {
	// FIXME should overlap the reads with a go-routine and 2 buffers?
	readBuf := fh.readBuf
	n, err := io.ReadFull(fh.rc, readBuf)
	if n == 0 {
		// err can't be nil since:
		// n == len(buf) if and only if err == nil.
		return err
	}
	// possibly err != nil here, but we will process the data and
	// the next call to ReadFull will return 0, err

	// Check header + 1 byte exists
	if n <= blockHeaderSize {
		if err != nil {
			return err // return pending error as it is likely more accurate
		}
		return ErrorEncryptedFileBadHeader
	}
	// Decrypt the block using the nonce
	block := fh.buf
	_, ok := secretbox.Open(block[:0], readBuf[:n], fh.nonce.pointer(), &fh.c.dataKey)
	if !ok {
		if err != nil {
			return err // return pending error as it is likely more accurate
		}
		return ErrorEncryptedBadBlock
	}
	fh.bufIndex = 0
	fh.bufSize = n - blockHeaderSize
	fh.nonce.increment()
	return nil
}

// Read as per io.Reader
func (fh *decrypter) Read(p []byte) (n int, err error) {
	fh.mu.Lock()
	defer fh.mu.Unlock()

	if fh.err != nil {
		return 0, fh.err
	}
	if fh.bufIndex >= fh.bufSize {
		err = fh.fillBuffer()
		if err != nil {
			return 0, fh.finish(err)
		}
	}
	toCopy := fh.bufSize - fh.bufIndex
	if fh.limit >= 0 && fh.limit < int64(toCopy) {
		toCopy = int(fh.limit)
	}
	n = copy(p, fh.buf[fh.bufIndex:fh.bufIndex+toCopy])
	fh.bufIndex += n
	if fh.limit >= 0 {
		fh.limit -= int64(n)
		if fh.limit == 0 {
			return n, fh.finish(io.EOF)
		}
	}
	return n, nil
}

// calculateUnderlying converts an (offset, limit) in a crypted file
// into an (underlyingOffset, underlyingLimit) for the underlying
// file.
//
// It also returns number of bytes to discard after reading the first
// block and number of blocks this is from the start so the nonce can
// be incremented.
func calculateUnderlying(offset, limit int64) (underlyingOffset, underlyingLimit, discard, blocks int64) {
	// blocks we need to seek, plus bytes we need to discard
	blocks, discard = offset/blockDataSize, offset%blockDataSize

	// Offset in underlying stream we need to seek
	underlyingOffset = int64(fileHeaderSize) + blocks*(blockHeaderSize+blockDataSize)

	// work out how many blocks we need to read
	underlyingLimit = int64(-1)
	if limit >= 0 {
		// bytes to read beyond the first block
		bytesToRead := limit - (blockDataSize - discard)

		// Read the first block
		blocksToRead := int64(1)

		if bytesToRead > 0 {
			// Blocks that need to be read plus left over blocks
			extraBlocksToRead, endBytes := bytesToRead/blockDataSize, bytesToRead%blockDataSize
			if endBytes != 0 {
				// If left over bytes must read another block
				extraBlocksToRead++
			}
			blocksToRead += extraBlocksToRead
		}

		// Must read a whole number of blocks
		underlyingLimit = blocksToRead * (blockHeaderSize + blockDataSize)
	}
	return
}

// RangeSeek behaves like a call to Seek(offset int64, whence
// int) with the output wrapped in an io.LimitedReader
// limiting the total length to limit.
//
// RangeSeek with a limit of < 0 is equivalent to a regular Seek.
func (fh *decrypter) RangeSeek(ctx context.Context, offset int64, whence int, limit int64) (int64, error) {
	fh.mu.Lock()
	defer fh.mu.Unlock()

	if fh.open == nil {
		return 0, fh.finish(errors.New("can't seek - not initialised with newDecrypterSeek"))
	}
	if whence != io.SeekStart {
		return 0, fh.finish(errors.New("can only seek from the start"))
	}

	// Reset error or return it if not EOF
	if fh.err == io.EOF {
		fh.unFinish()
	} else if fh.err != nil {
		return 0, fh.err
	}

	underlyingOffset, underlyingLimit, discard, blocks := calculateUnderlying(offset, limit)

	// Move the nonce on the correct number of blocks from the start
	fh.nonce = fh.initialNonce
	fh.nonce.add(uint64(blocks))

	// Can we seek underlying stream directly?
	if do, ok := fh.rc.(fs.RangeSeeker); ok {
		// Seek underlying stream directly
		_, err := do.RangeSeek(ctx, underlyingOffset, 0, underlyingLimit)
		if err != nil {
			return 0, fh.finish(err)
		}
	} else {
		// if not reopen with seek
		_ = fh.rc.Close() // close underlying file
		fh.rc = nil

		// Re-open the underlying object with the offset given
		rc, err := fh.open(ctx, underlyingOffset, underlyingLimit)
		if err != nil {
			return 0, fh.finish(errors.Wrap(err, "couldn't reopen file with offset and limit"))
		}

		// Set the file handle
		fh.rc = rc
	}

	// Fill the buffer
	err := fh.fillBuffer()
	if err != nil {
		return 0, fh.finish(err)
	}

	// Discard bytes from the buffer
	if int(discard) > fh.bufSize {
		return 0, fh.finish(ErrorBadSeek)
	}
	fh.bufIndex = int(discard)

	// Set the limit
	fh.limit = limit

	return offset, nil
}

// Seek implements the io.Seeker interface
func (fh *decrypter) Seek(offset int64, whence int) (int64, error) {
	return fh.RangeSeek(context.TODO(), offset, whence, -1)
}

// finish sets the final error and tidies up
func (fh *decrypter) finish(err error) error {
	if fh.err != nil {
		return fh.err
	}
	fh.err = err
	fh.c.putBlock(fh.buf)
	fh.buf = nil
	fh.c.putBlock(fh.readBuf)
	fh.readBuf = nil
	return err
}

// unFinish undoes the effects of finish
func (fh *decrypter) unFinish() {
	// Clear error
	fh.err = nil

	// reinstate the buffers
	fh.buf = fh.c.getBlock()
	fh.readBuf = fh.c.getBlock()

	// Empty the buffer
	fh.bufIndex = 0
	fh.bufSize = 0
}

// Close
func (fh *decrypter) Close() error {
	fh.mu.Lock()
	defer fh.mu.Unlock()

	// Check already closed
	if fh.err == ErrorFileClosed {
		return fh.err
	}
	// Closed before reading EOF so not finish()ed yet
	if fh.err == nil {
		_ = fh.finish(io.EOF)
	}
	// Show file now closed
	fh.err = ErrorFileClosed
	if fh.rc == nil {
		return nil
	}
	return fh.rc.Close()
}

// finishAndClose does finish then Close()
//
// Used when we are returning a nil fh from new
func (fh *decrypter) finishAndClose(err error) error {
	_ = fh.finish(err)
	_ = fh.Close()
	return err
}

// DecryptData decrypts the data stream
func (c *Cipher) DecryptData(rc io.ReadCloser) (io.ReadCloser, error) {
	out, err := c.newDecrypter(rc)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// DecryptDataSeek decrypts the data stream from offset
//
// The open function must return a ReadCloser opened to the offset supplied
//
// You must use this form of DecryptData if you might want to Seek the file handle
func (c *Cipher) DecryptDataSeek(ctx context.Context, open OpenRangeSeek, offset, limit int64) (ReadSeekCloser, error) {
	out, err := c.newDecrypterSeek(ctx, open, offset, limit)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// EncryptedSize calculates the size of the data when encrypted
func (c *Cipher) EncryptedSize(size int64) int64 {
	blocks, residue := size/blockDataSize, size%blockDataSize
	encryptedSize := int64(fileHeaderSize) + blocks*(blockHeaderSize+blockDataSize)
	if residue != 0 {
		encryptedSize += blockHeaderSize + residue
	}
	return encryptedSize
}

// DecryptedSize calculates the size of the data when decrypted
func (c *Cipher) DecryptedSize(size int64) (int64, error) {
	size -= int64(fileHeaderSize)
	if size < 0 {
		return 0, ErrorEncryptedFileTooShort
	}
	blocks, residue := size/blockSize, size%blockSize
	decryptedSize := blocks * blockDataSize
	if residue != 0 {
		residue -= blockHeaderSize
		if residue <= 0 {
			return 0, ErrorEncryptedFileBadHeader
		}
	}
	decryptedSize += residue
	return decryptedSize, nil
}

// check interfaces
var (
	_ Cipher         = (*Cipher)(nil)
	_ io.ReadCloser  = (*decrypter)(nil)
	_ io.Seeker      = (*decrypter)(nil)
	_ fs.RangeSeeker = (*decrypter)(nil)
	_ io.Reader      = (*encrypter)(nil)
)
