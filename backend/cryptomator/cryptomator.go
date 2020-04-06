// Package cryptomator provides wrappers for Fs and Object which implement Cryptomator encryption
package cryptomator

import (
	"context"
	"fmt"
	"io"
	"io/ioutil"
	"path"
	"strings"

	"github.com/pkg/errors"
	"github.com/rclone/rclone/fs"
	"github.com/rclone/rclone/fs/accounting"
	"github.com/rclone/rclone/fs/config/configmap"
	"github.com/rclone/rclone/fs/config/configstruct"
	"github.com/rclone/rclone/fs/fspath"
	"github.com/rclone/rclone/fs/hash"
)

// Globals
// Register with Fs
func init() {
	fs.Register(&fs.RegInfo{
		Name:        "cryptomator",
		Description: "Encrypt/Decrypt a remote with the Cryptomator implementation",
		NewFs:       NewFs,
		Options: []fs.Option{{
			Name:     "remote",
			Help:     "Remote to encrypt/decrypt.\nNormally should contain a ':' and a path, eg \"myremote:path/to/dir\",\n\"myremote:bucket\" or maybe \"myremote:\" (not recommended).",
			Required: true,
		}, {
			Name:       "password",
			Help:       "Password or pass phrase for encryption.",
			IsPassword: true,
			Required:   true,
		},},
	})
}

// NewFs constructs an Fs from the path, container:path
func NewFs(name, rpath string, m configmap.Mapper) (fs.Fs, error) {
	// Parse config into Options struct
	opt := new(Options)
	err := configstruct.Set(m, opt)
	if err != nil {
		return nil, err
	}
	cipher, err := newCipherForConfig(opt)
	if err != nil {
		return nil, err
	}
	remote := opt.Remote
	if strings.HasPrefix(remote, name+":") {
		return nil, errors.New("can't point crypt remote at itself - check the value of the remote setting")
	}
	wInfo, wName, wPath, wConfig, err := fs.ConfigFs(remote)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to parse remote %q to wrap", remote)
	}
	// Make sure to remove trailing . reffering to the current dir
	if path.Base(rpath) == "." {
		rpath = strings.TrimSuffix(rpath, ".")
	}
	// Look for a file first
	remotePath := fspath.JoinRootPath(wPath, cipher.EncryptFileName(rpath))
	wrappedFs, err := wInfo.NewFs(wName, remotePath, wConfig)
	// if that didn't produce a file, look for a directory
	if err != fs.ErrorIsFile {
		remotePath = fspath.JoinRootPath(wPath, cipher.EncryptDirName(rpath))
		wrappedFs, err = wInfo.NewFs(wName, remotePath, wConfig)
	}
	if err != fs.ErrorIsFile && err != nil {
		return nil, errors.Wrapf(err, "failed to make remote %s:%q to wrap", wName, remotePath)
	}
	f := &Fs{
		Fs:     wrappedFs,
		name:   name,
		root:   rpath,
		opt:    *opt,
	}
	// the features here are ones we could support, and they are
	// ANDed with the ones from wrappedFs
	f.features = (&fs.Features{
		CaseInsensitive:         cipher.NameEncryptionMode() == NameEncryptionOff,
		DuplicateFiles:          true,
		ReadMimeType:            false, // MimeTypes not supported with crypt
		WriteMimeType:           false,
		BucketBased:             true,
		CanHaveEmptyDirectories: true,
		SetTier:                 true,
		GetTier:                 true,
	}).Fill(f).Mask(wrappedFs).WrapsFs(f, wrappedFs)

	return f, err
}

// Options defines the configuration for this backend
type Options struct {
	Remote                  string `config:"remote"`
	Password                string `config:"password"`
}

// Fs represents a wrapped fs.Fs
type Fs struct {
	fs.Fs
	wrapper  fs.Fs
	name     string
	root     string
	opt      Options
	features *fs.Features // optional features
	cipher   Cipher
}

// Name of the remote (as passed into NewFs)
func (f *Fs) Name() string {
	return f.name
}

// Root of the remote (as passed into NewFs)
func (f *Fs) Root() string {
	return f.root
}

// Features returns the optional features of this Fs
func (f *Fs) Features() *fs.Features {
	return f.features
}

// String returns a description of the FS
func (f *Fs) String() string {
	return fmt.Sprintf("Encrypted drive '%s:%s'", f.name, f.root)
}

// List the objects and directories in dir into entries.  The
// entries can be returned in any order but should be for a
// complete directory.
//
// dir should be "" to list the root, and should not have
// trailing slashes.
//
// This should return ErrDirNotFound if the directory isn't
// found.
// IN PROGRESS
func (f *Fs) List(ctx context.Context, dir string) (entries fs.DirEntries, err error) {
	realPath, parentDirId, err := f.findPath(ctx, dir)
	if err != nil {
		return
	}
	rawEntries, err := f.Fs.List(ctx, realPath)
	if err != nil {
		return
	}
	return f.rawEntriesToEntries(ctx, parentDirId, entries)
}

// rawEntriesToEntries converts a given fs.DirEntries to decrypted entries of the files
// DONE
func (f *Fs) rawEntriesToEntries(ctx context.Context, parentDirId []byte, entries fs.DirEntries) (newEntries fs.DirEntries, err error) {
	newEntries = entries[:0] // in place filter
	for _, entry := range entries {
		switch entry.(type) {
		case fs.Object:
			if strings.HasPrefix(entry.String(), "0") {
				f.addDir(ctx, parentDirId, &newEntries, entry.(fs.Object))
			} else {
				f.add(&newEntries, parentDirId, entry.(fs.Object))
			}
		default:
			return nil, errors.Errorf("Unknown object type %T", entry)
		}
	}
	return newEntries, nil
}

// Encrypt an object file name to entries.
// DONE
func (f *Fs) add(entries *fs.DirEntries, parentDirId []byte, obj fs.Object) {
	_, err := f.cipher.DecryptFilename(obj.String(), parentDirId)
	if err != nil {
		fs.Debugf(remote, "Skipping undecryptable file name: %v", err)
		return
	}
	*entries = append(*entries, f.newObject(obj, parentDirId))
}

// Encrypt a directory file name to entries.
// DONE
func (f *Fs) addDir(ctx context.Context, parentDirId []byte, entries *fs.DirEntries, dir fs.Object) {
	decryptedRemote, err := f.cipher.DecryptDirName(dir.String(), parentDirId)
	if err != nil {
		fs.Debugf(remote, "Skipping undecryptable dir name: %v", err)
		return
	}
	*entries = append(*entries, f.newDir(ctx, string(decryptedRemote), dir))
}

// findPath finds the true location of a given directory or file
// DONE
func (f *Fs) findPath (ctx context.Context, path string) (remotePath string, parentDirId []byte, err error) {
	rootDirPath, err := f.cipher.DirIdToPath([]byte{})
	if err != nil {
		return "", nil, err
	}
	return f.recursiveFindPath(ctx, rootDirPath, []byte{}, []byte{}, strings.Split(path, "/"))
}

// recursiveFindPath is only used internally
// DONE
func (f *Fs) recursiveFindPath (ctx context.Context, currentPath string, parentDirId []byte, currentDirId []byte, segments []string) (path string, dirId []byte, err error) {
	if len(segments) == 0 { // Base case for when the file or directory could not be found
		err = fs.ErrorObjectNotFound
		return
	}
	segment := segments[0]
	if len(segments) <= 1 { // Base case for when dealing with a file
		name, err := f.cipher.GetFilename([]byte{segment}, currentDirId)
		if err != nil {
			return "", nil, err
		}
		path = currentPath + "/" + name
		dirId = currentDirId
		_, err = f.Fs.NewObject(ctx, path)
		if err != nil && err != fs.ErrorObjectNotFound {
			return "", nil, err
		}
	}
	dirFile, err := f.cipher.GetDirFilename([]byte{segment}, parentDirId)
	if err != nil {
		return
	}
	obj, err := f.Fs.NewObject(ctx, currentPath + "/" + dirFile)
	if err != nil {
		return
	}
	opened, err := obj.Open(ctx)
	if err != nil {
		return
	}
	newDirId, err := ioutil.ReadAll(opened)
	if err != nil {
		return
	}
	newDirPath, err := f.cipher.DirIdToPath(newDirId)
	if err != nil {
		return
	}
	if len(segments) <= 1 { // Base case for when dealing with a directory
		path = newDirPath
		dirId = currentDirId
		return
	}
	return f.recursiveFindPath(ctx, newDirPath, currentDirId, newDirId, segments[1:])
}

// setUpCipher
// IN PROGRESS
func (f *Fs) setUpCipher(ctx context.Context) (err error) {
	obj, err := f.Fs.NewObject(ctx, "/masterkey.cryptomator")
	if err != nil {
		return
	}
	c, err := newCipher(obj)
	if err != nil {
		return
	}
	f.cipher = c
}

// NewObject finds the Object at remote.
func (f *Fs) NewObject(ctx context.Context, remote string) (fs.Object, error) {
	rawRemote, parentDirId, err := f.findPath(ctx, remote)
	if err != nil {
		return nil, err
	}
	o, err := f.Fs.NewObject(ctx, rawRemote)
	if err != nil {
		return nil, err
	}
	return f.newObject(o, parentDirId), nil
}

type putFn func(ctx context.Context, in io.Reader, src fs.ObjectInfo, options ...fs.OpenOption) (fs.Object, error)

// put implements Put or PutStream
func (f *Fs) put(ctx context.Context, in io.Reader, src fs.ObjectInfo, options []fs.OpenOption, put putFn) (fs.Object, error) {
	// Encrypt the data into wrappedIn
	wrappedIn, err := f.cipher.EncryptData(in)
	if err != nil {
		return nil, err
	}

	// Find a hash the destination supports to compute a hash of
	// the encrypted data
	ht := f.Fs.Hashes().GetOne()
	var hasher *hash.MultiHasher
	if ht != hash.None {
		hasher, err = hash.NewMultiHasherTypes(hash.NewHashSet(ht))
		if err != nil {
			return nil, err
		}
		// unwrap the accounting
		var wrap accounting.WrapFn
		wrappedIn, wrap = accounting.UnWrap(wrappedIn)
		// add the hasher
		wrappedIn = io.TeeReader(wrappedIn, hasher)
		// wrap the accounting back on
		wrappedIn = wrap(wrappedIn)
	}

	// Transfer the data
	o, err := put(ctx, wrappedIn, f.newObjectInfo(src), options...)
	if err != nil {
		return nil, err
	}

	// Check the hashes of the encrypted data if we were comparing them
	if ht != hash.None && hasher != nil {
		srcHash := hasher.Sums()[ht]
		var dstHash string
		dstHash, err = o.Hash(ctx, ht)
		if err != nil {
			return nil, errors.Wrap(err, "failed to read destination hash")
		}
		if srcHash != "" && dstHash != "" && srcHash != dstHash {
			// remove object
			err = o.Remove(ctx)
			if err != nil {
				fs.Errorf(o, "Failed to remove corrupted object: %v", err)
			}
			return nil, errors.Errorf("corrupted on transfer: %v crypted hash differ %q vs %q", ht, srcHash, dstHash)
		}
	}

	return f.newObject(o), nil
}

// Put in to the remote path with the modTime given of the given size
//
// May create the object even if it returns an error - if so
// will return the object and the error, otherwise will return
// nil and the error
func (f *Fs) Put(ctx context.Context, in io.Reader, src fs.ObjectInfo, options ...fs.OpenOption) (fs.Object, error) {
	return f.put(ctx, in, src, options, f.Fs.Put)
}

// PutStream uploads to the remote path with the modTime given of indeterminate size
func (f *Fs) PutStream(ctx context.Context, in io.Reader, src fs.ObjectInfo, options ...fs.OpenOption) (fs.Object, error) {
	return f.put(ctx, in, src, options, f.Fs.Features().PutStream)
}

// Hashes returns the supported hash sets.
// DONE
func (f *Fs) Hashes() hash.Set {
	return hash.Set(hash.None)
}

// Mkdir makes the directory (container, bucket)
//
// Shouldn't return an error if it already exists
func (f *Fs) Mkdir(ctx context.Context, dir string) error {
	return f.Fs.Mkdir(ctx, f.cipher.EncryptDirName(dir))
}

// Rmdir removes the directory (container, bucket) if empty
//
// Return an error if it doesn't exist or isn't empty
func (f *Fs) Rmdir(ctx context.Context, dir string) error {
	return f.Fs.Rmdir(ctx, f.cipher.EncryptDirName(dir))
}

// Purge all files in the root and the root directory
//
// Implement this if you have a way of deleting all the files
// quicker than just running Remove() on the result of List()
//
// Return an error if it doesn't exist
func (f *Fs) Purge(ctx context.Context) error {
	do := f.Fs.Features().Purge
	if do == nil {
		return fs.ErrorCantPurge
	}
	return do(ctx)
}

// CleanUp the trash in the Fs
//
// Implement this if you have a way of emptying the trash or
// otherwise cleaning up old versions of files.
func (f *Fs) CleanUp(ctx context.Context) error {
	do := f.Fs.Features().CleanUp
	if do == nil {
		return errors.New("can't CleanUp")
	}
	return do(ctx)
}

// About gets quota information from the Fs
func (f *Fs) About(ctx context.Context) (*fs.Usage, error) {
	do := f.Fs.Features().About
	if do == nil {
		return nil, errors.New("About not supported")
	}
	return do(ctx)
}

// UnWrap returns the Fs that this Fs is wrapping
func (f *Fs) UnWrap() fs.Fs {
	return f.Fs
}

// WrapFs returns the Fs that is wrapping this Fs
func (f *Fs) WrapFs() fs.Fs {
	return f.wrapper
}

// SetWrapper sets the Fs that is wrapping this Fs
func (f *Fs) SetWrapper(wrapper fs.Fs) {
	f.wrapper = wrapper
}

// ComputeHash takes the nonce from o, and encrypts the contents of
// src with it, and calculates the hash given by HashType on the fly
//
// Note that we break lots of encapsulation in this function.
func (f *Fs) ComputeHash(ctx context.Context, o *Object, src fs.Object, hashType hash.Type) (hashStr string, err error) {
	// Read the nonce - opening the file is sufficient to read the nonce in
	// use a limited read so we only read the header
	in, err := o.Object.Open(ctx, &fs.RangeOption{Start: 0, End: int64(fileHeaderSize) - 1})
	if err != nil {
		return "", errors.Wrap(err, "failed to open object to read nonce")
	}
	d, err := f.cipher.(*Cipher).newDecrypter(in)
	if err != nil {
		_ = in.Close()
		return "", errors.Wrap(err, "failed to open object to read nonce")
	}
	nonce := d.nonce
	// fs.Debugf(o, "Read nonce % 2x", nonce)

	// Check nonce isn't all zeros
	isZero := true
	for i := range nonce {
		if nonce[i] != 0 {
			isZero = false
		}
	}
	if isZero {
		fs.Errorf(o, "empty nonce read")
	}

	// Close d (and hence in) once we have read the nonce
	err = d.Close()
	if err != nil {
		return "", errors.Wrap(err, "failed to close nonce read")
	}

	// Open the src for input
	in, err = src.Open(ctx)
	if err != nil {
		return "", errors.Wrap(err, "failed to open src")
	}
	defer fs.CheckClose(in, &err)

	// Now encrypt the src with the nonce
	out, err := f.cipher.(*Cipher).newEncrypter(in, &nonce)
	if err != nil {
		return "", errors.Wrap(err, "failed to make encrypter")
	}

	// pipe into hash
	m, err := hash.NewMultiHasherTypes(hash.NewHashSet(hashType))
	if err != nil {
		return "", errors.Wrap(err, "failed to make hasher")
	}
	_, err = io.Copy(m, out)
	if err != nil {
		return "", errors.Wrap(err, "failed to hash data")
	}

	return m.Sums()[hashType], nil
}

// Object describes a wrapped for being read from the Fs
//
// This decrypts the remote name and decrypts the data
type Object struct {
	fs.Object
	f *Fs
	parentDirId []byte
}

// DONE
func (f *Fs) newObject(o fs.Object, parentDirId []byte) *Object {
	return &Object{
		Object: o,
		f:      f,
		parentDirId: parentDirId,
	}
}

// Fs returns read only access to the Fs that this object is part of
func (o *Object) Fs() fs.Info {
	return o.f
}

// Return a string version
func (o *Object) String() string {
	if o == nil {
		return "<nil>"
	}
	return o.Remote()
}

// Remote returns the remote path
func (o *Object) Remote() string {
	remote := o.Object.Remote()
	decryptedName, err := o.f.cipher.DecryptFileName(remote)
	if err != nil {
		fs.Debugf(remote, "Undecryptable file name: %v", err)
		return remote
	}
	return decryptedName
}

// Size returns the size of the file
func (o *Object) Size() int64 {
	size, err := o.f.cipher.DecryptedSize(o.Object.Size())
	if err != nil {
		fs.Debugf(o, "Bad size for decrypt: %v", err)
	}
	return size
}

// Hash returns the selected checksum of the file
// If no checksum is available it returns ""
func (o *Object) Hash(ctx context.Context, ht hash.Type) (string, error) {
	return "", hash.ErrUnsupported
}

// UnWrap returns the wrapped Object
func (o *Object) UnWrap() fs.Object {
	return o.Object
}

// Open opens the file for read.  Call Close() on the returned io.ReadCloser
func (o *Object) Open(ctx context.Context, options ...fs.OpenOption) (rc io.ReadCloser, err error) {
	var openOptions []fs.OpenOption
	var offset, limit int64 = 0, -1
	for _, option := range options {
		switch x := option.(type) {
		case *fs.SeekOption:
			offset = x.Offset
		case *fs.RangeOption:
			offset, limit = x.Decode(o.Size())
		default:
			// pass on Options to underlying open if appropriate
			openOptions = append(openOptions, option)
		}
	}
	rc, err = o.f.cipher.DecryptDataSeek(ctx, func(ctx context.Context, underlyingOffset, underlyingLimit int64) (io.ReadCloser, error) {
		if underlyingOffset == 0 && underlyingLimit < 0 {
			// Open with no seek
			return o.Object.Open(ctx, openOptions...)
		}
		// Open stream with a range of underlyingOffset, underlyingLimit
		end := int64(-1)
		if underlyingLimit >= 0 {
			end = underlyingOffset + underlyingLimit - 1
			if end >= o.Object.Size() {
				end = -1
			}
		}
		newOpenOptions := append(openOptions, &fs.RangeOption{Start: underlyingOffset, End: end})
		return o.Object.Open(ctx, newOpenOptions...)
	}, offset, limit)
	if err != nil {
		return nil, err
	}
	return rc, nil
}

// Update in to the object with the modTime given of the given size
func (o *Object) Update(ctx context.Context, in io.Reader, src fs.ObjectInfo, options ...fs.OpenOption) error {
	update := func(ctx context.Context, in io.Reader, src fs.ObjectInfo, options ...fs.OpenOption) (fs.Object, error) {
		return o.Object, o.Object.Update(ctx, in, src, options...)
	}
	_, err := o.f.put(ctx, in, src, options, update)
	return err
}

// newDir returns a dir with the Name decrypted
// DONE
func (f *Fs) newDir(ctx context.Context, decryptedRemote string, dir fs.Object) fs.Directory {
	remote := dir.Remote()
	newDir := fs.NewDir(remote, dir.ModTime(ctx))
	if err != nil {
		fs.Debugf(remote, "newDir error name: %v", err)
	} else {
		newDir.SetRemote(decryptedRemote)
	}
	return newDir
}

// UserInfo returns info about the connected user
func (f *Fs) UserInfo(ctx context.Context) (map[string]string, error) {
	do := f.Fs.Features().UserInfo
	if do == nil {
		return nil, fs.ErrorNotImplemented
	}
	return do(ctx)
}

// Disconnect the current user
func (f *Fs) Disconnect(ctx context.Context) error {
	do := f.Fs.Features().Disconnect
	if do == nil {
		return fs.ErrorNotImplemented
	}
	return do(ctx)
}

// ObjectInfo describes a wrapped fs.ObjectInfo for being the source
//
// This encrypts the remote name and adjusts the size
type ObjectInfo struct {
	fs.ObjectInfo
	f *Fs
}

func (f *Fs) newObjectInfo(src fs.ObjectInfo) *ObjectInfo {
	return &ObjectInfo{
		ObjectInfo: src,
		f:          f,
	}
}

// Fs returns read only access to the Fs that this object is part of
func (o *ObjectInfo) Fs() fs.Info {
	return o.f
}

// Remote returns the remote path
func (o *ObjectInfo) Remote() string {
	return o.f.cipher.EncryptFileName(o.ObjectInfo.Remote())
}

// Size returns the size of the file
func (o *ObjectInfo) Size() int64 {
	size := o.ObjectInfo.Size()
	if size < 0 {
		return size
	}
	return o.f.cipher.EncryptedSize(size)
}

// Hash returns the selected checksum of the file
// If no checksum is available it returns ""
func (o *ObjectInfo) Hash(ctx context.Context, hash hash.Type) (string, error) {
	return "", nil
}

// ID returns the ID of the Object if known, or "" if not
func (o *Object) ID() string {
	do, ok := o.Object.(fs.IDer)
	if !ok {
		return ""
	}
	return do.ID()
}

// SetTier performs changing storage tier of the Object if
// multiple storage classes supported
func (o *Object) SetTier(tier string) error {
	do, ok := o.Object.(fs.SetTierer)
	if !ok {
		return errors.New("crypt: underlying remote does not support SetTier")
	}
	return do.SetTier(tier)
}

// GetTier returns storage tier or class of the Object
func (o *Object) GetTier() string {
	do, ok := o.Object.(fs.GetTierer)
	if !ok {
		return ""
	}
	return do.GetTier()
}

// Check the interfaces are satisfied
var (
	_ fs.Fs              = (*Fs)(nil)
	_ fs.Purger          = (*Fs)(nil)
	_ fs.PutStreamer     = (*Fs)(nil)
	_ fs.CleanUpper      = (*Fs)(nil)
	_ fs.UnWrapper       = (*Fs)(nil)
	_ fs.Abouter         = (*Fs)(nil)
	_ fs.Wrapper         = (*Fs)(nil)
	_ fs.UserInfoer      = (*Fs)(nil)
	_ fs.Disconnecter    = (*Fs)(nil)
	_ fs.ObjectInfo      = (*ObjectInfo)(nil)
	_ fs.Object          = (*Object)(nil)
	_ fs.ObjectUnWrapper = (*Object)(nil)
	_ fs.IDer            = (*Object)(nil)
	_ fs.SetTierer       = (*Object)(nil)
	_ fs.GetTierer       = (*Object)(nil)
)
