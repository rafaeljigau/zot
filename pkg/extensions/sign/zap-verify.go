package sign

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"math/big"
	"path"
	"path/filepath"
	"strings"

	"github.com/containers/image/v5/signature"
	"github.com/mtrmac/gpgme"
	v1 "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/opencontainers/umoci"
	"github.com/pkg/errors"
)

var (
	ErrInvalidPrivateKey    = errors.New("sign: invalid private key")
	ErrInvalidPublicKey     = errors.New("sign: invalid public key")
	ErrInvalidInput         = errors.New("sign: input type should be media or oci")
	ErrInvalidSignatureType = errors.New("sign: invalid signature type")
	ErrInvalidAuthor        = errors.New("sign: invalid author")
	ErrBadHTTPResponse      = errors.New("http: unexpected response")
	ErrUnknownAuth          = errors.New("http: unknown authentication")
	ErrInvalidAppConfig     = errors.New("config: invalid app config")
	ErrIncorrectArgLength   = errors.New("cli: incorrect command arguments")
	ErrInvalidArgs          = errors.New("build:invalid arguments")
	ErrUnknownFormat        = errors.New("push: unknown image fomrat")
	ErrEmptyKey             = errors.New("build: empty key")
	ErrEmptyDirPath         = errors.New("sign: empty oci dir path")
	ErrIncorrectBytes       = errors.New("pack: incorrect bytes written")
	ErrInvalidUntarDir      = errors.New("unpack: untar dir contains more than one files")
	ErrHashMismatch         = errors.New("unpack: hash mismatch")
	ErrFingerprintMismatch  = errors.New("unpack: fingerprint mismatch")
	ErrIncorrectSigLength   = errors.New("sign: invalid signature length")
	ErrBadSignature         = errors.New("sign: bad signature")
	ErrInvalidBlobFile      = errors.New("pack: invalid blobs.yaml file")
	ErrTagNotFound          = errors.New("unpack: tag not found")
	ErrInvalidAciApp        = errors.New("convert: invalid aci app")
)

type VerifyOptions struct {
	InputData        string
	MediaFingerprint string
	Fingerprint      string
	Ref              string
	OptionalDir      string
	SigFilePath      string
	SignatureType    string
	InputType        string
	Author           string
}

type untrustedSignature struct {
	UntrustedHash string
}

type SignOptions struct { // nolint: golint
	OptionalDir   string // This field is needed in case of creating new GPGME context
	SignKey       string // GPG Key ID
	InputData     string // This can be path of index.json in case of OCI while tar media path in case of MEDIA
	SigFilePath   string // Signature file path including signature filename
	InputType     string // OCI or MEDIA
	SignatureType string // Type of Signature either gpg or pki
	InputRef      string // Docker reference needed to sign manifest
	Author        string // name/id of author who is signing.
}

type SignatureFile struct {
	Signatures map[string]SignatureInfo `json:"signatures"`
}

type SignatureInfo struct {
	CreatedAt string `json:"created"`
	Signature []byte `json:"signature"`
}

const (
	OCI    = "OCI"
	MEDIA  = "MEDIA"
	GPG    = "GPG"
	PKI    = "PKI"
	COSIGN = "COSIGN"
)

// this will return private key...
func (signOpts SignOptions) getPrivateKey() (*rsa.PrivateKey, error) {
	priv, err := ioutil.ReadFile(signOpts.SignKey)
	if err != nil {
		return &rsa.PrivateKey{}, errors.Wrapf(err, "sign: error reading signature file")
	}

	privPem, _ := pem.Decode(priv)

	var privPemBytes []byte

	if privPem.Type != "RSA PRIVATE KEY" && privPem.Type != "PRIVATE KEY" {
		return &rsa.PrivateKey{}, ErrInvalidPrivateKey
	}

	privPemBytes = privPem.Bytes

	var parsedKey interface{}

	if parsedKey, err = x509.ParsePKCS1PrivateKey(privPemBytes); err != nil {
		if parsedKey, err = x509.ParsePKCS8PrivateKey(privPemBytes); err != nil { // note this returns type `interface{}`
			return &rsa.PrivateKey{}, errors.Wrapf(ErrInvalidPrivateKey, "sign: error parsing rsa private key")
		}
	}

	var privateKey *rsa.PrivateKey

	var ok bool

	privateKey, ok = parsedKey.(*rsa.PrivateKey)
	if !ok {
		return &rsa.PrivateKey{}, errors.Wrapf(ErrInvalidPrivateKey, "error parsing private key")
	}

	return privateKey, nil
}

// this will return public key...
func (verifyOpts VerifyOptions) getPublicKey() (*ecdsa.PublicKey, error) {
	pub, err := ioutil.ReadFile(verifyOpts.Fingerprint)
	if err != nil {
		return &ecdsa.PublicKey{}, errors.Wrapf(err, "error reading public key")
	}

	pubPem, _ := pem.Decode(pub)
	if pubPem == nil {
		return &ecdsa.PublicKey{}, errors.Wrapf(ErrInvalidPublicKey, "not able to decode public key")
	}

	if pubPem.Type != "RSA PUBLIC KEY" && pubPem.Type != "PUBLIC KEY" {
		return &ecdsa.PublicKey{}, errors.Wrapf(ErrInvalidPublicKey, "invalid rsa key type")
	}

	var parsedKey interface{}

	if parsedKey, err = x509.ParsePKIXPublicKey(pubPem.Bytes); err != nil {
		return &ecdsa.PublicKey{}, errors.Wrapf(ErrInvalidPublicKey, "error parsing rsa public key")
	}

	var pubKey *ecdsa.PublicKey

	pubKey, ok := parsedKey.(*ecdsa.PublicKey)
	fmt.Println(pubKey)
	if !ok {
		return &ecdsa.PublicKey{}, errors.Wrapf(ErrInvalidPublicKey, "error casting into rsa public key")
	}

	return pubKey, nil
}

func (verifyOpts VerifyOptions) verifyCosign() error {
	publicKey, err := verifyOpts.getPublicKey()
	if err != nil {
		return errors.Wrapf(err, "sign: error reading public key")
	}

	manifest, err := getImageManifest(verifyOpts.InputData, false)
	if err != nil {
		return errors.Wrapf(err, "sign: error getting image manifest")
	}

	manifestBytes, err := json.Marshal(manifest)
	if err != nil {
		return errors.Wrapf(err, "sign: error marshalling manifest")
	}

	hashMessage := sha256.Sum256(manifestBytes)

	sigManifest, err := getImageManifest(verifyOpts.InputData, true)
	if err != nil {
		return errors.Wrapf(err, "sign: error getting signature manifest")
	}

	sigBlobPath := path.Join(filepath.Dir(verifyOpts.InputData), "blobs", sigManifest.Digest.Algorithm().String(), sigManifest.Digest.Encoded())

	sigBlob, err := ioutil.ReadFile(sigBlobPath)
	if err != nil {
		return errors.Wrapf(err, "sign: error reading signature manifest blob")
	}

	var m v1.Manifest

	err = json.Unmarshal(sigBlob, &m)
	if err != nil {
		return errors.Wrapf(err, "sign: error unmarshalling signature manifest blob")
	}

	if len(m.Layers) == 0 {
		return errors.New("sign: invalid signature manifest")
	}

	sigLayer := m.Layers[0]

	layerBlobPath := path.Join(filepath.Dir(verifyOpts.InputData), "blobs", sigLayer.Digest.Algorithm().String(), sigLayer.Digest.Encoded())

	layerBlob, err := ioutil.ReadFile(layerBlobPath)
	if err != nil {
		return errors.Wrapf(err, "sign: error reading signature manifest blob")
	}

	var sigFile SignatureFile

	err = json.Unmarshal(layerBlob, &sigFile)
	if err != nil {
		return errors.Wrapf(err, "sign: error unmarshalling signature file")
	}

	if len(sigFile.Signatures) == 0 {
		return errors.New("sign: invalid signature")
	}

	signature, ok := sigFile.Signatures[verifyOpts.Author]
	if !ok || signature.Signature == nil {
		return errors.New("sign: invalid author")
	}

	valid := ecdsa.Verify(publicKey, hashMessage[:], big.NewInt(0), big.NewInt(0))
	/*err = rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, hashMessage[:], signature.Signature)
	if err != nil {
		return errors.Wrapf(err, "sign: error verifying signature file")
	}*/
	if !valid {
		return errors.New("Key is not valid!")
	}

	return nil
}

// verify pki.
/*func (verifyOpts VerifyOptions) verifyPKI() error {
	publicKey, err := verifyOpts.getPublicKey()
	if err != nil {
		return errors.Wrapf(err, "sign: error reading public key")
	}

	dataHash, err := utils.GenerateRSAHash(verifyOpts.InputData)
	if err != nil {
		return errors.Wrapf(err, "sign: error generating file hash")
	}

	sigFileBytes, err := ioutil.ReadFile(verifyOpts.SigFilePath)
	if err != nil {
		return errors.Wrapf(err, "sign: error reading signature file")
	}

	var sigFile SignatureFile

	err = json.Unmarshal(sigFileBytes, &sigFile)
	if err != nil {
		return errors.Wrapf(err, "sign: error unmarshalling signature file")
	}

	if len(sigFile.Signatures) == 0 {
		return errors.New("sign: invalid signature")
	}

	signature, ok := sigFile.Signatures[verifyOpts.Author]
	if !ok || signature.Signature == nil {
		return errors.New("sign: invalid author")
	}

	err = rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, dataHash[:], signature.Signature)
	if err != nil {
		return errors.Wrapf(err, "sign: error verifying signature file")
	}

	return nil
}*/

// Get GPGME context to sign or verify data.
func getGPGMEContext(optionalDir string) (*gpgme.Context, error) {
	ctx, err := gpgme.New()
	if err != nil {
		return nil, errors.Wrapf(err, "sign: error creating gpgme context")
	}

	if err = ctx.SetProtocol(gpgme.ProtocolOpenPGP); err != nil {
		return nil, errors.Wrapf(err, "sign: error setting up protocol")
	}

	if optionalDir != "" {
		err := ctx.SetEngineInfo(gpgme.ProtocolOpenPGP, "", optionalDir)
		if err != nil {
			return nil, errors.Wrapf(err, "sign: error setting up gpgme engine")
		}
	}

	ctx.SetArmor(false)

	ctx.SetTextMode(false)

	return ctx, nil
}

// Veriy signature based on input type.
func (verifyOpts *VerifyOptions) VerifySignature() error {
	switch verifyOpts.InputType {
	case OCI:
		return verifyOpts.verifyOCISignature()
	case MEDIA:
		return verifyOpts.verifyMediaSignature()
	default:
		return ErrInvalidInput
	}
}

func (verifyOpts *VerifyOptions) verifyOCISignature() error {
	var err error

	switch verifyOpts.SignatureType {
	case GPG:
		err = verifyOpts.verifyGpgOciSignature()
		if err != nil {
			return err
		}
	case PKI:
		//err = verifyOpts.verifyPKI()
		if err != nil {
			return err
		}
	case COSIGN:
		err = verifyOpts.verifyCosign()
		if err != nil {
			return err
		}
	default:
		return ErrInvalidSignatureType
	}

	return verifyOpts.verifyOCILayout()
}

func (verifyOpts *VerifyOptions) verifyMediaSignature() error {
	switch verifyOpts.SignatureType {
	case GPG:
		return verifyOpts.verifyGpgMediaSignature()
	case PKI:
		//return verifyOpts.verifyPKI()
		return nil
	default:
		return ErrInvalidSignatureType
	}
}

// Veirfy OCI Layout Signature using containers/image lib.
func (verifyOpts *VerifyOptions) verifyGpgOciSignature() error {
	unverifiedManifest, err := ioutil.ReadFile(verifyOpts.InputData)
	if err != nil {
		return errors.Wrapf(err, `sign: error reading manifest from "%s"`, verifyOpts.InputData)
	}

	unverifiedSignature, err := ioutil.ReadFile(verifyOpts.SigFilePath)
	if err != nil {
		return errors.Wrapf(err, `sign: error reading signature from "%s"`, verifyOpts.SigFilePath)
	}

	mech, err := signature.NewGPGSigningMechanism()
	if err != nil {
		return errors.Wrapf(err, "sign: error initializing GPG")
	}
	defer mech.Close()

	_, err = signature.VerifyDockerManifestSignature(unverifiedSignature, unverifiedManifest,
		strings.ToLower(verifyOpts.Ref), mech, verifyOpts.Fingerprint)
	if err != nil {
		return errors.Wrapf(err, "sign: error verifying signature")
	}

	return verifyOpts.verifyOCILayout()
}

// Veirfy media tar file signature.
func (verifyOpts *VerifyOptions) verifyGpgMediaSignature() error {
	gpgctx, err := getGPGMEContext(verifyOpts.OptionalDir)
	if err != nil {
		return errors.Wrapf(err, "sign: error getting gpgme context while verifying media signature")
	}

	unverifiedSignature, err := ioutil.ReadFile(verifyOpts.SigFilePath)
	if err != nil {
		return errors.Wrapf(err, `sign: error reading signature from "%s"`, verifyOpts.InputData)
	}

	sigBuffer := bytes.Buffer{}

	sigData, err := gpgme.NewDataWriter(&sigBuffer)
	if err != nil {
		return errors.Wrapf(err, "sign: error creating data writer")
	}

	unverifiedsignaturegpg, err := gpgme.NewDataBytes(unverifiedSignature)
	if err != nil {
		return errors.Wrapf(err, "sign: error converting into gpgme data bytes")
	}

	_, sigs, err := gpgctx.Verify(unverifiedsignaturegpg, nil, sigData)
	if err != nil {
		return errors.Wrapf(err, "sign: error while verifying signature")
	}

	if len(sigs) != 1 {
		return ErrIncorrectSigLength
	}

	sig := sigs[0]

	if sig.Status != nil || sig.Validity == gpgme.ValidityNever || sig.ValidityReason != nil || sig.WrongKeyUsage {
		return ErrBadSignature
	}

	var unmatchedSignature untrustedSignature

	if err := json.Unmarshal(sigBuffer.Bytes(), &unmatchedSignature); err != nil {
		return errors.Wrapf(err, "sign: error unmarshalling")
	}

	actualHash, err := GenerateFileHash(verifyOpts.InputData)
	if err != nil {
		return errors.Wrapf(err, "sign: error generating media tar file hash")
	}

	if actualHash != unmatchedSignature.UntrustedHash {
		return ErrHashMismatch
	}

	if sig.Fingerprint != verifyOpts.MediaFingerprint {
		return ErrFingerprintMismatch
	}

	return nil
}

func GenerateFileHash(filePath string) (string, error) {
	bytes, err := ioutil.ReadFile(filePath)
	if err != nil {
		return "", fmt.Errorf("utils: error opening file %s: %w", filePath, err)
	}

	hashCode := sha256.Sum256(bytes)

	return fmt.Sprintf("%x", hashCode), nil
}

func (verifyOpts *VerifyOptions) verifyOCILayout() error {
	ociDir := filepath.Dir(verifyOpts.InputData)

	ctx := context.Background()

	ociEngine, err := umoci.OpenLayout(ociDir)
	if err != nil {
		return errors.Wrapf(err, "verify: error opening oci layout")
	}
	defer ociEngine.Close()

	blobs, err := ociEngine.ListBlobs(ctx)
	if err != nil {
		return errors.Wrapf(err, "verify: error getting list of oci layout")
	}

	for _, blob := range blobs {
		expectedHash, err := GenerateFileHash(path.Join(ociDir, "blobs/sha256", blob.Hex()))
		if err != nil {
			return errors.Wrapf(err, "verify: error generating file hash")
		}

		if expectedHash != blob.Hex() {
			return errors.Wrapf(ErrHashMismatch, "verify: hash mismatch, blob contents are corrupted")
		}
	}

	return nil
}

func getImageManifest(indexFilePath string, signed bool) (v1.Descriptor, error) {
	index, err := getImageIndex(indexFilePath)
	if err != nil {
		return v1.Descriptor{}, err
	}

	for _, manifest := range index.Manifests {
		if signed {
			tag := manifest.Annotations["org.opencontainers.image.ref.name"]
			if strings.Contains(tag, ".sig") {
				return manifest, nil
			}
		} else {
			tag := manifest.Annotations["org.opencontainers.image.ref.name"]
			if !strings.Contains(tag, ".sig") {
				return manifest, nil
			}
		}
	}

	return v1.Descriptor{}, err
}

func getImageIndex(indexFilePath string) (v1.Index, error) {
	buf, err := ioutil.ReadFile(indexFilePath)
	if err != nil {
		return v1.Index{}, err
	}

	var index v1.Index

	err = json.Unmarshal(buf, &index)
	if err != nil {
		return v1.Index{}, err
	}

	return index, err
}
