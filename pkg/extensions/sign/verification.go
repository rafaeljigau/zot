package sign

import (
	"context"
	"errors"
	"io/fs"
	"path/filepath"
	"strings"

	"github.com/anuvu/zot/pkg/storage"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/sigstore/cosign/cmd/cosign/cli/sign"
	"github.com/sigstore/cosign/cmd/cosign/cli/verify"
	"github.com/sigstore/cosign/pkg/cosign"
	sigs "github.com/sigstore/cosign/pkg/signature"
	"github.com/sigstore/sigstore/pkg/signature"
)

func verifyImage(repo string, info fs.FileInfo, is storage.ImageStore, keyPath string, address string, port string, co *cosign.CheckOpts) error {
	tags, err := is.GetImageTags(repo)
	if err != nil {
		return err
	}
	ok := false
	for _, tag := range tags {
		if strings.Contains(tag, "sig") {
			ok = true
		}
	}
	if ok {
		keyRef := keyPath
		var pubKey signature.Verifier
		pubKey, err = sigs.PublicKeyFromKeyRef(context.TODO(), keyRef)
		if err != nil {
			return err
		}
		co.SigVerifier = pubKey

		host := address + ":" + port
		repo = filepath.Join(host, repo)
		repo = repo + ":" + tags[0]

		ref, err := name.ParseReference(repo)
		if err != nil {
			return err
		}
		ref, err = sign.GetAttachedImageRef(ref, "", co.RegistryClientOpts...)
		if err != nil {
			return err
		}

		verified, bundleVerified, err := cosign.VerifySignatures(context.TODO(), ref, co)
		if err != nil {
			return err
		}

		verify.PrintVerificationHeader(ref.Name(), co, bundleVerified)
		verify.PrintVerification(ref.Name(), verified, "json")

		return nil
	}
	return errors.New("No key provided for repository " + repo)
}
