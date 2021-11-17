package sign

import (
	"context"
	"os"
	"path/filepath"
	"time"

	"github.com/anuvu/zot/pkg/log"
	"github.com/anuvu/zot/pkg/storage"
	"github.com/sigstore/cosign/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/pkg/cosign"
)

type Repo struct {
	PublicKey    string
	Verified     bool
	VisitedCount int
}

type Config struct {
	VerificationInterval string
	PublicKeys           map[string]string
}

func Run(config *Config, log log.Logger, address string, port string, is storage.ImageStore) {

	timeInterval, _ := time.ParseDuration(config.VerificationInterval)
	ticker := time.NewTicker(timeInterval)

	registryOptions := options.RegistryOptions{
		AllowInsecure:      false,
		KubernetesKeychain: false,
		RefOpts:            options.ReferenceOptions{},
	}
	ociremoteOpts, err := registryOptions.ClientOpts(context.TODO())
	if err != nil {
		log.Error().Err(err).Msg("constructing client options")
	}

	go func() {

		co := &cosign.CheckOpts{
			RegistryClientOpts: ociremoteOpts,
			CertEmail:          "",
		}

		co.ClaimVerifier = cosign.SimpleClaimVerifier
		for ; true; <-ticker.C {

			repos, err := is.GetRepositories()
			if err != nil {
				log.Error().Err(err).Msg("error while getting repositories")
				return
			}

			for _, repo := range repos {
				repoPath := is.RootDir()
				repoPath = filepath.Join(repoPath, repo)
				info, err := os.Lstat(repoPath)

				if err != nil {
					log.Error().Err(err).Msg("error while getting repository stats")
				}

				err = verifyImage(repo, info, is, config.PublicKeys[repo], address, port, co)
				if err != nil {
					log.Error().Err(err).Msg("Can't verify!")
				}
			}
		}
	}()
}
