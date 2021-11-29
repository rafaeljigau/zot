package sign

import (
	"fmt"

	"github.com/anuvu/zot/pkg/log"
	"github.com/anuvu/zot/pkg/storage"
)

type Repo struct {
	IsValidated  bool
	VisitedCount int
}

type Config struct {
	VerificationInterval string
	PublicKeys           map[string]string
}

func Run(config *Config, log log.Logger, address string, port string, is storage.ImageStore) {

	go func() {
		verifyOption := VerifyOptions{
			Fingerprint: "/home/rafael/Downloads/keys1/cosign.pub",
			InputData:   "/home/rafael/Downloads/zot-repo/runner/index.json",
		}
		err := verifyOption.verifyCosign()
		fmt.Println(err)
	}()

	/*timeInterval, _ := time.ParseDuration(config.VerificationInterval)
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
	reposMap := make(map[string]*Repo)

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
				_, ok := reposMap[repo]
				if !ok {
					reposMap[repo] = &Repo{}
				}
				if !reposMap[repo].IsValidated && reposMap[repo].VisitedCount < 2 {
					repoPath := is.RootDir()
					repoPath = filepath.Join(repoPath, repo)
					info, err := os.Lstat(repoPath)

					if err != nil {
						log.Error().Err(err).Msg("error while getting repository stats")
					}

					err = verifyImage(repo, info, is, config.PublicKeys[repo], address, port, co)
					if errors.Is(err, ErrNoSignatureProvided) {
						log.Error().Err(err).Msg("K")
					} else if err != nil {
						log.Error().Err(err).Msg("A")
					} else {
						reposMap[repo].IsValidated = true
					}
					reposMap[repo].VisitedCount++
				}
				if reposMap[repo].VisitedCount == 2 {
					dir := path.Join(is.RootDir(), repo)

					is.RLock()
					defer is.RUnlock()

					buf, err := ioutil.ReadFile(path.Join(dir, "index.json"))
					if err != nil {
						log.Error().Err(err).Str("dir", dir).Msg("failed to read index.json")
					}

					var index ispec.Index

					if err := json.Unmarshal(buf, &index); err != nil {
						log.Error().Err(err).Str("dir", dir).Msg("invalid JSON")
					}

					digest := index.Manifests[0].Digest.String()

					err = is.DeleteImageManifest(repo, string(digest))
					if err != nil {
						log.Error().Err(err).Msg("cant delete manifest:(")
					}
					delete(reposMap, repo)

					if len(index.Manifests) == 0 {
						os.RemoveAll(dir)
					}
				}
			}
		}
	}()
	*/
}
