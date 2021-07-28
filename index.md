## What is _zot_?

zot is a open source registry based on the [OCI Distribution Spec](https://github.com/opencontainers/distribution-spec) compatible with the Kubernetes ecosystem.

[Latest Release](https://github.com/anuvu/zot/pkgs/container/zot) => [v1.2.5](https://github.com/anuvu/zot/pkgs/container/zot/versions)


### Try It! 

```markdown
docker run -p 5000:5000 ghcr.io/anuvu/zot:latest
```

## Features
* Uses [OCI image layout](https://github.com/opencontainers/image-spec/blob/master/image-layout.md) for image storage
* Supports [helm charts](https://helm.sh/docs/topics/registries/)
* Currently suitable for on-prem deployments (e.g. colocated with Kubernetes)
* Compatible with ecosystem tools such as [skopeo](#skopeo) and [cri-o](#cri-o)
* [Vulnerability scanning of images](#Scanning-images-for-known-vulnerabilities)
* [Command-line client support](#cli)
* TLS support
* Authentication via:
  * TLS mutual authentication
  * HTTP *Basic* (local _htpasswd_ and LDAP)
  * HTTP *Bearer* token
* Doesn't require _root_ privileges
* Storage optimizations:
  * Automatic garbage collection of orphaned blobs
  * Layer deduplication using hard links when content is identical
* Swagger based documentation
* Single binary for _all_ the above features

For more details see [https://github.com/anuvu/zot](https://github.com/anuvu/zot).
