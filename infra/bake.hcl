# ForgeGuard — Docker Buildx Configuration
#
# Enable multi-platform builds with Docker Buildx.
# Run: docker buildx bake -f infra/bake.hcl

group "default" {
  targets = ["forgeguard"]
}

target "forgeguard" {
  dockerfile = "Dockerfile"
  context    = "."
  tags       = ["ghcr.io/jdrexx/forgeguard:latest"]
  platforms  = ["linux/amd64", "linux/arm64"]
  cache-from = ["type=gha"]
  cache-to   = ["type=gha,mode=max"]
  output     = ["type=image,push=false"]
}

target "forgeguard-release" {
  inherits   = ["forgeguard"]
  output     = ["type=image,push=true"]
  provenance = true
  sbom       = true
}
