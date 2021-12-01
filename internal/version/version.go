package version

var (
	// Version shows the current notation version, optionally with pre-release.
	Version = "v0.7.1-alpha.1"

	// BuildMetadata stores the build metadata.
	BuildMetadata = "azure"
)

// GetVersion returns the version string in SemVer 2.
func GetVersion() string {
	if BuildMetadata == "" {
		return Version
	}
	return Version + "+" + BuildMetadata
}
