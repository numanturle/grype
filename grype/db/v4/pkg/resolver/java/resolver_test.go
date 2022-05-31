package java

import (
	grypePkg "github.com/anchore/grype/grype/pkg"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestResolver_Normalize(t *testing.T) {
	tests := []struct {
		packageName string
		normalized  string
	}{
		{
			packageName: "PyYAML",
			normalized:  "pyyaml",
		},
		{
			packageName: "oslo.concurrency",
			normalized:  "oslo.concurrency",
		},
		{
			packageName: "",
			normalized:  "",
		},
		{
			packageName: "test---1",
			normalized:  "test---1",
		},
		{
			packageName: "AbCd.-__.--.-___.__.--1234____----....XyZZZ",
			normalized:  "abcd.-__.--.-___.__.--1234____----....xyzzz",
		},
	}

	resolver := Resolver{}

	for _, test := range tests {
		resolvedNames := resolver.Normalize(test.packageName)
		assert.Equal(t, resolvedNames, test.normalized)
	}
}

func TestResolver_Resolve(t *testing.T) {
	tests := []struct {
		pkg      grypePkg.Package
		resolved []string
	}{
		{
			pkg: grypePkg.Package{
				Name:         "ABCD",
				Version:      "1.2.3.4",
				Language:     "java",
				MetadataType: "",
				Metadata: grypePkg.JavaMetadata{
					VirtualPath:   "virtual-path-info",
					PomArtifactID: "pom-ARTIFACT-ID-info",
					PomGroupID:    "pom-group-ID-info",
					ManifestName:  "main-section-name-info",
				},
			},
			resolved: []string{"pom-group-id-info:pom-artifact-id-info", "pom-group-id-info:main-section-name-info"},
		},
	}

	resolver := Resolver{}

	for _, test := range tests {
		resolvedNames := resolver.Resolve(test.pkg)
		assert.ElementsMatch(t, resolvedNames, test.resolved)
	}
}
