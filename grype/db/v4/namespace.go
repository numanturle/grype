package v4

import (
	"fmt"
	"strings"
)

const (
	NVDNamespace        = "nvd"
	MSRCNamespacePrefix = "msrc"
	VulnDBNamespace     = "vulndb"
)

func RecordSource(feed, group string) string {
	return fmt.Sprintf("%s:%s", feed, group)
}

func NamespaceForFeedGroup(feed, group string) (string, error) {
	switch {
	case feed == "vulnerabilities":
		return group, nil
	case feed == "github":
		return group, nil
	case feed == "nvdv2" && group == "nvdv2:cves":
		return NVDNamespace, nil
	case feed == "vulndb" && group == "vulndb:vulnerabilities":
		return VulnDBNamespace, nil
	case feed == "microsoft" && strings.HasPrefix(group, MSRCNamespacePrefix+":"):
		return group, nil
	}
	return "", fmt.Errorf("feed=%q group=%q has no namespace mappings", feed, group)
}
