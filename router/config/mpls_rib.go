package config

import (
	"os"

	"gopkg.in/yaml.v2"

	"github.com/scionproto/scion/pkg/private/serrors"
)

type MplsRibConfig struct {
	BrRib []struct {
		Id  string               `yaml:"id,omitempty"`
		Rib []MplsRibConfigEntry `yaml:"rib,omitempty"`
	} `yaml:"br_rib,omitempty"`
}

func (m *MplsRibConfigEntry) Validate() error {
	return nil
}

type MplsRibConfigEntry struct {
	Label         uint32 `yaml:"label,omitempty"`
	NextHop       string `yaml:"nexthop,omitempty"`
	InterfaceName string `yaml:"intf,omitempty"`
}

func MplsRibConfigFromFile(file string) (MplsRibConfig, error) {
	mpls := MplsRibConfig{}
	b, err := os.ReadFile(file)
	if err != nil {
		return mpls, serrors.WrapStr("Unable to read the fabrid policy in file", err, "path", file)
	}
	if err = yaml.UnmarshalStrict(b, &mpls); err != nil {
		return mpls, serrors.WrapStr("Unable to parse policy", err)
	}
	return mpls, nil
}
