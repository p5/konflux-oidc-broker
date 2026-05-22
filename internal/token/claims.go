package token

import (
	"fmt"
	"strings"

	"github.com/p5/konflux-oidc-broker/internal/metadata"
)

const SubVersion = "v1"

func BuildSubClaim(meta *metadata.PipelineRunMeta) (string, error) {
	for field, value := range map[string]string{
		"application":  meta.Application,
		"component":    meta.Component,
		"pipelineType": meta.PipelineType,
		"pipelineName": meta.PipelineName,
		"taskName":     meta.TaskName,
		"targetBranch": meta.TargetBranch,
		"commitSHA":    meta.CommitSHA,
	} {
		if strings.Contains(value, ":") {
			return "", fmt.Errorf("invalid %s value %q: contains delimiter ':'", field, value)
		}
	}

	return fmt.Sprintf("%s:ns:%s:app:%s:component:%s:type:%s:pipeline:%s:task:%s:ref:%s",
		SubVersion,
		meta.Namespace,
		meta.Application,
		meta.Component,
		meta.PipelineType,
		meta.PipelineName,
		meta.TaskName,
		meta.TargetBranch,
	), nil
}
