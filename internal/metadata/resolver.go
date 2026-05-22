package metadata

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
)

type PipelineRunMeta struct {
	Namespace    string
	Application  string
	Component    string
	PipelineType string
	PipelineName string
	TaskName     string
	TargetBranch string
	CommitSHA    string
	PipelineRun  string
}

type Resolver struct {
	Client   *http.Client
	KubeBase string
}

func (r *Resolver) Resolve(namespace, podName string) (*PipelineRunMeta, error) {
	brokerToken, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/token")
	if err != nil {
		return nil, fmt.Errorf("reading broker SA token: %w", err)
	}
	token := string(brokerToken)
	meta := &PipelineRunMeta{Namespace: namespace}

	// Pod
	podData, err := r.kubeGet(fmt.Sprintf("/api/v1/namespaces/%s/pods/%s", namespace, podName), token)
	if err != nil {
		return nil, fmt.Errorf("getting pod: %w", err)
	}
	var pod struct {
		Metadata struct {
			Labels map[string]string `json:"labels"`
		} `json:"metadata"`
		Status struct {
			Phase string `json:"phase"`
		} `json:"status"`
	}
	if err := json.Unmarshal(podData, &pod); err != nil {
		return nil, fmt.Errorf("parsing pod: %w", err)
	}
	if pod.Status.Phase != "Running" && pod.Status.Phase != "Pending" {
		return nil, fmt.Errorf("pod %s is not active (phase: %s)", podName, pod.Status.Phase)
	}
	taskRunName := pod.Metadata.Labels["tekton.dev/taskRun"]
	if taskRunName == "" {
		return nil, fmt.Errorf("pod %s is not a Tekton task pod", podName)
	}

	// TaskRun
	trData, err := r.kubeGet(fmt.Sprintf("/apis/tekton.dev/v1/namespaces/%s/taskruns/%s", namespace, taskRunName), token)
	if err != nil {
		return nil, fmt.Errorf("getting taskrun: %w", err)
	}
	var taskRun struct {
		Metadata struct {
			Labels map[string]string `json:"labels"`
		} `json:"metadata"`
	}
	if err := json.Unmarshal(trData, &taskRun); err != nil {
		return nil, fmt.Errorf("parsing taskrun: %w", err)
	}
	meta.TaskName = taskRun.Metadata.Labels["tekton.dev/pipelineTask"]
	pipelineRunName := taskRun.Metadata.Labels["tekton.dev/pipelineRun"]
	if pipelineRunName == "" {
		return nil, fmt.Errorf("taskrun %s is not part of a PipelineRun", taskRunName)
	}

	// PipelineRun
	prData, err := r.kubeGet(fmt.Sprintf("/apis/tekton.dev/v1/namespaces/%s/pipelineruns/%s", namespace, pipelineRunName), token)
	if err != nil {
		return nil, fmt.Errorf("getting pipelinerun: %w", err)
	}
	var pr struct {
		Metadata struct {
			Name        string            `json:"name"`
			Labels      map[string]string `json:"labels"`
			Annotations map[string]string `json:"annotations"`
		} `json:"metadata"`
	}
	if err := json.Unmarshal(prData, &pr); err != nil {
		return nil, fmt.Errorf("parsing pipelinerun: %w", err)
	}

	meta.PipelineRun = pr.Metadata.Name
	meta.PipelineName = pr.Metadata.Labels["tekton.dev/pipeline"]
	meta.Application = pr.Metadata.Labels["appstudio.openshift.io/application"]
	meta.Component = pr.Metadata.Labels["appstudio.openshift.io/component"]
	meta.PipelineType = pr.Metadata.Labels["pipelines.appstudio.openshift.io/type"]
	meta.CommitSHA = pr.Metadata.Annotations["build.appstudio.redhat.com/commit_sha"]
	meta.TargetBranch = pr.Metadata.Annotations["build.appstudio.redhat.com/target_branch"]

	if meta.Application == "" || meta.Component == "" {
		return nil, fmt.Errorf("pipelinerun %s missing required Konflux labels", pipelineRunName)
	}

	return meta, nil
}

func (r *Resolver) kubeGet(path, token string) ([]byte, error) {
	req, err := http.NewRequest("GET", r.KubeBase+path, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := r.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		limit := len(body)
		if limit > 200 {
			limit = 200
		}
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body[:limit]))
	}
	return body, nil
}
