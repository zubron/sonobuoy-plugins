package whocan

import (
	"encoding/json"
	"strings"

	whocancmd "github.com/aquasecurity/kubectl-who-can/pkg/cmd"
	"github.com/pkg/errors"
	rbac "k8s.io/api/rbac/v1"
	clioptions "k8s.io/cli-runtime/pkg/genericclioptions"
	"k8s.io/client-go/kubernetes"
)

// RoleBindings is an alias for a slice of rbac.RoleBinding to allow
// custom JSON marshalling.
type RoleBindings []rbac.RoleBinding

// ClusterRoleBindings is an alias for a slice of rbac.ClusterRoleBinding to allow
// custom JSON marshalling.
type ClusterRoleBindings []rbac.ClusterRoleBinding

// Result represents the result of a who-can query.
type Result struct {
	Resource            string `json:"resource"`
	Verb                string `json:"verb"`
	RoleBindings        `json:"role-bindings"`
	ClusterRoleBindings `json:"cluster-role-bindings"`
}

type roleBinding struct {
	Name        string `json:"name"`
	Type        string `json:"type"`
	Subject     string `json:"subject"`
	Namespace   string `json:"namespace,omitempty"`
	SANamespace string `json:"sa-namespace,omitempty"`
}

// MarshalJSON iterates over the RoleBindings to create a slice of
// the output structure, roleBindings, and marshals that as JSON.
func (rbs RoleBindings) MarshalJSON() ([]byte, error) {
	r := []roleBinding{}
	for _, rb := range rbs {
		for _, subject := range rb.Subjects {
			r = append(r, roleBinding{
				Name:        rb.Name,
				Type:        subject.Kind,
				Subject:     subject.Name,
				Namespace:   rb.GetNamespace(),
				SANamespace: subject.Namespace,
			})
		}
	}
	return json.Marshal(r)
}

// MarshalJSON iterates over the ClusterRoleBindings to create a slice of
// the output structure, roleBindings, and marshals that as JSON.
func (crbs ClusterRoleBindings) MarshalJSON() ([]byte, error) {
	r := []roleBinding{}
	for _, crb := range crbs {
		for _, subject := range crb.Subjects {
			r = append(r, roleBinding{
				Name:        crb.Name,
				Type:        subject.Kind,
				Subject:     subject.Name,
				SANamespace: subject.Namespace,
			})
		}
	}
	return json.Marshal(r)
}

// createArguments inspects the given resource and verb and creates the arguments necessary for a
// who-can query.
func createArguments(resource, verb string) []string {
	// Determine if the resource type is a subresource based on the name form resource/subresource.
	// If the resource begins with "/", leave as is as a non-resource URL, otherwise attempt to split.
	var resourceArgs []string
	if strings.HasPrefix(resource, "/") {
		resourceArgs = append(resourceArgs, resource)
	} else {
		resourceTokens := strings.SplitN(resource, "/", 2)
		resourceArgs = append(resourceArgs, resourceTokens[0])
		if len(resourceTokens) > 1 {
			resourceArgs = append(resourceArgs, "--subresource", resourceTokens[1])
		}
	}
	return append([]string{verb}, resourceArgs...)
}

// Run runs a who-can query for the given resource and verb.
func (c *Client) Run(resource, verb string) (Result, error) {
	args := createArguments(resource, verb)

	if err := c.wc.Complete(args); err != nil {
		return Result{}, errors.Wrap(err, "complete")
	}
	if err := c.wc.Validate(); err != nil {
		return Result{}, errors.Wrap(err, "validate")
	}
	rbs, crbs, err := c.wc.Check()
	if err != nil {
		return Result{}, errors.Wrap(err, "check")
	}
	return Result{
		Resource:            resource,
		Verb:                verb,
		RoleBindings:        rbs,
		ClusterRoleBindings: crbs,
	}, nil
}

type Client struct {
	wc *whocancmd.WhoCan
}

// NewWhoCanClient creates a client which can run who-can queries.
func NewWhoCanClient(configFlags *clioptions.ConfigFlags, client *kubernetes.Clientset) (*Client, error) {
	mapper, err := configFlags.ToRESTMapper()
	if err != nil {
		errors.Wrap(err, "creating REST mapper")
	}

	return &Client{wc: whocancmd.NewWhoCan(configFlags, client, mapper)}, nil
}
