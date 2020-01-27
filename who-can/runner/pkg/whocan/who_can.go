package whocan

import (
	"encoding/json"
	"os"
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
	Namespace           string `json:"namespace"`
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

// Client runs who-can queries
type Client struct {
	whocancmd.WhoCan
	resourceResolver whocancmd.ResourceResolver
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
func (c *Client) createAction(resource, verb, namespace string) whocancmd.Action {
	// Determine if the resource type is a subresource based on the name form resource/subresource.
	// If the resource begins with "/", leave as is as a non-resource URL, otherwise attempt to split.
	var subResource string
	if !strings.HasPrefix(resource, "/") {
		resourceTokens := strings.SplitN(resource, "/", 2)
		resource = resourceTokens[0]
		if len(resourceTokens) > 1 {
			subResource = resourceTokens[1]
		}
	}

	gr, err := c.resourceResolver.Resolve(verb, resource, subResource)
	if err != nil {
		return whocancmd.Action{}
		// return fmt.Errorf("resolving resource: %v", err)
	}

	allNamespaces := false
	if namespace == "*" {
		allNamespaces = true
		namespace = ""
	}

	return whocancmd.NewAction(verb, resource, "", subResource, "", gr, namespace, allNamespaces)
}

// Run runs a who-can query for the given resource and verb.
func (c *Client) Run(resource, verb, namespace string) (Result, error) {
	c.WhoCan.Action = c.createAction(resource, verb, namespace)
	if err := c.Validate(); err != nil {
		return Result{}, errors.Wrap(err, "validate")
	}
	rbs, crbs, err := c.Check()
	if err != nil {
		return Result{}, errors.Wrap(err, "check")
	}
	return Result{
		Resource:            resource,
		Verb:                verb,
		Namespace:           namespace,
		RoleBindings:        rbs,
		ClusterRoleBindings: crbs,
	}, nil
}

// NewWhoCanClient creates a client which can run who-can queries.
func NewWhoCanClient(configFlags *clioptions.ConfigFlags, client *kubernetes.Clientset) (*Client, error) {
	mapper, err := configFlags.ToRESTMapper()
	if err != nil {
		errors.Wrap(err, "creating REST mapper")
	}

	resourceResolver := whocancmd.NewResourceResolver(client.Discovery(), mapper)
	streams := clioptions.IOStreams{In: os.Stdin, Out: os.Stdout, ErrOut: os.Stderr}
	wc := whocancmd.NewWhoCan(configFlags, client, mapper, streams)
	return &Client{WhoCan: *wc, resourceResolver: resourceResolver}, nil
}
