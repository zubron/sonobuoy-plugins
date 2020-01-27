package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/pkg/errors"
	"github.com/vmware-tanzu/sonobuoy-plugins/who-can/runner/pkg/whocan"
	"gopkg.in/yaml.v2"
	rbac "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	clioptions "k8s.io/cli-runtime/pkg/genericclioptions"
	"k8s.io/client-go/kubernetes"
)

const whoCanConfigEnv = "WHO_CAN_CONFIG"

func createClient(configFlags clioptions.ConfigFlags) (*kubernetes.Clientset, error) {
	clientConfig, err := configFlags.ToRESTConfig()
	if err != nil {
		errors.Wrap(err, "getting rest config")
	}
	// TODO: make this configurable
	clientConfig.QPS = 100.0
	clientConfig.Burst = 50

	return kubernetes.NewForConfig(clientConfig)
}

func getAPIResources(client *kubernetes.Clientset) ([]metav1.APIResource, error) {
	dc := client.Discovery()
	if dc == nil {
		return []metav1.APIResource{}, fmt.Errorf("cannot get server resources, no discovery client available")
	}
	resourceMap, err := dc.ServerPreferredResources()
	if err != nil {
		return nil, err
	}

	// Some resources are ambiguously set in two or more groups. As kubectl
	// does, we should just prefer the first one returned by discovery.
	resources := []metav1.APIResource{}
	resourcesSeen := map[string]struct{}{}
	for _, apiResourceList := range resourceMap {
		version, err := schema.ParseGroupVersion(apiResourceList.GroupVersion)
		if err != nil {
			return nil, errors.Wrap(err, "parsing schema")
		}
		resourceList, err := client.ServerResourcesForGroupVersion(version.String())

		for _, apiResource := range resourceList.APIResources {
			// If we've seen the resource already, skip it.
			if _, ok := resourcesSeen[apiResource.Name]; ok {
				continue
			}
			resources = append(resources, apiResource)
			resourcesSeen[apiResource.Name] = struct{}{}
			continue
		}
	}

	return resources, nil
}

func getAllSubjects(client *kubernetes.Clientset) []rbac.Subject {
	rbacClient := client.RbacV1()
	namespaces, err := client.CoreV1().Namespaces().List(metav1.ListOptions{})
	if err != nil {
		fmt.Printf("error getting namespaces %v\n", err)
	}
	seen := map[rbac.Subject]struct{}{}
	for _, ns := range namespaces.Items {
		rbs, err := rbacClient.RoleBindings(ns.Name).List(metav1.ListOptions{})
		if err != nil {
			fmt.Printf("error getting rbs %v\n", err)
		}
		for _, rb := range rbs.Items {
			for _, subject := range rb.Subjects {
				if _, ok := seen[subject]; ok {
					continue
				}
				seen[subject] = struct{}{}
			}
		}
	}
	crbs, err := rbacClient.ClusterRoleBindings().List(metav1.ListOptions{})
	if err != nil {
		fmt.Printf("error getting crbs %v\n", err)
	}

	for _, crb := range crbs.Items {
		for _, subject := range crb.Subjects {
			if _, ok := seen[subject]; ok {
				continue
			}
			seen[subject] = struct{}{}
		}
	}

	subjects := []rbac.Subject{}
	for subject := range seen {
		subjects = append(subjects, subject)
	}
	return subjects
}

// WhoCanConfig is used to configure the who-can queries
type WhoCanConfig struct {
	Namespaces []string `yaml:"namespaces"`
}

func loadWhoCanConfig() (WhoCanConfig, error) {
	config := os.Getenv(whoCanConfigEnv)
	wcc := WhoCanConfig{}
	if config == "" {
		return wcc, nil
	}

	if err := yaml.Unmarshal([]byte(config), &wcc); err != nil {
		return wcc, err
	}
	return wcc, nil
}

// RoleBindings represents RoleBindings or ClusterRoleBindings which may be applied to a subject
type RoleBindings struct {
	RoleBindings        []string `json:"roleBindings,omitempty"`
	ClusterRoleBindings []string `json:"clusterRoleBindings,omitempty"`
}

// VerbRoleBindings represents all role bindings that allow a verb to be performed
type VerbRoleBindings map[string]RoleBindings

func (vrb VerbRoleBindings) MarshalJSON() ([]byte, error) {
	s := []struct {
		Name                string   `json:"name"`
		RoleBindings        []string `json:"roleBindings,omitempty"`
		ClusterRoleBindings []string `json:"clusterRoleBindings,omitempty"`
	}{}
	for name, bindings := range vrb {
		s = append(s, struct {
			Name                string   `json:"name"`
			RoleBindings        []string `json:"roleBindings,omitempty"`
			ClusterRoleBindings []string `json:"clusterRoleBindings,omitempty"`
		}{
			Name:                name,
			RoleBindings:        bindings.RoleBindings,
			ClusterRoleBindings: bindings.ClusterRoleBindings,
		})
	}

	return json.Marshal(s)
}

// ResourcePermission represents a permission granted to a particular resource
// This really wants to be another map for indexing while iterating over all resources/subjects
type ResourcePermission map[string]VerbRoleBindings

func (rp ResourcePermission) MarshalJSON() ([]byte, error) {
	s := []struct {
		Name  string           `json:"name"`
		Verbs VerbRoleBindings `json:"verbs"`
	}{}
	for name, verbs := range rp {
		s = append(s, struct {
			Name  string           `json:"name"`
			Verbs VerbRoleBindings `json:"verbs"`
		}{
			Name:  name,
			Verbs: verbs,
		})
	}

	return json.Marshal(s)
}

// NamespacePermissions represents all permissions granted within namespaces
type NamespacePermissions map[string]ResourcePermission

// SubjectPermissions represents all the permissions for a subject
type SubjectPermissions map[rbac.Subject]NamespacePermissions

func (np NamespacePermissions) initialize(result whocan.Result) {
	if _, ok := np[result.Namespace]; !ok {
		np[result.Namespace] = ResourcePermission{}
	}
	if _, ok := np[result.Namespace][result.Resource]; !ok {
		np[result.Namespace][result.Resource] = VerbRoleBindings{}
	}
	if _, ok := np[result.Namespace][result.Resource][result.Verb]; !ok {
		np[result.Namespace][result.Resource][result.Verb] = RoleBindings{}
	}
}

func (np NamespacePermissions) AddRoleBindingResult(result whocan.Result, rb rbac.RoleBinding) {
	np.initialize(result)
	ref := np[result.Namespace][result.Resource][result.Verb]
	ref.RoleBindings = append(ref.RoleBindings, rb.Name)
	np[result.Namespace][result.Resource][result.Verb] = ref
}

func (np NamespacePermissions) AddClusterRoleBindingResult(result whocan.Result, rb rbac.ClusterRoleBinding) {
	np.initialize(result)
	ref := np[result.Namespace][result.Resource][result.Verb]
	ref.ClusterRoleBindings = append(ref.ClusterRoleBindings, rb.Name)
	np[result.Namespace][result.Resource][result.Verb] = ref
}

func (np NamespacePermissions) MarshalJSON() ([]byte, error) {
	s := []struct {
		Namespace string             `json:"namespace"`
		Resources ResourcePermission `json:"resources"`
	}{}
	for namespace, resources := range np {
		s = append(s, struct {
			Namespace string             `json:"namespace"`
			Resources ResourcePermission `json:"resources"`
		}{
			Namespace: namespace,
			Resources: resources,
		})
	}

	return json.Marshal(s)
}

// MarshalJSON takes a Sub
func (spm SubjectPermissions) MarshalJSON() ([]byte, error) {
	s := []struct {
		rbac.Subject
		Permissions NamespacePermissions `json:"permissions"`
	}{}
	for subject, val := range spm {
		s = append(s, struct {
			rbac.Subject
			Permissions NamespacePermissions `json:"permissions"`
		}{
			Subject:     subject,
			Permissions: val,
		})
	}

	return json.Marshal(s)
}

func main() {
	wcc, err := loadWhoCanConfig()
	if err != nil {
		fmt.Printf("unable to load config: %v\n", err)
		os.Exit(1)
	}

	var configFlags clioptions.ConfigFlags

	client, err := createClient(configFlags)
	if err != nil {
		fmt.Printf("unable to create Kubernetes client: %v\n", err)
		os.Exit(1)
	}

	resources, err := getAPIResources(client)
	if err != nil {
		fmt.Printf("unable to get resources: %v\n", err)
		os.Exit(1)
	}

	wc, err := whocan.NewWhoCanClient(&configFlags, client)
	if err != nil {
		fmt.Printf("unable to create who-can client: %v\n", err)
		os.Exit(1)
	}

	results := []whocan.Result{}

	// Include the empty string so that queries against the default namespace are performed
	namespaces := []string{"default", "kube-system"}
	namespaces = append(namespaces, wcc.Namespaces...)

	for _, namespace := range namespaces {
		for _, resource := range resources {
			// if resource.Name == "pods" || strings.HasPrefix(resource.Name, "pods/log") {
			for _, verb := range resource.Verbs {
				r, err := wc.Run(resource.Name, verb, namespace)
				if err != nil {
					fmt.Printf("error running who-can query: %v\n", err)
					os.Exit(1)
				}
				results = append(results, r)
			}
			// }
		}

	}

	subjectResults := SubjectPermissions{}
	subjects := getAllSubjects(client)
	for _, subject := range subjects {
		subjectResults[subject] = NamespacePermissions{}
	}

	for _, result := range results {
		for _, rb := range result.RoleBindings {
			for _, subject := range rb.Subjects {
				subjectResults[subject].AddRoleBindingResult(result, rb)
			}
		}
		for _, crb := range result.ClusterRoleBindings {
			for _, subject := range crb.Subjects {
				subjectResults[subject].AddClusterRoleBindingResult(result, crb)
			}
		}
	}

	j, err := json.Marshal(subjectResults)
	if err != nil {
		fmt.Printf("unable to marshal results as JSON: %v\n", err)
		os.Exit(1)
	}
	fmt.Println(string(j))
}
