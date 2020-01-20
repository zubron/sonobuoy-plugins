package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/pkg/errors"
	"github.com/vmware-tanzu/sonobuoy-plugins/who-can/runner/pkg/whocan"
	"gopkg.in/yaml.v2"
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
	clientConfig.QPS = 50.0
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

	results := []whocan.Result{}

	namespaces := []string{"default", "kube-system"}
	namespaces = append(namespaces, wcc.Namespaces...)

	for _, namespace := range namespaces {
		configFlags.Namespace = &namespace
		wc, err := whocan.NewWhoCanClient(&configFlags, client)
		if err != nil {
			fmt.Printf("unable to create who-can client: %v\n", err)
			os.Exit(1)
		}
		for _, resource := range resources {
			for _, verb := range resource.Verbs {
				r, err := wc.Run(resource.Name, verb, namespace)
				if err != nil {
					fmt.Printf("error running who-can query: %v\n", err)
					os.Exit(1)
				}
				results = append(results, r)
			}
		}

	}

	j, err := json.Marshal(results)
	if err != nil {
		fmt.Printf("unable to marshal results as JSON: %v\n", err)
		os.Exit(1)
	}
	fmt.Println(string(j))

}
