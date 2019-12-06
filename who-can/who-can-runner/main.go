package main

import (
	"fmt"
	"os"
	"strings"

	whocan "github.com/aquasecurity/kubectl-who-can/pkg/cmd"
	"github.com/pkg/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	clioptions "k8s.io/cli-runtime/pkg/genericclioptions"
	"k8s.io/client-go/kubernetes"
)

func getResources(client *kubernetes.Clientset) ([]metav1.APIResource, error) {
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

// whoCanArguments iterates over the given resources and creates the arguments necessary for a
// who-can query.
func whoCanArguments(resources []metav1.APIResource) [][]string {
	args := [][]string{}

	for _, resource := range resources {
		// Determine if the resource type is a subresource based on the name form resource/subresource.
		// If the resource begins with "/", leave as is as a non-resource URL, otherwise attempt to split.
		var resourceArgs []string
		if strings.HasPrefix(resource.Name, "/") {
			resourceArgs = append(resourceArgs, resource.Name)
		} else {
			resourceTokens := strings.SplitN(resource.Name, "/", 2)
			resourceArgs = append(resourceArgs, resourceTokens[0])
			if len(resourceTokens) > 1 {
				resourceArgs = append(resourceArgs, "--subresource", resourceTokens[1])
			}
		}
		for _, verb := range resource.Verbs {
			args = append(args, append([]string{verb}, resourceArgs...))
		}
	}
	return args
}

func main() {
	var configFlags clioptions.ConfigFlags

	clientConfig, err := configFlags.ToRESTConfig()
	if err != nil {
		fmt.Printf("Unable to get rest config: %v\n", err)
		os.Exit(1)
	}
	clientConfig.QPS = 50.0
	clientConfig.Burst = 50

	client, err := kubernetes.NewForConfig(clientConfig)
	if err != nil {
		fmt.Printf("creating client: %v\n", err)
		os.Exit(1)
	}

	streams := clioptions.IOStreams{In: os.Stdin, Out: os.Stdout, ErrOut: os.Stderr}
	mapper, err := configFlags.ToRESTMapper()
	if err != nil {
		fmt.Printf("getting mapper: %v\n", err)
		os.Exit(1)
	}

	wc := whocan.NewWhoCan(&configFlags, client, mapper, streams)

	resources, err := getResources(client)
	if err != nil {
		fmt.Printf("Unable to get resources: %v\n", err)
		os.Exit(1)
	}
	whoCanArgs := whoCanArguments(resources)

	for _, wca := range whoCanArgs {
		fmt.Printf("who-can %s\n", strings.Join(wca, " "))

		if err := wc.Complete(wca); err != nil {
			fmt.Printf("whocan complete: %v\n", err)
			os.Exit(1)
		}
		if err := wc.Validate(); err != nil {
			fmt.Printf("whocan validate: %v\n", err)
			os.Exit(1)
		}
		if err := wc.Check(); err != nil {
			fmt.Printf("whocan check: %v\n", err)
			os.Exit(1)
		}
		fmt.Println()
	}

}
