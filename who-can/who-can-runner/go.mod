module github.com/vmware-tanzu/sonobuoy-plugins/who-can/who-can-runner

go 1.13

require (
	github.com/aquasecurity/kubectl-who-can v0.1.0-beta.2
	github.com/google/go-cmp v0.3.1 // indirect
	github.com/googleapis/gnostic v0.3.1 // indirect
	github.com/pkg/errors v0.8.1
	github.com/stretchr/testify v1.4.0 // indirect
	golang.org/x/crypto v0.0.0-20190829043050-9756ffdc2472 // indirect
	golang.org/x/net v0.0.0-20190827160401-ba9fcec4b297 // indirect
	golang.org/x/sys v0.0.0-20200107162124-548cf772de50 // indirect
	gopkg.in/inf.v0 v0.9.1 // indirect
	k8s.io/api v0.0.0-20190829034738-40d3837b7e3d // indirect
	k8s.io/apimachinery v0.0.0-20190828114620-4147c925140e
	k8s.io/cli-runtime v0.0.0-20190612131021-ced92c4c4749
	k8s.io/client-go v0.0.0-20190704045512-07281898b0f0
)

replace github.com/aquasecurity/kubectl-who-can => github.com/zubron/kubectl-who-can v0.1.0-beta.2.0.20200109193533-711350fdb148
