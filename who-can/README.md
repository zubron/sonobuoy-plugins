# who-can

This plugin utilizes the [`kubectl-who-can` project from AquaSecurity](https://github.com/aquasecurity/kubectl-who-can) to produce a report of who can perform actions against resource types in a cluster.

It iterates over all resources and subresources available on the cluster and checks who can perform each of the supported verbs for these resources.

## Usage

To run this plugin, run the following command:

```
sonobuoy run --plugin https://raw.githubusercontent.com/zubron/sonobuoy-plugins/who-can/who-can/who-can.yaml
```
