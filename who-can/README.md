# who-can

This plugin utilizes the [`kubectl-who-can` project from AquaSecurity](https://github.com/aquasecurity/kubectl-who-can) to produce a report that shows which subjects have RBAC permissions to perform actions (verbs) against resources in the cluster.

This plugin makes use of a small runner which finds all the API resources available in the cluster.
It then iterates over all of these resources and subresources and checks which subjects can perform each of the supported verbs for the resource.

By default, it will perform the check against the default namespace.
This means that if the query is to check who can `create pods`, it will only check who can create pods in the default namespace.
Additional namespaces to query against can be specified by modifying the `WHO_CAN_CONFIG` entry in the [plugin definition](./who-can.yaml) to add more namespaces to the list.
The plugin definition currently includes the `kube-system` namespace and "all namespaces" (`*`) in this list.

## Usage

To run this plugin, run the following command:

```
sonobuoy run --plugin https://raw.githubusercontent.com/zubron/sonobuoy-plugins/who-can-subjects/who-can/who-can.yaml
```

The plugin status can be checked using the command:

```
sonobuoy status
```

Once the plugin is complete, retrieve the results using the command:

```
sonobuoy retrieve
```

This command will return the name of the results tarball.

The report from the plugin can be found in the tarball at the path `plugins/who-can/results/global/who-can-report.json`.

## Report format
The plugin produces a JSON file which includes details of all subjects found in the system and what they have permissions to do:

```
  {
    "kind": "ServiceAccount",
    "name": "kube-controller-manager",
    "namespace": "kube-system",
    "permissions": [
      {
        "namespace": "kube-system",
        "resources": [
          {
            "name": "configmaps",
            "verbs": [
              {
                "name": "watch",
                "roleBindings": [
                  "system::leader-locking-kube-controller-manager"
                ]
              }
            ]
          }
        ]
      }
    ]
  }
```

The above object shows details for the ServiceAccount `kube-controller-manager` which exists in the `kube-system` namespace.
This ServiceAccount has permissions in the `kube-system` namespace to perform the `watch` verb on `configmaps`.
This permission is given by the `system::leader-locking-kube-controller-manager` RoleBinding.
