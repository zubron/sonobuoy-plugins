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
sonobuoy run --plugin https://raw.githubusercontent.com/zubron/sonobuoy-plugins/who-can/who-can/who-can.yaml
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
The plugin produces a JSON file which includes the result of all queries performed in the following format:

```
  {
    "resource": "pods",
    "verb": "list",
    "namespace": "default",
    "role-bindings": [
      {
        "name": "podlister-rb",
        "type": "User",
        "subject": "test-user",
        "namespace": "default"
      },
      {
        "name": "podlister-rb",
        "type": "Group",
        "subject": "test-group",
        "namespace": "default"
      }
    ],
    "cluster-role-bindings": [
      {
        "name": "cluster-admin",
        "type": "Group",
        "subject": "system:masters"
      },
      {
        "name": "system:controller:attachdetach-controller",
        "type": "ServiceAccount",
        "subject": "attachdetach-controller",
        "sa-namespace": "kube-system"
      },
      {
        "name": "system:controller:cronjob-controller",
        "type": "ServiceAccount",
        "subject": "cronjob-controller",
        "sa-namespace": "kube-system"
      },
      {
        "name": "system:kube-scheduler",
        "type": "User",
        "subject": "system:kube-scheduler"
      }
    ]
  }

```

The above obehct shows that the query checked who can `list pods` in the default namespace.
The `role-bindings` and `cluster-role-bindings` show the subjects that can perform those actions as a result of those bindings.
For example, the User subject `test-user` can list pods in the `default` namespace.
The bindings also show which namespace they belong to.
For example, the `podlister-rb` RoleBinding was created in the `default` namespace, however the `system:controller:cronjob-controller` ClusterRoleBinding was created in the `kube-system` namespace.
