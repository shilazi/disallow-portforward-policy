# disallow-portforward-policy

Disallow the `kubectl port-forward` sub-command.

## Build

```bash
make
```

## Usage

1. Upload `disallow-portforward-policy-v1.0.0.wasm` to static server
2. Generate `ClusterAdmissionPolicy` manifest
    ```yaml
    apiVersion: policies.kubewarden.io/v1alpha2
    kind: ClusterAdmissionPolicy
    metadata:
      name: disallow-portforward-policy
    spec:
      module: https://your.server/kubewarden/policies/disallow-portforward-policy-v1.0.0.wasm
      rules:
      - apiGroups: [""]
        apiVersions: ["v1"]
        resources: ["pods/portforward"]
        operations: ["CONNECT"]
      mutating: false
      settings:
        # exempt with service account by username
        exempt_users:
        - kubernetes-admin
        # exempt with pod name
        exempt_pod_names:
        - foo
        # exempt with Namespace
        exempt_namespaces:
        - kube-system
    ```
3. Apply with kubectl
   ```bash
   kubectl apply -f disallow-portforward-policy.yml
   ```

## Validation

With exempt:

```
$ kubectl port-forward foo 8888:80
Forwarding from 127.0.0.1:8888 -> 80
Forwarding from [::1]:8888 -> 80
```

```
accepting resource with exemption data={"column":5,"file":"src/lib.rs","line":67,"policy":"disallow-portforward-policy"}
```

Without exempt:

```
$ kubectl port-forward bar 8888:80
error: error upgrading connection: admission webhook "disallow-portforward-policy.kubewarden.admission" denied the request: The 'port-forward' is on the deny kubectl sub-command list
```
