# Idea

**Authenticate against docker registry using service account tokens**

Kubernetes provides an discovery endpoint for the openid configuration of the service accounts.
This can be used to check that a serviceaccount token is valid.

In every cluster a ClusterRole `system:service-account-issuer-discovery` exists that can be bound to access these information.

```
Name:         system:service-account-issuer-discovery
Labels:       kubernetes.io/bootstrapping=rbac-defaults
Annotations:  rbac.authorization.kubernetes.io/autoupdate: true
PolicyRule:
  Resources  Non-Resource URLs                     Resource Names  Verbs
  ---------  -----------------                     --------------  -----
             [/.well-known/openid-configuration/]  []              [get]
             [/.well-known/openid-configuration]   []              [get]
             [/openid/v1/jwks/]                    []              [get]
             [/openid/v1/jwks]                     []              [get]
```

By default, anonymous requests to these endpoints are not allowed so you need to create a rolebinding:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: oidc-reviewer
subjects:
- kind: Group
  name: system:unauthenticated
  apiGroup: rbac.authorization.k8s.io
roleRef:
  kind: ClusterRole
  name: system:service-account-issuer-discovery
  apiGroup: rbac.authorization.k8s.io
```

By default shoots do not enable anonymous authentication for the kubernetes apiserver. Therefore enable it:

```yaml
spec:
  kubernetes:
    kubeAPIServer:
      enableAnonymousAuthentication: true
```

Dockers config.json does not support reading the password from a file (ref <https://github.com/google/go-containerregistry/blob/59a4b85930392a30c39462519adc8a2026d47181/vendor/github.com/docker/cli/cli/config/configfile/file.go#L71-L88>). Therefore one must setup some sort of init container to copy the serviceaccount token (/var/run/secrets/kubernets.io/token) into the docker config or run a login command.

## Command Reference

**Inspecting service-account token**

```
kubectl exec deployments/token-pod -- cat /var/run/secrets/kubernetes.io/serviceaccount/token | jq -R 'split(".") | .[1] | @base64d | fromjson'
```

**API Server URL**

```
kubectl config view -o json | jq -r '.clusters[0].cluster.server'
```

**Dump CA into file**

```
kubectl get secret token -o jsonpath='{.data.ca\.crt}' | base64 -d > ca.crt
```

**Executing the auth prog**

```
go run main.go \
  -issuer $(kubectl config view -o json | jq -r '.clusters[1].cluster.server') \
  -ca-file ca.crt \
  foo \
  $(kubectl exec deployments/token-pod -- cat /var/run/secrets/kubernetes.io/serviceaccount/token) \
| jq     
```
