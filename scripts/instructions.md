Instructions to generate install.sh

- The script needs to support installation in two environments: Kind worker node and AKS Flex node. Any other environment is not supported.
- To detect whether script is running on an AKS flex node, it should check for the presence of /usr/local/bin/aks-flex-node binary.
- It should also use some mechanism to detect whether script is running on a kind worker node.
- Maintain install.sh to neatly support these two environments with extensibility for adding a 3rd environment.
- When running on AKS Flex node:
  - The location of the kubelet's kubeconfig is /var/lib/kubelet/kubeconfig
  - The kubelet's kubeconfig user section uses the exec technique and not client credentials to authenticate to API server. The relevant kubeconfig section will be of the form:
    ```json
    users:
    - name: arc-user
      user:
        exec:
          apiVersion: client.authentication.k8s.io/v1beta1
          command: /var/lib/kubelet/token.sh
          env: null
          provideClusterInfo: false
    So kubelet-proxy kubeconfig should be created taking the above scheme under consideration.
    ```
  
