# Weaviate

[Weaviate](https://weaviate.io) is a decentralised vector search engine.

Please visit the [official docs](https://weaviate.io/developers/weaviate/installation/kubernetes)
to learn how to install Weaviate on K8s using helm.

## Install

```bash
helm repo add weaviate https://weaviate.github.io/weaviate-helm
helm install my-weaviate weaviate/weaviate
```


## Helm upgrade
```bash
helm upgrade --install   "weaviate"   ./weaviate   --namespace "weaviate"   --values ./weaviate/values.yaml
```