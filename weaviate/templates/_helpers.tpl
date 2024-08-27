{{/* Generate the enabled modules config. This can be done a lot nicer once we drop Helm v2 support */}}
{{ define "enabled_modules" }}
  {{- $modules := list -}}
  {{- if or (index .Values "modules" "text2vec-contextionary" "enabled") (index .Values "modules" "text2vec-contextionary" "inferenceUrl") -}}
    {{ $modules = append $modules "text2vec-contextionary" }}
  {{- end -}}
  {{- if or (index .Values "modules" "text2vec-transformers" "enabled") (index .Values "modules" "text2vec-transformers" "inferenceUrl") -}}
    {{ $modules = append $modules "text2vec-transformers" }}
  {{- else if or (index .Values "modules" "text2vec-transformers" "passageQueryServices" "passage" "enabled") (index .Values "modules" "text2vec-transformers" "passageQueryServices" "passage" "inferenceUrl") -}}
    {{ $modules = append $modules "text2vec-transformers" }}
  {{- else if or (index .Values "modules" "text2vec-transformers" "passageQueryServices" "query" "enabled") (index .Values "modules" "text2vec-transformers" "passageQueryServices" "query" "inferenceUrl") -}}
    {{ $modules = append $modules "text2vec-transformers" }}
  {{- end -}}
  {{- if or (index .Values "modules" "text2vec-gpt4all" "enabled") (index .Values "modules" "text2vec-gpt4all" "inferenceUrl") -}}
    {{ $modules = append $modules "text2vec-gpt4all" }}
  {{- end -}}
  {{- if or (index .Values "modules" "qna-transformers" "enabled") (index .Values "modules" "qna-transformers" "inferenceUrl") -}}
    {{ $modules = append $modules "qna-transformers" }}
  {{- end -}}
  {{- if (index .Values "modules" "qna-openai" "enabled") -}}
    {{ $modules = append $modules "qna-openai" }}
  {{- end -}}
  {{- if (index .Values "modules" "generative-openai" "enabled") -}}
    {{ $modules = append $modules "generative-openai" }}
  {{- end -}}
  {{- if (index .Values "modules" "generative-cohere" "enabled") -}}
    {{ $modules = append $modules "generative-cohere" }}
  {{- end -}}
  {{- if (index .Values "modules" "generative-palm" "enabled") -}}
    {{ $modules = append $modules "generative-palm" }}
  {{- end -}}
  {{- if (index .Values "modules" "generative-aws" "enabled") -}}
    {{ $modules = append $modules "generative-aws" }}
  {{- end -}}
  {{- if (index .Values "modules" "generative-anyscale" "enabled") -}}
    {{ $modules = append $modules "generative-anyscale" }}
  {{- end -}}
  {{- if (index .Values "modules" "generative-mistral" "enabled") -}}
    {{ $modules = append $modules "generative-mistral" }}
  {{- end -}}
  {{- if (index .Values "modules" "generative-ollama" "enabled") -}}
    {{ $modules = append $modules "generative-ollama" }}
  {{- end -}}
  {{- if (index .Values "modules" "generative-octoai" "enabled") -}}
    {{ $modules = append $modules "generative-octoai" }}
  {{- end -}}
  {{- if (index .Values "modules" "generative-anthropic" "enabled") -}}
    {{ $modules = append $modules "generative-anthropic" }}
  {{- end -}}
  {{- if or (index .Values "modules" "img2vec-neural" "enabled") (index .Values "modules" "img2vec-neural" "inferenceUrl") -}}
    {{ $modules = append $modules "img2vec-neural" }}
  {{- end -}}
  {{- if or (index .Values "modules" "ner-transformers" "enabled") (index .Values "modules" "ner-transformers" "inferenceUrl") -}}
    {{ $modules = append $modules "ner-transformers" }}
  {{- end -}}
  {{- if or (index .Values "modules" "sum-transformers" "enabled") (index .Values "modules" "sum-transformers" "inferenceUrl") -}}
    {{ $modules = append $modules "sum-transformers" }}
  {{- end -}}
  {{- if or (index .Values "modules" "text-spellcheck" "enabled") (index .Values "modules" "text-spellcheck" "inferenceUrl") -}}
    {{ $modules = append $modules "text-spellcheck" }}
  {{- end -}}
  {{- if or (index .Values "modules" "multi2vec-clip" "enabled") (index .Values "modules" "multi2vec-clip" "inferenceUrl") -}}
    {{ $modules = append $modules "multi2vec-clip" }}
  {{- end -}}
  {{- if or (index .Values "modules" "multi2vec-bind" "enabled") (index .Values "modules" "multi2vec-bind" "inferenceUrl") -}}
    {{ $modules = append $modules "multi2vec-bind" }}
  {{- end -}}
  {{- if (index .Values "modules" "multi2vec-palm" "enabled") -}}
    {{ $modules = append $modules "multi2vec-palm" }}
  {{- end -}}
  {{- if (index .Values "modules" "text2vec-openai" "enabled") -}}
    {{ $modules = append $modules "text2vec-openai" }}
  {{- end -}}
  {{- if (index .Values "modules" "text2vec-huggingface" "enabled") -}}
    {{ $modules = append $modules "text2vec-huggingface" }}
  {{- end -}}
  {{- if (index .Values "modules" "text2vec-cohere" "enabled") -}}
    {{ $modules = append $modules "text2vec-cohere" }}
  {{- end -}}
  {{- if (index .Values "modules" "text2vec-palm" "enabled") -}}
    {{ $modules = append $modules "text2vec-palm" }}
  {{- end -}}
  {{- if (index .Values "modules" "text2vec-jinaai" "enabled") -}}
    {{ $modules = append $modules "text2vec-jinaai" }}
  {{- end -}}
  {{- if (index .Values "modules" "text2vec-aws" "enabled") -}}
    {{ $modules = append $modules "text2vec-aws" }}
  {{- end -}}
  {{- if (index .Values "modules" "text2vec-voyageai" "enabled") -}}
    {{ $modules = append $modules "text2vec-voyageai" }}
  {{- end -}}
  {{- if (index .Values "modules" "text2vec-ollama" "enabled") -}}
    {{ $modules = append $modules "text2vec-ollama" }}
  {{- end -}}
  {{- if (index .Values "modules" "text2vec-octoai" "enabled") -}}
    {{ $modules = append $modules "text2vec-octoai" }}
  {{- end -}}
  {{- if (index .Values "modules" "ref2vec-centroid" "enabled") -}}
    {{ $modules = append $modules "ref2vec-centroid" }}
  {{- end -}}
  {{- if (index .Values "modules" "reranker-cohere" "enabled") -}}
    {{ $modules = append $modules "reranker-cohere" }}
  {{- end -}}
  {{- if (index .Values "modules" "reranker-transformers" "enabled") -}}
    {{ $modules = append $modules "reranker-transformers" }}
  {{- end -}}
  {{- if (index .Values "modules" "reranker-voyageai" "enabled") -}}
    {{ $modules = append $modules "reranker-voyageai" }}
  {{- end -}}
  {{- if (index .Values "modules" "reranker-jinaai" "enabled") -}}
    {{ $modules = append $modules "reranker-jinaai" }}
  {{- end -}}
  {{- if (index .Values "offload" "s3" "enabled") -}}
    {{ $modules = append $modules "offload-s3" }}
  {{- end -}}
  {{- if (index .Values "backups" "filesystem" "enabled") -}}
    {{ $modules = append $modules "backup-filesystem" }}
  {{- end -}}
  {{- if (index .Values "backups" "s3" "enabled") -}}
    {{ $modules = append $modules "backup-s3" }}
  {{- end -}}
  {{- if (index .Values "backups" "gcs" "enabled") -}}
    {{ $modules = append $modules "backup-gcs" }}
  {{- end -}}
  {{- if (index .Values "backups" "azure" "enabled") -}}
    {{ $modules = append $modules "backup-azure" }}
  {{- end -}}
  {{- if gt (len $modules) 0 -}}
          - name: ENABLE_MODULES
            value: {{ join "," $modules }}
  {{- end -}}
{{- end -}}


{{/* 
Return Image pull secret Names
Usage:
{{- include "image.pullSecrets" (dict "pullSecrets" path_to_image_pullSecrets) | nindent 6 }}
*/}}
{{- define "image.pullSecrets" -}}
  {{- $pullSecrets := list -}}

  {{- if .pullSecrets -}}
    {{- range .pullSecrets -}}
      {{- $pullSecrets = append $pullSecrets . -}}
    {{- end -}}
  {{- end -}}

  {{- if (not (empty $pullSecrets)) -}}
imagePullSecrets:
    {{- range $pullSecrets }}
  - name: {{ . }}
    {{- end -}}
  {{- end -}}
{{- end -}}


{{/*
Cluster API Secrets
*/}}
{{- define "cluster_api.secret" -}}
{{- $secret := lookup "v1" "Secret" .Release.Namespace "weaviate-cluster-api-basic-auth" -}}
{{- if $secret -}}
{{/*
   Reusing value of secret if exist
*/}}
username: {{ $secret.data.username }}
password: {{ $secret.data.password }}
{{- else -}}
{{/*
    add new data
*/}}
username: {{ randAlphaNum 32 | b64enc | quote }}
password: {{ randAlphaNum 32 | b64enc | quote }}
{{- end -}}
{{- end -}}


{{/* 
Return PriorityClassName
Usage:
{{- include "pod.priorityClassName" ( dict "global" .Values.path.to.global.priorityClassName "priorityClassName" .Values.path.to.priorityClassName) | nindent 6 }}
*/}}
{{- define "pod.priorityClassName" -}}
  {{- $priorityClassName := "" -}}

  {{- if .global -}}
    {{- $priorityClassName = .global -}}
  {{- else if .priorityClassName -}}
    {{- $priorityClassName = .priorityClassName -}}
  {{- end -}}

  {{- if (not (empty $priorityClassName)) -}}
    {{- printf "priorityClassName: %s" $priorityClassName -}}
  {{- end -}}
{{- end -}}


{{/*
Raft cluster configuration settings
*/}}
{{- define "raft_configuration" -}}
  {{- $replicas := .Values.replicas | int -}}
  {{- $voters := .Values.env.RAFT_BOOTSTRAP_EXPECT | int -}}
  {{- $metada_only_voters := false -}}
  {{- if not (empty .Values.env.RAFT_METADATA_ONLY_VOTERS) -}}
    {{- $metada_only_voters = .Values.env.RAFT_METADATA_ONLY_VOTERS -}}
  {{- end -}} 
  {{- if empty .Values.env.RAFT_BOOTSTRAP_EXPECT -}}
    {{- if ge $replicas 10 -}}
      {{- $voters = 5 -}}
    {{- else if ge $replicas 3 -}}
      {{- $voters = 3 -}}
    {{- else -}}
      {{- $voters = 1 -}}
    {{- end -}}
  {{- end -}}
  {{- if gt $voters $replicas  -}}
    {{- fail "env.RAFT_BOOTSTRAP_EXPECT value cannot be greater than replicas value" -}}
  {{- end -}}
  {{- if empty .Values.env.RAFT_JOIN -}}
    {{- $nodes := list -}}
    {{- range $i := until $voters -}}
      {{- $node_name := list -}}
      {{- $node_name = append $node_name "weaviate" -}}
      {{- $node_name = append $node_name $i -}}
      {{- $nodes = append $nodes (join "-" $node_name) -}}
    {{- end -}}
          - name: RAFT_JOIN
            value: "{{ join "," $nodes }}"
  {{- else -}}
    {{- $votersCount := len (split "," .Values.env.RAFT_JOIN) -}}
    {{- if empty .Values.env.RAFT_BOOTSTRAP_EXPECT }}
      {{- $voters = $votersCount -}}
    {{- end -}}
    {{- if not (eq $votersCount $voters)  -}}
      {{- fail "env.RAFT_BOOTSTRAP_EXPECT value needs to be equal to number of env.RAFT_JOIN nodes" -}}
    {{- end -}}
  {{- end -}}
  {{- if empty .Values.env.RAFT_BOOTSTRAP_EXPECT }}
          - name: RAFT_BOOTSTRAP_EXPECT
            value: "{{ $voters }}"
  {{- end -}}
  {{- if and ($metada_only_voters) (le $replicas $voters) -}}
    {{- fail "env.RAFT_METADATA_ONLY_VOTERS is true then .replicas size must be greater than env.RAFT_BOOTSTRAP_EXPECT" -}}
  {{- end -}}
{{- end -}}
