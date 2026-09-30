{{- define "authz.labels" -}}
app.kubernetes.io/name: authz
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{- define "authz.selector" -}}
app.kubernetes.io/name: authz
app.kubernetes.io/component: server
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{- define "authz.domain" -}}
{{ required "domain is required (see helmvars/)" .Values.domain }}
{{- end }}
