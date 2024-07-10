{{/* Determine fsm namespace */}}
{{- define "fsm.namespace" -}}
{{ default .Release.Namespace .Values.fsm.fsmNamespace}}
{{- end -}}

{{/* Labels to be added to all resources */}}
{{- define "fsm.labels" -}}
app.kubernetes.io/name: flomesh.io
app.kubernetes.io/instance: {{ .Values.fsm.meshName }}
app.kubernetes.io/version: {{ .Chart.AppVersion }}
{{- end -}}

{{/* Security context values that ensure restricted access to host resources */}}
{{- define "restricted.securityContext" -}}
securityContext:
    runAsUser: 1000
    runAsGroup: 3000
    fsGroup: 2000
    supplementalGroups: [5555]
{{- end -}}

{{/* fsm-curl image */}}
{{- define "fsmCurl.image" -}}
{{- if .Values.fsm.image.tag -}}
{{- printf "%s/%s:%s" .Values.fsm.image.registry .Values.fsm.image.name.fsmCurl .Values.fsm.image.tag -}}
{{- else -}}
{{- printf "%s/%s@%s" .Values.fsm.image.registry .Values.fsm.image.name.fsmCurl .Values.fsm.image.digest.fsmCurl -}}
{{- end -}}
{{- end -}}

{{/* ztm image */}}
{{- define "ztm.image" -}}
{{- if .Values.fsm.ztm.image.registry -}}
{{- printf "%s/%s:%s" .Values.fsm.ztm.image.registry .Values.fsm.ztm.image.name .Values.fsm.ztm.image.tag -}}
{{- else -}}
{{- printf "%s/%s:%s" .Values.fsm.image.registry .Values.fsm.ztm.image.name .Values.fsm.ztm.image.tag -}}
{{- end -}}
{{- end -}}

{{/* fsm-ztm-agent image */}}
{{- define "ztmController.image" -}}
{{- if .Values.fsm.image.tag -}}
{{- printf "%s/%s:%s" .Values.fsm.image.registry .Values.fsm.image.name.ztmController .Values.fsm.image.tag -}}
{{- else -}}
{{- printf "%s/%s@%s" .Values.fsm.image.registry .Values.fsm.image.name.ztmController .Values.fsm.image.digest.ztmController -}}
{{- end -}}
{{- end -}}

{{/* fsm ztm controller's name */}}
{{- define "ztmController.name" -}}
{{- printf "fsm-ztmagent-%s" .Values.fsm.ztmController.name -}}
{{- end -}}
