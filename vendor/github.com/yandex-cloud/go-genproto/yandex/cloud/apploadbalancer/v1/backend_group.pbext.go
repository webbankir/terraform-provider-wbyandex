// Code generated by protoc-gen-goext. DO NOT EDIT.

package apploadbalancer

import (
	duration "github.com/golang/protobuf/ptypes/duration"
	timestamp "github.com/golang/protobuf/ptypes/timestamp"
	wrappers "github.com/golang/protobuf/ptypes/wrappers"
)

type BackendGroup_Backend = isBackendGroup_Backend

func (m *BackendGroup) SetBackend(v BackendGroup_Backend) {
	m.Backend = v
}

func (m *BackendGroup) SetId(v string) {
	m.Id = v
}

func (m *BackendGroup) SetName(v string) {
	m.Name = v
}

func (m *BackendGroup) SetDescription(v string) {
	m.Description = v
}

func (m *BackendGroup) SetFolderId(v string) {
	m.FolderId = v
}

func (m *BackendGroup) SetLabels(v map[string]string) {
	m.Labels = v
}

func (m *BackendGroup) SetHttp(v *HttpBackendGroup) {
	m.Backend = &BackendGroup_Http{
		Http: v,
	}
}

func (m *BackendGroup) SetGrpc(v *GrpcBackendGroup) {
	m.Backend = &BackendGroup_Grpc{
		Grpc: v,
	}
}

func (m *BackendGroup) SetCreatedAt(v *timestamp.Timestamp) {
	m.CreatedAt = v
}

func (m *HttpBackendGroup) SetBackends(v []*HttpBackend) {
	m.Backends = v
}

func (m *GrpcBackendGroup) SetBackends(v []*GrpcBackend) {
	m.Backends = v
}

func (m *HeaderSessionAffinity) SetHeaderName(v string) {
	m.HeaderName = v
}

func (m *CookieSessionAffinity) SetName(v string) {
	m.Name = v
}

func (m *CookieSessionAffinity) SetTtl(v *duration.Duration) {
	m.Ttl = v
}

func (m *ConnectionSessionAffinity) SetSourceIp(v bool) {
	m.SourceIp = v
}

func (m *LoadBalancingConfig) SetPanicThreshold(v int64) {
	m.PanicThreshold = v
}

func (m *LoadBalancingConfig) SetLocalityAwareRoutingPercent(v int64) {
	m.LocalityAwareRoutingPercent = v
}

func (m *LoadBalancingConfig) SetStrictLocality(v bool) {
	m.StrictLocality = v
}

type HttpBackend_BackendType = isHttpBackend_BackendType

func (m *HttpBackend) SetBackendType(v HttpBackend_BackendType) {
	m.BackendType = v
}

func (m *HttpBackend) SetName(v string) {
	m.Name = v
}

func (m *HttpBackend) SetBackendWeight(v *wrappers.Int64Value) {
	m.BackendWeight = v
}

func (m *HttpBackend) SetLoadBalancingConfig(v *LoadBalancingConfig) {
	m.LoadBalancingConfig = v
}

func (m *HttpBackend) SetPort(v int64) {
	m.Port = v
}

func (m *HttpBackend) SetTargetGroups(v *TargetGroupsBackend) {
	m.BackendType = &HttpBackend_TargetGroups{
		TargetGroups: v,
	}
}

func (m *HttpBackend) SetHealthchecks(v []*HealthCheck) {
	m.Healthchecks = v
}

func (m *HttpBackend) SetTls(v *BackendTls) {
	m.Tls = v
}

func (m *HttpBackend) SetUseHttp2(v bool) {
	m.UseHttp2 = v
}

type GrpcBackend_BackendType = isGrpcBackend_BackendType

func (m *GrpcBackend) SetBackendType(v GrpcBackend_BackendType) {
	m.BackendType = v
}

func (m *GrpcBackend) SetName(v string) {
	m.Name = v
}

func (m *GrpcBackend) SetBackendWeight(v *wrappers.Int64Value) {
	m.BackendWeight = v
}

func (m *GrpcBackend) SetLoadBalancingConfig(v *LoadBalancingConfig) {
	m.LoadBalancingConfig = v
}

func (m *GrpcBackend) SetPort(v int64) {
	m.Port = v
}

func (m *GrpcBackend) SetTargetGroups(v *TargetGroupsBackend) {
	m.BackendType = &GrpcBackend_TargetGroups{
		TargetGroups: v,
	}
}

func (m *GrpcBackend) SetHealthchecks(v []*HealthCheck) {
	m.Healthchecks = v
}

func (m *GrpcBackend) SetTls(v *BackendTls) {
	m.Tls = v
}

func (m *TargetGroupsBackend) SetTargetGroupIds(v []string) {
	m.TargetGroupIds = v
}

func (m *BackendTls) SetSni(v string) {
	m.Sni = v
}

func (m *BackendTls) SetValidationContext(v *ValidationContext) {
	m.ValidationContext = v
}

type HealthCheck_Healthcheck = isHealthCheck_Healthcheck

func (m *HealthCheck) SetHealthcheck(v HealthCheck_Healthcheck) {
	m.Healthcheck = v
}

func (m *HealthCheck) SetTimeout(v *duration.Duration) {
	m.Timeout = v
}

func (m *HealthCheck) SetInterval(v *duration.Duration) {
	m.Interval = v
}

func (m *HealthCheck) SetIntervalJitterPercent(v float64) {
	m.IntervalJitterPercent = v
}

func (m *HealthCheck) SetHealthyThreshold(v int64) {
	m.HealthyThreshold = v
}

func (m *HealthCheck) SetUnhealthyThreshold(v int64) {
	m.UnhealthyThreshold = v
}

func (m *HealthCheck) SetHealthcheckPort(v int64) {
	m.HealthcheckPort = v
}

func (m *HealthCheck) SetStream(v *HealthCheck_StreamHealthCheck) {
	m.Healthcheck = &HealthCheck_Stream{
		Stream: v,
	}
}

func (m *HealthCheck) SetHttp(v *HealthCheck_HttpHealthCheck) {
	m.Healthcheck = &HealthCheck_Http{
		Http: v,
	}
}

func (m *HealthCheck) SetGrpc(v *HealthCheck_GrpcHealthCheck) {
	m.Healthcheck = &HealthCheck_Grpc{
		Grpc: v,
	}
}

func (m *HealthCheck_StreamHealthCheck) SetSend(v *Payload) {
	m.Send = v
}

func (m *HealthCheck_StreamHealthCheck) SetReceive(v *Payload) {
	m.Receive = v
}

func (m *HealthCheck_HttpHealthCheck) SetHost(v string) {
	m.Host = v
}

func (m *HealthCheck_HttpHealthCheck) SetPath(v string) {
	m.Path = v
}

func (m *HealthCheck_HttpHealthCheck) SetUseHttp2(v bool) {
	m.UseHttp2 = v
}

func (m *HealthCheck_GrpcHealthCheck) SetServiceName(v string) {
	m.ServiceName = v
}
