package plugin

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"

	"github.com/argoproj/argo-rollouts/pkg/apis/rollouts/v1alpha1"
	plugintypes "github.com/argoproj/argo-rollouts/utils/plugin/types"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/yaml"
)

const (
	weightedBackendsAnnotation = "http.kedify.io/weighted-backends"
)

var httpsoGVR = schema.GroupVersionResource{
	Group:    "http.keda.sh",
	Version:  "v1alpha1",
	Resource: "httpscaledobjects",
}

// WeightedBackend represents a single backend in a weighted traffic split
type WeightedBackend struct {
	Service string `json:"service" yaml:"service"`
	Weight  uint32 `json:"weight" yaml:"weight"`
}

// KedifyPluginConfig is the plugin configuration from the Rollout CR
type KedifyPluginConfig struct {
	HTTPScaledObjectName string `json:"httpScaledObjectName"`
}

// KedifyPlugin implements the Argo Rollouts TrafficRouterPlugin interface
type KedifyPlugin struct {
	client dynamic.Interface
}

func (p *KedifyPlugin) InitPlugin() plugintypes.RpcError {
	config, err := rest.InClusterConfig()
	if err != nil {
		return plugintypes.RpcError{ErrorString: fmt.Sprintf("failed to get in-cluster config: %v", err)}
	}
	p.client, err = dynamic.NewForConfig(config)
	if err != nil {
		return plugintypes.RpcError{ErrorString: fmt.Sprintf("failed to create dynamic client: %v", err)}
	}
	slog.Info("KedifyPlugin initialized")
	return plugintypes.RpcError{}
}

func (p *KedifyPlugin) Type() string {
	return "Kedify"
}

func (p *KedifyPlugin) SetWeight(rollout *v1alpha1.Rollout, desiredWeight int32, additionalDestinations []v1alpha1.WeightDestination) plugintypes.RpcError {
	cfg, err := parsePluginConfig(rollout)
	if err != nil {
		return plugintypes.RpcError{ErrorString: err.Error()}
	}

	stableService := rollout.Spec.Strategy.Canary.StableService
	canaryService := rollout.Spec.Strategy.Canary.CanaryService
	if stableService == "" || canaryService == "" {
		return plugintypes.RpcError{ErrorString: "stableService and canaryService must be set in rollout spec"}
	}

	namespace := rollout.Namespace
	slog.Info("SetWeight", "httpso", cfg.HTTPScaledObjectName, "namespace", namespace,
		"desiredWeight", desiredWeight, "stable", stableService, "canary", canaryService)

	var patch map[string]interface{}
	if desiredWeight == 0 {
		// remove annotation when weight is 0 (promotion complete)
		patch = map[string]interface{}{
			"metadata": map[string]interface{}{
				"annotations": map[string]interface{}{
					weightedBackendsAnnotation: nil,
				},
			},
		}
	} else {
		backends := []WeightedBackend{
			{Service: stableService, Weight: uint32(100 - desiredWeight)},
			{Service: canaryService, Weight: uint32(desiredWeight)},
		}
		backendsYAML, err := yaml.Marshal(backends)
		if err != nil {
			return plugintypes.RpcError{ErrorString: fmt.Sprintf("failed to marshal weighted backends: %v", err)}
		}
		patch = map[string]interface{}{
			"metadata": map[string]interface{}{
				"annotations": map[string]interface{}{
					weightedBackendsAnnotation: string(backendsYAML),
				},
			},
		}
	}

	patchBytes, err := json.Marshal(patch)
	if err != nil {
		return plugintypes.RpcError{ErrorString: fmt.Sprintf("failed to marshal patch: %v", err)}
	}

	_, err = p.client.Resource(httpsoGVR).Namespace(namespace).Patch(
		context.Background(),
		cfg.HTTPScaledObjectName,
		types.MergePatchType,
		patchBytes,
		metav1.PatchOptions{},
	)
	if err != nil {
		return plugintypes.RpcError{ErrorString: fmt.Sprintf("failed to patch HTTPSO %s/%s: %v", namespace, cfg.HTTPScaledObjectName, err)}
	}

	slog.Info("SetWeight completed", "httpso", cfg.HTTPScaledObjectName, "desiredWeight", desiredWeight)
	return plugintypes.RpcError{}
}

func (p *KedifyPlugin) VerifyWeight(rollout *v1alpha1.Rollout, desiredWeight int32, additionalDestinations []v1alpha1.WeightDestination) (plugintypes.RpcVerified, plugintypes.RpcError) {
	cfg, err := parsePluginConfig(rollout)
	if err != nil {
		return plugintypes.NotVerified, plugintypes.RpcError{ErrorString: err.Error()}
	}

	namespace := rollout.Namespace
	httpso, err := p.client.Resource(httpsoGVR).Namespace(namespace).Get(
		context.Background(),
		cfg.HTTPScaledObjectName,
		metav1.GetOptions{},
	)
	if err != nil {
		return plugintypes.NotVerified, plugintypes.RpcError{ErrorString: fmt.Sprintf("failed to get HTTPSO: %v", err)}
	}

	annotations := httpso.GetAnnotations()
	if desiredWeight == 0 {
		// weight 0 means promotion is complete, annotation should be removed
		if _, exists := annotations[weightedBackendsAnnotation]; !exists {
			return plugintypes.Verified, plugintypes.RpcError{}
		}
		return plugintypes.NotVerified, plugintypes.RpcError{}
	}

	annotationValue, exists := annotations[weightedBackendsAnnotation]
	if !exists {
		return plugintypes.NotVerified, plugintypes.RpcError{}
	}

	var backends []WeightedBackend
	if err := yaml.Unmarshal([]byte(annotationValue), &backends); err != nil {
		return plugintypes.NotVerified, plugintypes.RpcError{ErrorString: fmt.Sprintf("failed to parse annotation: %v", err)}
	}

	canaryService := rollout.Spec.Strategy.Canary.CanaryService
	for _, b := range backends {
		if b.Service == canaryService && int32(b.Weight) == desiredWeight {
			return plugintypes.Verified, plugintypes.RpcError{}
		}
	}

	return plugintypes.NotVerified, plugintypes.RpcError{}
}

func (p *KedifyPlugin) RemoveManagedRoutes(rollout *v1alpha1.Rollout) plugintypes.RpcError {
	cfg, err := parsePluginConfig(rollout)
	if err != nil {
		return plugintypes.RpcError{ErrorString: err.Error()}
	}

	namespace := rollout.Namespace
	slog.Info("RemoveManagedRoutes", "httpso", cfg.HTTPScaledObjectName, "namespace", namespace)

	patch := map[string]interface{}{
		"metadata": map[string]interface{}{
			"annotations": map[string]interface{}{
				weightedBackendsAnnotation: nil,
			},
		},
	}
	patchBytes, err := json.Marshal(patch)
	if err != nil {
		return plugintypes.RpcError{ErrorString: fmt.Sprintf("failed to marshal patch: %v", err)}
	}

	_, err = p.client.Resource(httpsoGVR).Namespace(namespace).Patch(
		context.Background(),
		cfg.HTTPScaledObjectName,
		types.MergePatchType,
		patchBytes,
		metav1.PatchOptions{},
	)
	if err != nil {
		return plugintypes.RpcError{ErrorString: fmt.Sprintf("failed to patch HTTPSO: %v", err)}
	}

	return plugintypes.RpcError{}
}

func (p *KedifyPlugin) UpdateHash(rollout *v1alpha1.Rollout, canaryHash string, stableHash string, additionalDestinations []v1alpha1.WeightDestination) plugintypes.RpcError {
	return plugintypes.RpcError{}
}

func (p *KedifyPlugin) SetHeaderRoute(rollout *v1alpha1.Rollout, setHeaderRoute *v1alpha1.SetHeaderRoute) plugintypes.RpcError {
	return plugintypes.RpcError{}
}

func (p *KedifyPlugin) SetMirrorRoute(rollout *v1alpha1.Rollout, setMirrorRoute *v1alpha1.SetMirrorRoute) plugintypes.RpcError {
	return plugintypes.RpcError{}
}

// parsePluginConfig extracts the Kedify plugin config from the Rollout spec
func parsePluginConfig(rollout *v1alpha1.Rollout) (*KedifyPluginConfig, error) {
	if rollout.Spec.Strategy.Canary == nil ||
		rollout.Spec.Strategy.Canary.TrafficRouting == nil ||
		rollout.Spec.Strategy.Canary.TrafficRouting.Plugins == nil {
		return nil, fmt.Errorf("rollout %s/%s has no traffic routing plugins configured", rollout.Namespace, rollout.Name)
	}

	pluginConfig, ok := rollout.Spec.Strategy.Canary.TrafficRouting.Plugins["kedify"]
	if !ok {
		return nil, fmt.Errorf("rollout %s/%s has no 'kedify' plugin config", rollout.Namespace, rollout.Name)
	}

	cfg := &KedifyPluginConfig{}
	// Plugin config comes as json.RawMessage
	if err := json.Unmarshal(pluginConfig, cfg); err != nil {
		return nil, fmt.Errorf("failed to parse kedify plugin config: %w", err)
	}
	if cfg.HTTPScaledObjectName == "" {
		return nil, fmt.Errorf("kedify plugin config missing httpScaledObjectName")
	}

	return cfg, nil
}

// SetClient allows injecting a client for testing
func (p *KedifyPlugin) SetClient(client dynamic.Interface) {
	p.client = client
}

// GetHTTPSO retrieves the HTTPSO for testing/debugging
func (p *KedifyPlugin) GetHTTPSO(namespace, name string) (*unstructured.Unstructured, error) {
	return p.client.Resource(httpsoGVR).Namespace(namespace).Get(
		context.Background(),
		name,
		metav1.GetOptions{},
	)
}
