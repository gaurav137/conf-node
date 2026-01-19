package admission

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"regexp"
	"strings"
)

// Policy defines the admission policy configuration
type Policy struct {
	// Name of the policy
	Name string `json:"name"`

	// DefaultAction is the default action when no rules match (allow/deny)
	DefaultAction string `json:"defaultAction"`

	// Rules are the admission rules to evaluate
	Rules []PolicyRule `json:"rules"`
}

// PolicyRule defines a single admission rule
type PolicyRule struct {
	// Name of the rule
	Name string `json:"name"`

	// Action is the action to take when the rule matches (allow/deny)
	Action string `json:"action"`

	// Match defines the matching criteria
	Match PolicyMatch `json:"match"`

	// Message is the message to return when the rule matches
	Message string `json:"message,omitempty"`
}

// PolicyMatch defines matching criteria for a rule
type PolicyMatch struct {
	// Namespaces to match (supports wildcards)
	Namespaces []string `json:"namespaces,omitempty"`

	// NamespaceRegex is a regex pattern for namespace matching
	NamespaceRegex string `json:"namespaceRegex,omitempty"`

	// Labels to match (all must match)
	Labels map[string]string `json:"labels,omitempty"`

	// Annotations to match (all must match)
	Annotations map[string]string `json:"annotations,omitempty"`

	// Images defines image matching rules
	Images *ImageMatch `json:"images,omitempty"`

	// Security defines security-related matching
	Security *SecurityMatch `json:"security,omitempty"`
}

// ImageMatch defines image matching criteria
type ImageMatch struct {
	// Allowed is a list of allowed image patterns (supports wildcards)
	Allowed []string `json:"allowed,omitempty"`

	// Denied is a list of denied image patterns (supports wildcards)
	Denied []string `json:"denied,omitempty"`

	// RequireDigest requires images to have a digest
	RequireDigest bool `json:"requireDigest,omitempty"`

	// AllowedRegistries is a list of allowed registries
	AllowedRegistries []string `json:"allowedRegistries,omitempty"`

	// DeniedRegistries is a list of denied registries
	DeniedRegistries []string `json:"deniedRegistries,omitempty"`
}

// SecurityMatch defines security matching criteria
type SecurityMatch struct {
	// DenyPrivileged denies privileged containers
	DenyPrivileged bool `json:"denyPrivileged,omitempty"`

	// DenyHostNetwork denies host network usage
	DenyHostNetwork bool `json:"denyHostNetwork,omitempty"`

	// DenyHostPID denies host PID namespace
	DenyHostPID bool `json:"denyHostPID,omitempty"`

	// DenyHostIPC denies host IPC namespace
	DenyHostIPC bool `json:"denyHostIPC,omitempty"`

	// DenyRunAsRoot denies running as root
	DenyRunAsRoot bool `json:"denyRunAsRoot,omitempty"`

	// DeniedCapabilities is a list of denied capabilities
	DeniedCapabilities []string `json:"deniedCapabilities,omitempty"`

	// DenyHostPath denies hostPath volumes
	DenyHostPath bool `json:"denyHostPath,omitempty"`
}

// PolicyController is an admission controller based on policy rules
type PolicyController struct {
	policy *Policy
	logger *log.Logger
}

// NewPolicyController creates a new policy-based admission controller
func NewPolicyController(policyFile string) (*PolicyController, error) {
	data, err := os.ReadFile(policyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read policy file: %w", err)
	}

	var policy Policy
	if err := json.Unmarshal(data, &policy); err != nil {
		return nil, fmt.Errorf("failed to parse policy file: %w", err)
	}

	// Validate policy
	if policy.DefaultAction != "allow" && policy.DefaultAction != "deny" {
		return nil, fmt.Errorf("invalid default action: %s (must be 'allow' or 'deny')", policy.DefaultAction)
	}

	for i, rule := range policy.Rules {
		if rule.Action != "allow" && rule.Action != "deny" {
			return nil, fmt.Errorf("invalid action in rule %d (%s): %s", i, rule.Name, rule.Action)
		}
	}

	logger := log.New(os.Stdout, "[admission-policy] ", log.LstdFlags|log.Lmicroseconds)
	logger.Printf("Loaded policy '%s' with %d rules (default: %s)",
		policy.Name, len(policy.Rules), policy.DefaultAction)

	return &PolicyController{
		policy: &policy,
		logger: logger,
	}, nil
}

// Name returns the name of the controller
func (c *PolicyController) Name() string {
	return "policy:" + c.policy.Name
}

// Admit evaluates the pod against policy rules
func (c *PolicyController) Admit(req *Request) *Decision {
	c.logger.Printf("Evaluating pod %s/%s", req.Namespace, req.Name)

	// Evaluate rules in order
	for _, rule := range c.policy.Rules {
		matches, reason := c.matchRule(&rule, req)
		if matches {
			c.logger.Printf("Rule '%s' matched: action=%s, reason=%s", rule.Name, rule.Action, reason)
			if rule.Action == "deny" {
				message := rule.Message
				if message == "" {
					message = reason
				}
				return Deny(fmt.Sprintf("denied by rule '%s': %s", rule.Name, message))
			}
			return Allow(fmt.Sprintf("allowed by rule '%s': %s", rule.Name, reason))
		}
	}

	// No rules matched, use default action
	c.logger.Printf("No rules matched, using default action: %s", c.policy.DefaultAction)
	if c.policy.DefaultAction == "deny" {
		return Deny("no matching rules, default action is deny")
	}
	return Allow("no matching rules, default action is allow")
}

func (c *PolicyController) matchRule(rule *PolicyRule, req *Request) (bool, string) {
	match := &rule.Match

	// Check namespace match
	if len(match.Namespaces) > 0 {
		if !matchesAny(req.Namespace, match.Namespaces) {
			return false, ""
		}
	}

	if match.NamespaceRegex != "" {
		re, err := regexp.Compile(match.NamespaceRegex)
		if err != nil {
			c.logger.Printf("Invalid namespace regex in rule '%s': %v", rule.Name, err)
			return false, ""
		}
		if !re.MatchString(req.Namespace) {
			return false, ""
		}
	}

	// Check label match
	if len(match.Labels) > 0 {
		podLabels := getLabels(req.Pod)
		for k, v := range match.Labels {
			if podLabels[k] != v {
				return false, ""
			}
		}
	}

	// Check annotation match
	if len(match.Annotations) > 0 {
		podAnnotations := getAnnotations(req.Pod)
		for k, v := range match.Annotations {
			if podAnnotations[k] != v {
				return false, ""
			}
		}
	}

	// Check image match
	if match.Images != nil {
		images := getImages(req.Pod)
		matched, reason := c.matchImages(match.Images, images)
		if !matched {
			return false, ""
		}
		if reason != "" {
			return true, reason
		}
	}

	// Check security match
	if match.Security != nil {
		matched, reason := c.matchSecurity(match.Security, req.Pod)
		if matched {
			return true, reason
		}
		return false, ""
	}

	return true, "matched all criteria"
}

func (c *PolicyController) matchImages(match *ImageMatch, images []string) (bool, string) {
	for _, image := range images {
		// Check denied images
		for _, pattern := range match.Denied {
			if matchPattern(image, pattern) {
				return true, fmt.Sprintf("image '%s' matches denied pattern '%s'", image, pattern)
			}
		}

		// Check denied registries
		for _, registry := range match.DeniedRegistries {
			if strings.HasPrefix(image, registry) {
				return true, fmt.Sprintf("image '%s' from denied registry '%s'", image, registry)
			}
		}

		// Check allowed registries (if specified, image must be from one of them)
		if len(match.AllowedRegistries) > 0 {
			allowed := false
			for _, registry := range match.AllowedRegistries {
				if strings.HasPrefix(image, registry) {
					allowed = true
					break
				}
			}
			if !allowed {
				return true, fmt.Sprintf("image '%s' not from allowed registries", image)
			}
		}

		// Check require digest
		if match.RequireDigest {
			if !strings.Contains(image, "@sha256:") {
				return true, fmt.Sprintf("image '%s' does not have a digest", image)
			}
		}
	}

	return false, ""
}

func (c *PolicyController) matchSecurity(match *SecurityMatch, pod map[string]interface{}) (bool, string) {
	spec, ok := pod["spec"].(map[string]interface{})
	if !ok {
		return false, ""
	}

	// Check host namespace settings
	if match.DenyHostNetwork {
		if hostNetwork, ok := spec["hostNetwork"].(bool); ok && hostNetwork {
			return true, "pod uses hostNetwork"
		}
	}

	if match.DenyHostPID {
		if hostPID, ok := spec["hostPID"].(bool); ok && hostPID {
			return true, "pod uses hostPID"
		}
	}

	if match.DenyHostIPC {
		if hostIPC, ok := spec["hostIPC"].(bool); ok && hostIPC {
			return true, "pod uses hostIPC"
		}
	}

	// Check hostPath volumes
	if match.DenyHostPath {
		if volumes, ok := spec["volumes"].([]interface{}); ok {
			for _, vol := range volumes {
				if volume, ok := vol.(map[string]interface{}); ok {
					if _, hasHostPath := volume["hostPath"]; hasHostPath {
						return true, "pod uses hostPath volume"
					}
				}
			}
		}
	}

	// Check container security contexts
	containers := getContainers(spec)
	for _, container := range containers {
		name, _ := container["name"].(string)

		secCtx, ok := container["securityContext"].(map[string]interface{})
		if !ok {
			continue
		}

		if match.DenyPrivileged {
			if privileged, ok := secCtx["privileged"].(bool); ok && privileged {
				return true, fmt.Sprintf("container '%s' is privileged", name)
			}
		}

		if match.DenyRunAsRoot {
			if runAsUser, ok := secCtx["runAsUser"].(float64); ok && runAsUser == 0 {
				return true, fmt.Sprintf("container '%s' runs as root", name)
			}
		}

		if len(match.DeniedCapabilities) > 0 {
			if caps, ok := secCtx["capabilities"].(map[string]interface{}); ok {
				if add, ok := caps["add"].([]interface{}); ok {
					for _, cap := range add {
						if capStr, ok := cap.(string); ok {
							for _, denied := range match.DeniedCapabilities {
								if strings.EqualFold(capStr, denied) {
									return true, fmt.Sprintf("container '%s' adds denied capability '%s'", name, capStr)
								}
							}
						}
					}
				}
			}
		}
	}

	return false, ""
}

// Helper functions

func getLabels(pod map[string]interface{}) map[string]string {
	labels := make(map[string]string)
	if metadata, ok := pod["metadata"].(map[string]interface{}); ok {
		if l, ok := metadata["labels"].(map[string]interface{}); ok {
			for k, v := range l {
				if vs, ok := v.(string); ok {
					labels[k] = vs
				}
			}
		}
	}
	return labels
}

func getAnnotations(pod map[string]interface{}) map[string]string {
	annotations := make(map[string]string)
	if metadata, ok := pod["metadata"].(map[string]interface{}); ok {
		if a, ok := metadata["annotations"].(map[string]interface{}); ok {
			for k, v := range a {
				if vs, ok := v.(string); ok {
					annotations[k] = vs
				}
			}
		}
	}
	return annotations
}

func getImages(pod map[string]interface{}) []string {
	var images []string
	if spec, ok := pod["spec"].(map[string]interface{}); ok {
		for _, container := range getContainers(spec) {
			if image, ok := container["image"].(string); ok {
				images = append(images, image)
			}
		}
	}
	return images
}

func getContainers(spec map[string]interface{}) []map[string]interface{} {
	var result []map[string]interface{}
	for _, key := range []string{"containers", "initContainers", "ephemeralContainers"} {
		if containers, ok := spec[key].([]interface{}); ok {
			for _, c := range containers {
				if container, ok := c.(map[string]interface{}); ok {
					result = append(result, container)
				}
			}
		}
	}
	return result
}

func matchesAny(value string, patterns []string) bool {
	for _, pattern := range patterns {
		if matchPattern(value, pattern) {
			return true
		}
	}
	return false
}

func matchPattern(value, pattern string) bool {
	// Simple wildcard matching
	if pattern == "*" {
		return true
	}
	if strings.HasPrefix(pattern, "*") && strings.HasSuffix(pattern, "*") {
		return strings.Contains(value, pattern[1:len(pattern)-1])
	}
	if strings.HasPrefix(pattern, "*") {
		return strings.HasSuffix(value, pattern[1:])
	}
	if strings.HasSuffix(pattern, "*") {
		return strings.HasPrefix(value, pattern[:len(pattern)-1])
	}
	return value == pattern
}
