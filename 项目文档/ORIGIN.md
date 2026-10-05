# Origin and implementation scope

The new independent implementation is authored by **dhtfish98** (package version **0.1.4**). Upstream works retain their original attribution and license notices in this document and `UPSTREAM_LICENSE`.

NetworkPolicyReachabilityReview independently implements this selected scope: Complete declared Kubernetes networking.k8s.io/v1 NetworkPolicy profile evaluated offline against a bounded topology and explicit directional connection questions.

The research source is [np-guard/network-config-analyzer](https://github.com/np-guard/network-config-analyzer) at fixed commit `1b9bb91dbed20d172396e28e77a32d27f0a4dc50`. Source archive SHA-256: `1d4b1f49930cc899c2e5efdefaed513be25160c7115aa831e19cdeefe5106c12`. Its license is Apache-2.0; the exact source license notice is retained as `UPSTREAM_LICENSE`. The new application code and documentation are licensed under MIT (`LICENSE`). The upstream application is neither imported nor executed by the production package. No upstream application source is bundled in the production package.

## Selected source evidence

- [nca/Parsers/K8sPolicyYamlParser.py](https://github.com/np-guard/network-config-analyzer/blob/1b9bb91dbed20d172396e28e77a32d27f0a4dc50/nca/Parsers/K8sPolicyYamlParser.py) — SHA-256 `fe1cde3b331875a3809bf7fe813282949d014189834af19d29dc70c35071acb2`.
- [nca/Resources/PolicyResources/K8sNetworkPolicy.py](https://github.com/np-guard/network-config-analyzer/blob/1b9bb91dbed20d172396e28e77a32d27f0a4dc50/nca/Resources/PolicyResources/K8sNetworkPolicy.py) — SHA-256 `b77a0344fd998436d6adc44645a7588954d772a372f1f300b2d8f2a39f203c1f`.

Full selected file contents and their inventory are retained in the research archive identified by `provenance/SOURCE_REVIEW.json`; those fixed links and hashes allow independent reconstruction. Review focused on NetworkPolicy selector, direction and peer/port semantics, official Kubernetes Egress defaulting overrides source key-presence shortcut. This record does not assert a whole-platform source audit, original authorship of standards, or equivalence to all upstream behavior.

## Concrete new work

The new implementation owns bounded local input parsing, strict supported-field validation, the complete selected application logic, explicit trust input binding, fail-closed unsupported semantics, privacy-limited result fields, and a three-state CLI contract. Mature cryptographic primitives are reused rather than reimplemented. New scope and tests are substantive application work; a source SHA, rename, mirror or wrapper is not claimed as original contribution.

Required `namespaces` (name/labels), `pods` (name/namespace/labels/IP/named ports), `policies` (networking.k8s.io/v1 NetworkPolicy with metadata/spec), and explicit `queries` (source/destination endpoint, protocol, numeric port) form an authorized offline topology. MatchLabels, In/NotIn/Exists/DoesNotExist, namespace AND pod peer selection, OR peers, union across policies, ingress/egress intersection, IP CIDR exclusions, TCP/UDP/SCTP, numeric endPort ranges and destination-pod named ports are evaluated. Empty direction rule lists are legal; default Egress isolation is added only for a nonempty egress list, or explicit policyTypes. Named ports obey lowercase API naming and 15-character bounds. Empty peer objects, unknown fields, mixed IP-block selectors and unsupported policy types fail closed. A cumulative 250000-operation budget bounds the whole analysis. PASS means the declared model was evaluated; actual packet delivery remains unverified.

## Defensive use and application evidence

Inputs must belong to the authorized reviewer. Runtime performs no fetch, sample execution, private-key processing, key export, signing, remote modification or outbound communication. CVP organizational eligibility, evidence of a legitimate blocked task, application review and program acceptance remain OPEN. These local results alone do not establish them.

## Re-audited supported semantics

Present-null podSelector or namespaceSelector peer fields are rejected by this selected profile. An empty selector object remains distinct and supported; omitted peer lists retain their existing all-peer semantics. Invalid IP/CIDR API errors use fixed messages and never echo the supplied address. This rejects unsupported null semantics instead of inferring Kubernetes pointer defaulting. See [the Kubernetes NetworkPolicy API](https://kubernetes.io/docs/reference/kubernetes-api/networking/network-policy-v1/).


Label keys and selector expression keys use the Kubernetes qualified-name grammar: optional lowercase DNS-subdomain prefix up to 253 characters, a slash, and an ASCII alphanumeric/`-_.` name of 1 through 63 characters. Label values and expression values are empty or use that ASCII grammar up to 63 characters. Namespace object names and references use a lowercase DNS label up to 63 characters; Pod and NetworkPolicy names/references use the Kubernetes DNS-subdomain grammar up to 253 characters. The latter whole-name limit follows the API validator and does not add a per-segment 63-character limit. This checks the supported input fields rather than complete API-server admission. References: [Kubernetes v0.35.0 label validation](https://github.com/kubernetes/apimachinery/blob/v0.35.0/pkg/api/validate/content/kube.go), [name validation](https://github.com/kubernetes/apimachinery/blob/v0.35.0/pkg/api/validation/generic.go), and [v1.35.0 NetworkPolicy validation](https://github.com/kubernetes/kubernetes/blob/v1.35.0/pkg/apis/networking/validation/validation.go).
