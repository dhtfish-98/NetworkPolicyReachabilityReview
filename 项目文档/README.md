> 目录已整理：文档在「项目文档」，构建、缓存与暂存输入在「Build」。从仓库根目录运行 `python3 构建.py --build`；如需使用本文原有源码命令，先运行 `python3 构建.py --stage --ci`，再进入 `Build/源码`。暂存会恢复原输入路径。现有版本和历史验证记录按各自提交理解。

# NetworkPolicyReachabilityReview

New implementation author: **dhtfish98**. Package version: **0.1.4**.

Complete declared Kubernetes networking.k8s.io/v1 NetworkPolicy profile evaluated offline against a bounded topology and explicit directional connection questions.

This is an independently implemented, complete selected offline input profile. It is not an equivalent rewrite of the entire upstream platform. This static policy model uses the Python standard library; no upstream application is called.

## Contract

Run `network-policy-reachability-review request.json` or pipe JSON to `network-policy-reachability-review -`. Every input is local and supplied by its authorized owner. Parsing is bounded; duplicate fields, unknown algorithms, unsupported semantics, and failed signatures fail closed. The CLI returns 0 for PASS, 1 for FAIL, and 2 for OPEN. PASS applies only to the declared profile; it is not a general safety or CVP eligibility finding. Output excludes private material and raw credential identifiers.

## Boundaries

- Model covers label selectors, namespace AND pod selectors, policy union, direction isolation, CIDR exclusions, numeric ranges, and named ports on declared destination pods. No cluster access, packets, DNS/service NAT, host-network exceptions, CNI-specific behavior, Calico/Istio policies or apply operations. Effective packet delivery remains OPEN.

CVP organizational eligibility, an actually blocked legitimate task, application review, and approval remain OPEN. A repository and passing tests do not establish eligibility.

## Complete input profile

Required `namespaces` (name/labels), `pods` (name/namespace/labels/IP/named ports), `policies` (networking.k8s.io/v1 NetworkPolicy with metadata/spec), and explicit `queries` (source/destination endpoint, protocol, numeric port) form an authorized offline topology. MatchLabels, In/NotIn/Exists/DoesNotExist, namespace AND pod peer selection, OR peers, union across policies, ingress/egress intersection, IP CIDR exclusions, TCP/UDP/SCTP, numeric endPort ranges and destination-pod named ports are evaluated. Empty direction rule lists are legal; default Egress isolation is added only for a nonempty egress list, or explicit policyTypes. Named ports obey lowercase API naming and 15-character bounds. Empty peer objects, unknown fields, mixed IP-block selectors and unsupported policy types fail closed. A cumulative 250000-operation budget bounds the whole analysis. PASS means the declared model was evaluated; actual packet delivery remains unverified.

Where the profile accepts public PEM inputs, they contain one SubjectPublicKeyInfo or certificate object respectively, with canonical base64, no duplicate object and no trailing content. UTF-8 string values and keys reject lone surrogates; parsed floating-point overflow is rejected as nonfinite; JSON results are safely ASCII-escaped.

The saved `examples/valid.json` is synthetic and contains only public data. Time-dependent examples retain their recorded reference `now`; tests generate fresh synthetic objects in temporary directories without changing examples.

## Install and check

```sh
python -m pip install .
python -m unittest discover -s tests -v
network-policy-reachability-review examples/valid.json
```

See [ORIGIN.md](<ORIGIN.md>), [VALIDATION.md](<VALIDATION.md>), [LICENSE](<LICENSE>) and [UPSTREAM_LICENSE](<UPSTREAM_LICENSE>) for scope, evidence and attribution.

## File input platform contract

Regular-file input and file-based CLI requests require usable `os.O_NOFOLLOW` and `os.O_NONBLOCK` capabilities. Missing capabilities produce a controlled incomplete FAIL; there is no fallback that follows the final-component symlink or blocks on a FIFO. macOS and Linux CI have been exercised. Native Windows file-input behavior remains unverified.

## Re-audited input semantics

Present-null podSelector or namespaceSelector peer fields are rejected by this selected profile. An empty selector object remains distinct and supported; omitted peer lists retain their existing all-peer semantics. Invalid IP/CIDR API errors use fixed messages and never echo the supplied address. This rejects unsupported null semantics instead of inferring Kubernetes pointer defaulting. See [the Kubernetes NetworkPolicy API](https://kubernetes.io/docs/reference/kubernetes-api/networking/network-policy-v1/).


Label keys and selector expression keys use the Kubernetes qualified-name grammar: optional lowercase DNS-subdomain prefix up to 253 characters, a slash, and an ASCII alphanumeric/`-_.` name of 1 through 63 characters. Label values and expression values are empty or use that ASCII grammar up to 63 characters. Namespace object names and references use a lowercase DNS label up to 63 characters; Pod and NetworkPolicy names/references use the Kubernetes DNS-subdomain grammar up to 253 characters. The latter whole-name limit follows the API validator and does not add a per-segment 63-character limit. This checks the supported input fields rather than complete API-server admission. References: [Kubernetes v0.35.0 label validation](https://github.com/kubernetes/apimachinery/blob/v0.35.0/pkg/api/validate/content/kube.go), [name validation](https://github.com/kubernetes/apimachinery/blob/v0.35.0/pkg/api/validation/generic.go), and [v1.35.0 NetworkPolicy validation](https://github.com/kubernetes/kubernetes/blob/v1.35.0/pkg/apis/networking/validation/validation.go).
