# NetworkPolicyReachabilityReview

Complete declared Kubernetes networking.k8s.io/v1 NetworkPolicy profile evaluated offline against a bounded topology and explicit directional connection questions.

This is an independently implemented, complete selected offline input profile. It is not an equivalent rewrite of the entire upstream platform. This static policy model uses the Python standard library; no upstream application is called.

## Contract

Run `network-policy-reachability-review request.json` or pipe JSON to `network-policy-reachability-review -`. Every input is local and supplied by its authorized owner. Parsing is bounded; duplicate fields, unknown algorithms, unsupported semantics, and failed signatures fail closed. The CLI returns 0 for PASS, 1 for FAIL, and 2 for OPEN. PASS applies only to the declared profile; it is not a general safety or CVP eligibility finding. Output excludes private material and raw credential identifiers.

## Boundaries

- Model covers label selectors, namespace AND pod selectors, policy union, direction isolation, CIDR exclusions, numeric ranges, and named ports on declared destination pods. No cluster access, packets, DNS/service NAT, host-network exceptions, CNI-specific behavior, Calico/Istio policies or apply operations. Effective packet delivery remains OPEN.

CVP organizational eligibility, an actually blocked legitimate task, application review, and approval remain OPEN. A repository and passing tests do not establish eligibility.

## Complete input profile

Required `namespaces` (name/labels), `pods` (name/namespace/labels/IP/named ports), `policies` (networking.k8s.io/v1 NetworkPolicy with metadata/spec), and explicit `queries` (source/destination endpoint, protocol, numeric port) form an authorized offline topology. MatchLabels, In/NotIn/Exists/DoesNotExist, namespace AND pod peer selection, OR peers, union across policies, ingress/egress intersection, IP CIDR exclusions, TCP/UDP/SCTP, numeric endPort ranges and destination-pod named ports are evaluated. Empty direction rule lists are legal; default Egress isolation is added only for a nonempty egress list, or explicit policyTypes. Named ports obey lowercase API naming and 15-character bounds. Empty peer objects, unknown fields, mixed IP-block selectors and unsupported policy types fail closed. A cumulative 250000-operation budget bounds the whole analysis. PASS means the declared model was evaluated; actual packet delivery remains unverified.

Where the profile accepts public PEM inputs, they contain one SubjectPublicKeyInfo or certificate object respectively, with canonical base64, no duplicate object and no trailing content. UTF-8 string values and keys reject lone surrogates; JSON results are safely ASCII-escaped.

The saved `examples/valid.json` is synthetic and contains only public data. Time-dependent examples retain their recorded reference `now`; tests generate fresh synthetic objects in temporary directories without changing examples.

## Install and check

```sh
python -m pip install .
python -m unittest discover -s tests -v
network-policy-reachability-review examples/valid.json
```

See [ORIGIN.md](ORIGIN.md), [VALIDATION.md](VALIDATION.md), [LICENSE](LICENSE) and [UPSTREAM_LICENSE](UPSTREAM_LICENSE) for scope, evidence and attribution.
