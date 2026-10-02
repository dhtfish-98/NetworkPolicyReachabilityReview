from .common import *
import ipaddress,re

def labels(v):
    obj(v);need(len(v)<=128,"label count limit")
    for k,val in v.items():string(k,253);string(val,253)
    return v
def selector(s,l,budget=None):
    fields(s,[],['matchLabels','matchExpressions']);m=labels(s.get('matchLabels',{}));ok=all(l.get(k)==v for k,v in m.items())
    if budget:budget(1+len(m))
    for e in seq(s.get('matchExpressions',[]),128):
        if budget:budget(1)
        fields(e,['key','operator'],['values']);k=string(e['key'],253);op=e['operator'];vals=seq(e.get('values',[]),128)
        need(all(isinstance(x,str) for x in vals) and len(set(vals))==len(vals),"invalid selector values")
        if op in ('In','NotIn'):need(vals,"selector set cannot be empty")
        elif op in ('Exists','DoesNotExist'):need(not vals,"existence selector cannot have values")
        else:raise ReviewError("unsupported selector operator")
        ok=ok and ({'In':k in l and l[k] in vals,'NotIn':k not in l or l[k] not in vals,'Exists':k in l,'DoesNotExist':k not in l}[op])
    return ok
def protocol(v):need(v in ('TCP','UDP','SCTP'),"unsupported protocol");return v
def portname(v):
    string(v,15);need(re.fullmatch(r'[a-z0-9]([-a-z0-9]*[a-z0-9])?',v) is not None and re.search('[a-z]',v) is not None,"invalid Kubernetes named port");return v

def audit(d):
    fields(d,['namespaces','pods','policies','queries'])
    ns={};pods={};policies=[];operations=0
    def spend(n=1):
        nonlocal operations
        operations+=n;need(operations<=250000,"analysis operation budget exceeded; result incomplete")
    def sel(s,l):return selector(s,l,spend)
    for n in seq(d['namespaces'],128):
        fields(n,['name','labels']);name=string(n['name'],253);need(name and name not in ns,"empty or duplicate namespace");ns[name]=labels(n['labels'])
    for p in seq(d['pods'],1024):
        fields(p,['name','namespace','labels','ip','ports']);name=string(p['name'],253);namespace=string(p['namespace'],253);need(name and namespace in ns,"pod namespace unavailable")
        key=(namespace,name);need(key not in pods,"duplicate pod identity");labels(p['labels']);ipaddress.ip_address(p['ip']);named=set()
        for port in seq(p['ports'],128):
            fields(port,['name','port','protocol']);pn=portname(port['name']);proto=protocol(port['protocol']);integer(port['port'],1,65535);need(pn and (pn,proto) not in named,"duplicate or empty named port");named.add((pn,proto))
        pods[key]=p
    def endpoint(e):
        fields(e,[],['namespace','pod','external_ip'])
        if 'external_ip' in e:need(set(e)=={'external_ip'},"mixed endpoint types");return {'ip':str(ipaddress.ip_address(e['external_ip'])),'external':True}
        fields(e,['namespace','pod']);key=(string(e['namespace'],253),string(e['pod'],253));need(key in pods,"query pod absent");return pods[key]
    def peer(peer,remote,namespace):
        spend();need(peer,"empty policy peer unsupported; use an omitted peer list for all peers")
        fields(peer,[],['podSelector','namespaceSelector','ipBlock'])
        if 'ipBlock' in peer:
            need(len(peer)==1,"ipBlock cannot mix with selectors");block=peer['ipBlock'];fields(block,['cidr'],['except']);network=ipaddress.ip_network(block['cidr'],strict=True);excludes=[]
            for x in seq(block.get('except',[]),128):
                excluded=ipaddress.ip_network(x,strict=True);need(excluded.version==network.version and excluded.subnet_of(network),"invalid CIDR exclusion");excludes.append(excluded)
            ip=ipaddress.ip_address(remote['ip']);return ip in network and not any(ip in x for x in excludes)
        nsselector=peer.get('namespaceSelector');podselector=peer.get('podSelector')
        # Validate selectors even when the queried peer is external.
        if nsselector is not None:sel(nsselector,{})
        if podselector is not None:sel(podselector,{})
        if not peer:return True
        if remote.get('external'):return False
        nsok=sel(nsselector,ns[remote['namespace']]) if nsselector is not None else remote['namespace']==namespace
        podok=sel(podselector,remote['labels']) if podselector is not None else True
        return nsok and podok
    def portmatch(rule,query,destination):
        spend()
        fields(rule,[],['protocol','port','endPort']);proto=protocol(rule.get('protocol','TCP'));v=rule.get('port')
        if v is None:need('endPort' not in rule,"endPort requires numeric port");return proto==query['protocol']
        if isinstance(v,str):
            portname(v);need('endPort' not in rule,"invalid named port range")
            return not destination.get('external') and any(x['name']==v and x['protocol']==proto and x['port']==query['port'] for x in destination['ports']) and proto==query['protocol']
        number=integer(v,1,65535);end=integer(rule.get('endPort',number),number,65535);return proto==query['protocol'] and number<=query['port']<=end
    identities=set()
    dummy={'ip':'192.0.2.1','external':True};q={'protocol':'TCP','port':80}
    for p in seq(d['policies'],512):
        fields(p,['apiVersion','kind','metadata','spec']);need(p['apiVersion']=='networking.k8s.io/v1' and p['kind']=='NetworkPolicy',"unsupported policy API")
        fields(p['metadata'],['name','namespace']);pn=string(p['metadata']['name'],253);namespace=string(p['metadata']['namespace'],253);need(namespace in ns and (namespace,pn) not in identities,"missing namespace or duplicate policy");identities.add((namespace,pn))
        spec=p['spec'];fields(spec,['podSelector'],['policyTypes','ingress','egress']);sel(spec['podSelector'],{})
        types=spec.get('policyTypes',['Ingress']+(['Egress'] if len(seq(spec.get('egress',[]),256))>0 else []));seq(types,2);need(types and len(set(types))==len(types) and set(types)<={'Ingress','Egress'},"invalid policyTypes")
        for direction,peerfield in (('ingress','from'),('egress','to')):
            need(not spec.get(direction) or direction.title() in types,"rules supplied for an undeclared direction")
            for rule in seq(spec.get(direction,[]),256):
                fields(rule,[],[peerfield,'ports'])
                for x in seq(rule.get(peerfield,[]),128):peer(x,dummy,namespace)
                for x in seq(rule.get('ports',[]),128):portmatch(x,q,dummy)
        policies.append((namespace,spec,types))
    def allowed(local,remote,direction,query,destination):
        if local.get('external'):return True,False
        selected=[]
        for namespace,spec,types in policies:
            spend()
            if namespace==local['namespace'] and direction.title() in types and sel(spec['podSelector'],local['labels']):selected.append((namespace,spec))
        if not selected:return True,False
        peerfield='from' if direction=='ingress' else 'to'
        for namespace,spec in selected:
            for rule in spec.get(direction,[]):
                spend();peers=rule.get(peerfield,[]);ports=rule.get('ports',[])
                if (not peers or any(peer(x,remote,namespace) for x in peers)) and (not ports or any(portmatch(x,query,destination) for x in ports)):return True,True
        return False,True
    answers=[]
    for i,q in enumerate(seq(d['queries'],1024)):
        fields(q,['source','destination','protocol','port']);protocol(q['protocol']);integer(q['port'],1,65535);src=endpoint(q['source']);dst=endpoint(q['destination'])
        eg,ei=allowed(src,dst,'egress',q,dst);ing,ii=allowed(dst,src,'ingress',q,dst)
        answers.append({'query_index':i,'allowed_by_declared_policies':eg and ing,'ingress_allowed':ing,'egress_allowed':eg,'source_egress_isolated':ei,'destination_ingress_isolated':ii})
    return report(verified=False,answers=answers,actual_packet_delivery_verified=False,analysis_operations=operations)
