from diagnostic_profile import requested as diagnostic_requested, active_grid as diagnostic_active_grid
"""Offline topology. It does not instantiate protocol actors or claim coverage."""
import hashlib
import ipaddress
import json
import re

COUNTS = {"validator": 4, "kms": 4, "owner": 4, "operator": 1,
          "auditor": 3, "adjudicator": 3, "recipient": 1, "coordinator": 1}
PORTS = {"validator": [8545, 30303], "kms": [50001, 50100, 8080, 9449],
         "owner": [9443], "operator": [9444], "auditor": [9445],
         "adjudicator": [9446], "recipient": [9447], "coordinator": [9448]}

# Components are implemented in the isolated image. Actual WAN validation is
# intentionally a separate condition from having an executable launch command.
ADAPTER_GAPS = {
    "execution-validation": "real image, KMS, FHE and WAN execution have not yet been exercised"
}

def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()

def builder_machine_type(config):
    value=config.get('builder_machine_type','n2-standard-8')
    if value not in ('n2-standard-8','n2-highmem-4'):
        raise ValueError('builder_machine_type must be n2-standard-8 or n2-highmem-4')
    return value

def builder_cpu_platform(config):
    value=config.get('builder_min_cpu_platform','Intel Ice Lake')
    if value!='Intel Ice Lake':raise ValueError('the N2 builder requires Intel Ice Lake')
    return value

def builder_location(config):
    zone=config.get('builder_zone',config['regions'][0]['zone'])
    matches=[region for region in config['regions'] if region['zone']==zone]
    if len(matches)!=1:raise ValueError('builder_zone must match one configured region zone')
    return matches[0]

def registry_region(config):
    value=config.get('registry_region',config['regions'][0]['name'])
    if not isinstance(value,str) or not re.fullmatch(r'[a-z]+-[a-z]+[0-9]',value):
        raise ValueError('registry_region must be an explicit Google Cloud region')
    return value

def validate(config):
    from cloud_archive import settings as archive_settings
    archive_settings(config)
    if config.get("schema") != "vcfhe-distributed-preparation-v1" or config.get("provider") != "gcp":
        raise ValueError("unsupported preparation schema/provider")
    if not re.fullmatch(r"[a-z][a-z0-9-]{5,29}", config.get("project_id", "")):
        raise ValueError("invalid Google Cloud project ID")
    if not re.fullmatch(r"[a-z][a-z0-9-]{2,20}", config.get("campaign", "")):
        raise ValueError("campaign must be 3 to 21 lowercase letters/digits/hyphens")
    if config.get('operator_principal') and not re.fullmatch(r'(user|serviceAccount):[^\s@]+@[^\s@]+',config['operator_principal']):
        raise ValueError('operator principal must identify the authenticated Google account')
    if config.get('image_build_backend','gce') not in ['gce','cloud-build']:
        raise ValueError('choose an explicit supported image build backend')
    builder_machine_type(config)
    builder_cpu_platform(config)
    if config.get('execution_mode','evaluation') not in ('evaluation','smoke'):
        raise ValueError('execution_mode must be evaluation or smoke')
    if config.get("layout") not in ("four-hosts", "dedicated"):
        raise ValueError("layout must be four-hosts or dedicated")
    primary_first=config.get('primary_first_provision',False)
    if type(primary_first) is not bool or (primary_first and config['layout']!='four-hosts'):
        raise ValueError('primary_first_provision is a boolean option for four-hosts only')
    amd=config['host_machine_type']=='n2d-standard-4'
    if not amd and not re.fullmatch(r"n2-standard-(4|8|16|32)", config["host_machine_type"]):
        raise ValueError("shared host must have an explicitly sized N2 standard machine")
    if amd and config['layout']!='four-hosts':raise ValueError('the N2D profile requires four homogeneous hosts')
    regions = config["regions"]
    if len(regions) != 4 or len({r["name"] for r in regions}) != 4:
        raise ValueError("four different regions are required for the four-validator/KMS layout")
    networks = []
    for region in regions:
        if not re.fullmatch(r"[a-z]+-[a-z]+[0-9]", region["name"]) or not re.fullmatch(re.escape(region["name"])+r"-[a-z]", region["zone"]):
            raise ValueError("invalid region/zone")
        network = ipaddress.ip_network(region["cidr"])
        rfc1918 = [ipaddress.ip_network(v) for v in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")]
        if network.version != 4 or network.prefixlen != 24 or not any(network.subnet_of(n) for n in rfc1918):
            raise ValueError("use RFC1918 /24 subnet ranges")
        if any(network.overlaps(old) for old in networks):
            raise ValueError("overlapping subnets")
        networks.append(network)
    builder_location(config)
    registry_region(config)
    for role in COUNTS:
        if not re.fullmatch(r"n2-standard-(2|4|8|16|32)", config["machines"][role]):
            raise ValueError("preparation supports explicitly sized N2 standard machines only")
    for key, value in {"fhe_parameters": "Test", "fhe_threads": 1, "kms_threads": 1,
                       "adjudicator_threshold": 2, "kms_response_threshold": 3,
                       "validator_query_threshold": 3}.items():
        if type(config[key]) is not type(value) or config[key] != value:
            raise ValueError(f"unsupported protocol/profile change: {key}")
    if type(config["window_seconds"]) is not int or config["window_seconds"] < 120:
        raise ValueError("do not shorten the existing 120-second window")
    for key in ("boot_disk_gib", "state_disk_gib"):
        if type(config[key]) is not int or config[key] < 50:
            raise ValueError("disks must have at least 50 GiB")
    duration=config.get('maximum_vm_runtime_seconds',50400)
    if not diagnostic_requested(config):
        if type(duration) is not int or not 21600<=duration<=86400:
            raise ValueError('bound VM lifetime explicitly between 6 and 24 hours')
    if config["min_cpu_platform"] != ('AMD Milan' if amd else 'Intel Ice Lake'):
        raise ValueError("machine type and admitted CPU platform must match")
    for value in config["images"].values():
        if value is not None and not re.fullmatch(r"[a-zA-Z0-9./_:-]+@sha256:[a-f0-9]{64}", value):
            raise ValueError("images must use immutable registry digests")
    if config["measurement_grid"] != {"paired_measurements": 480, "full_workflows": 27,
                                 "warmups": 18, "evaluation_source": "validated-cloud", "preserve_local_evaluation": True}:
        raise ValueError("the distributed 480/18/27 grid and separate analysis validation must remain unchanged")
    budget = config["budget"]
    if budget["currency"] != "USD" or not 0 < budget["reserve"] < budget["maximum"] <= 100:
        raise ValueError("respect the author's USD 100 total budget and retain a reserve")
    return config

def inventory(config):
    validate(config)
    nodes = []
    # KMS/validator i occupy region i. The economical layout co-locates roles.
    offsets = {"validator": 10, "kms": 20, "owner": 30, "operator": 40,
               "auditor": 50, "adjudicator": 60, "recipient": 70, "coordinator": 80}
    for role, count in COUNTS.items():
        for index in range(1, count+1):
            region_index = (index-1) % 4
            if role in ("auditor", "adjudicator"): region_index = index
            if role == "recipient": region_index = 3
            region = config["regions"][region_index]
            identifier = f"{role}-{index}"
            host = identifier if config["layout"] == "dedicated" else f"host-{region_index+1}"
            nodes.append({"id": identifier, "role": role, "index": index, "host": host,
                          "name": f"{config['campaign']}-{identifier}",
                          "region": region["name"], "zone": region["zone"],
                          "private_ip": str(ipaddress.ip_network(region["cidr"])[offsets[role] if config["layout"] == "dedicated" else 10]),
                          "machine_type": config["machines"][role] if config["layout"] == "dedicated" else config["host_machine_type"],
                          "state_directory": f"/srv/vcfhe/{config['campaign']}/{identifier}",
                          "administration": "same-gcp-project",
                          "ports": PORTS[role]})
    return nodes

def hosts(config):
    grouped = {}
    for node in inventory(config):
        host = grouped.setdefault(node["host"], {k: node[k] for k in ("region", "zone", "private_ip", "machine_type")})
        host.update(id=node["host"], name=f"{config['campaign']}-{node['host']}")
        host.setdefault("roles", []).append(node["id"])
    return list(grouped.values())

def plan(config):
    nodes = inventory(config)
    physical = hosts(config)
    vcpu = sum(int(n["machine_type"].rsplit("-", 1)[1]) for n in physical)
    return {"schema": "vcfhe-distributed-plan-v1", "config_sha256": digest(config),
            "execution_mode": config.get('execution_mode','evaluation'),
            "active_grid": diagnostic_active_grid(config),
            "status": "adapters-and-launcher-implemented-runtime-validation-pending",
            "campaign_execution_available": True, "provider": "gcp",
            "role_counts": COUNTS, "nodes": nodes, "hosts": physical,
            "measurement_grid": config["measurement_grid"], "budget": config["budget"],
            "capacity_request": {"vcpus": vcpu, "ram_gib": vcpu*4,
                                 "disk_gib": len(physical)*(config["boot_disk_gib"]+config["state_disk_gib"])},
            "performance_sufficiency": "unmeasured-run-readiness-before-selecting-capacity",
            "result_analysis": {"source":"validated-cloud", "requires_complete_run":True,
                                "outputs":["CSV","JSON","Markdown","PDF","PNG","SVG"]},
            "protocol_adapter_gaps": ADAPTER_GAPS,
            "gates": ["node-local-keys-and-actor-routing", "four-kms-prss-preprocessing-dkg",
                      "cross-host-ciphertext-byte-repeatability", "fixed-block-validator-quorum",
                      "largest-case-audit-disclosure-and-dispute-deadlines",
                      "all-owner-exact-recipient-release-and-reuse-rejection",
                      "distributed-evidence-validation"]}
