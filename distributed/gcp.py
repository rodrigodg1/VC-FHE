"""Generate infrastructure as code without contacting Google Cloud."""
from pathlib import Path
import json
from topology import digest, hosts, inventory, registry_region

def image_repository(config):
    repositories=set()
    for image in config['images'].values():
        if not image:continue
        parts=image.split('/',3)
        if len(parts)!=4:raise ValueError('image repository path is incomplete')
        registry,project,repository,_=parts
        if project!=config['project_id'] or registry!=registry_region(config)+'-docker.pkg.dev':
            raise ValueError('image repository must match the configured project and registry region')
        repositories.add(repository)
    if len(repositories)>1:raise ValueError('campaign and Besu images must share the source-bound repository')
    return next(iter(repositories)) if repositories else config['campaign']

def terraform(config):
    campaign = config["campaign"]
    physical = hosts(config)
    resource = {}
    def add(kind, name, value):
        resource.setdefault(kind, {})[name] = value
    ref = lambda kind, name, field="id": "${"+kind+"."+name+"."+field+"}"
    add("google_compute_network", "experiment", {"name": campaign, "auto_create_subnetworks": False,
                                                 "routing_mode": "GLOBAL"})
    for i, region in enumerate(config["regions"], 1):
        key = f"region{i}"
        add("google_compute_subnetwork", key, {"name": f"{campaign}-r{i}", "region": region["name"],
            "network": ref("google_compute_network", "experiment"), "ip_cidr_range": region["cidr"],
            "private_ip_google_access": True})
        add("google_compute_router", key, {"name": f"{campaign}-r{i}", "region": region["name"],
            "network": ref("google_compute_network", "experiment")})
        add("google_compute_router_nat", key, {"name": f"{campaign}-nat{i}", "region": region["name"],
            "router": ref("google_compute_router", key, "name"), "nat_ip_allocate_option": "AUTO_ONLY",
            "source_subnetwork_ip_ranges_to_nat": "LIST_OF_SUBNETWORKS",
            "subnetwork": [{"name": ref("google_compute_subnetwork", key), "source_ip_ranges_to_nat": ["ALL_IP_RANGES"]}]})
    add("google_artifact_registry_repository", "images", {"location": registry_region(config),
        "repository_id": image_repository(config), "description": "VC-FHE experiment images, no private keys", "format": "DOCKER"})
    host_keys = {}
    for host in physical:
        key = host["id"].replace("-", "_")
        host_keys[host["id"]] = key
        region_key = "region"+str(next(i for i,r in enumerate(config["regions"],1) if r["name"] == host["region"]))
        add("google_service_account", key, {"account_id": f"vcfhe-{digest(config)[:8]}-{host['id']}", "display_name": host["name"]})
        add("google_artifact_registry_repository_iam_member", key, {
            "location": registry_region(config), "repository": ref("google_artifact_registry_repository", "images", "name"),
            "role": "roles/artifactregistry.reader",
            "member": "serviceAccount:"+ref("google_service_account", key, "email")})
        add("google_compute_disk", key, {"name": host["name"]+"-state", "zone": host["zone"],
            "type": "pd-balanced", "size": config["state_disk_gib"],
            "labels": {"experiment": campaign, "purpose": "retain-protocol-state"},
            "lifecycle": {"prevent_destroy": True}})
        add("google_compute_instance", key, {"name": host["name"], "zone": host["zone"],
            "machine_type": host["machine_type"], "min_cpu_platform": config["min_cpu_platform"],
            "deletion_protection": True, "allow_stopping_for_update": False,
            "scheduling":{"automatic_restart":False,"instance_termination_action":"STOP",
                          "max_run_duration":{"seconds":config.get('maximum_vm_runtime_seconds',50400)}},
            "labels": {"experiment": campaign, "profile": "test", "administration": "common"},
            "boot_disk": {"initialize_params": {"image": "${data.google_compute_image.debian.self_link}",
                           "size": config["boot_disk_gib"], "type": "pd-balanced"}},
            "attached_disk": [{"source": ref("google_compute_disk", key), "device_name": "vcfhe-state"}],
            "network_interface": [{"subnetwork": ref("google_compute_subnetwork", region_key),
                                   "network_ip": host["private_ip"]}],
            "service_account": {"email": ref("google_service_account", key, "email"),
                                "scopes": ["cloud-platform"]},
            "metadata": {"enable-oslogin": "TRUE", "block-project-ssh-keys": "TRUE",
                         "vcfhe-campaign": campaign, "vcfhe-host": host["id"]},
            "metadata_startup_script": "${file(\"bootstrap.sh\")}",
            "shielded_instance_config": {"enable_secure_boot": True, "enable_vtpm": True,
                                         "enable_integrity_monitoring": True},
            "depends_on": ["google_compute_router_nat."+region_key]})
        principal=config.get('operator_principal')
        if config.get('primary_first_provision',False):
            if not principal:raise ValueError('primary-first provisioning requires a scoped operator principal')
            resource['google_compute_instance'][key]['depends_on'].append('google_service_account_iam_member.'+key)
        if principal:
            add('google_compute_instance_iam_member',key,{
                'project':config['project_id'],'zone':host['zone'],
                'instance_name':ref('google_compute_instance',key,'name'),
                'role':'roles/compute.osAdminLogin','member':principal})
            add('google_iap_tunnel_instance_iam_member',key,{
                'project':config['project_id'],'zone':host['zone'],
                'instance':ref('google_compute_instance',key,'name'),
                'role':'roles/iap.tunnelResourceAccessor','member':principal})
            add('google_service_account_iam_member',key,{
                'service_account_id':ref('google_service_account',key),
                'role':'roles/iam.serviceAccountUser','member':principal})
    accounts = lambda ids: [ref("google_service_account", host_keys[i], "email") for i in sorted(set(ids))]
    nodes = inventory(config)
    role_hosts = lambda roles: [n["host"] for n in nodes if n["role"] in roles]
    def firewall(name, targets, sources, protocol, ports):
        source_accounts, target_accounts = accounts(sources), accounts(targets)
        for s in range(0,len(source_accounts),10):
            for t in range(0,len(target_accounts),10):
                suffix = f"-{s//10}-{t//10}"
                rule = {"name": campaign+"-"+name+suffix, "network": ref("google_compute_network", "experiment"),
                        "direction": "INGRESS", "target_service_accounts": target_accounts[t:t+10],
                        "source_service_accounts": source_accounts[s:s+10], "allow": [{"protocol": protocol, "ports": ports}]}
                add("google_compute_firewall", (name+suffix).replace("-", "_"), rule)
    all_hosts = [h["id"] for h in physical]
    validators = role_hosts(["validator"])
    kms = role_hosts(["kms"])
    firewall("qbft-tcp", validators, validators, "tcp", ["30303"])
    firewall("qbft-udp", validators, validators, "udp", ["30303"])
    firewall("chain-read", validators, all_hosts, "tcp", ["8545"])
    firewall("kms-mpc", kms, kms, "tcp", ["50001"])
    firewall("kms-client", kms, role_hosts(["coordinator", "recipient"]), "tcp", ["50100"])
    firewall("kms-public", kms, all_hosts, "tcp", ["8080"])
    # Authenticated role endpoints use distinct ports on shared hosts.
    firewall("role-rpc", all_hosts, all_hosts, "tcp", ["9443-9450"])
    for index in range(0,len(all_hosts),10):
        add("google_compute_firewall", f"iap{index}", {"name": campaign+f"-iap{index}", "network": ref("google_compute_network", "experiment"),
            "source_ranges": ["35.235.240.0/20"], "target_service_accounts": accounts(all_hosts[index:index+10]),
            "allow": [{"protocol": "tcp", "ports": ["22"]}]})
    return {"terraform": {"required_version": ">= 1.9.8, < 2.0.0",
                           "required_providers": {"google": {"source": "hashicorp/google", "version": "6.50.0"}}},
            "provider": {"google": {"project": "${var.project_id}"}},
            "variable": {"project_id": {"type": "string", "description": "Dedicated, billing-enabled experiment project"}},
            "data": {"google_compute_image": {"debian": {"family": "debian-12", "project": "debian-cloud"}}},
            "resource": resource,
            "output": {"instances": {"value": {h["id"]: {"name": ref("google_compute_instance", host_keys[h["id"]], "name"),
                                                            "zone": h["zone"], "private_ip": h["private_ip"]} for h in physical}},
                       "resolved_boot_image": {"value": "${data.google_compute_image.debian.self_link}"}}}

def write(config, destination):
    destination = Path(destination)
    destination.mkdir()
    (destination/"main.tf.json").write_text(json.dumps(terraform(config), indent=2)+"\n")
    (destination/"terraform.tfvars.json").write_text(json.dumps({"project_id": config["project_id"]}, indent=2)+"\n")
    (destination/"bootstrap.sh").write_text((Path(__file__).parent/"bootstrap.sh").read_text())
    lock = Path(__file__).parent/"terraform.lock.hcl"
    if lock.is_file(): (destination/".terraform.lock.hcl").write_bytes(lock.read_bytes())
