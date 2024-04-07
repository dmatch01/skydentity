# Example taken from https://github.com/IBM/ibm-cloud-sdk-common/blob/main/README.md#using-the-sdk,
# https://github.com/IBM/vpc-python-sdk and https://github.com/skypilot-org/skypilot.

import getopt
import os
import sys
from typing import Any, Dict
from uuid import uuid4
import yaml

import ibm_cloud_sdk_core
import ibm_vpc

CLUSTER_SECURITY_GROUP_NAME_DEFAULT = "skydentity-cluster-sg"
INSTANCE_NAME_DEFAULT = "skydentity-my-instance"
INSTANCE_PROFILE_NAME_DEFAULT = "bx2-2x8"
REGION_DEFAULT = "us-south"
REQUIRED_RULES = {
    "outbound_tcp_all":
    "selected security group is missing rule permitting outbound TCP access\n",
    "outbound_udp_all":
    "selected security group is missing rule permitting outbound UDP access\n",
    "inbound_tcp_sg":
    "selected security group is missing rule permitting inbound tcp traffic inside selected security group\n",
    "inbound_tcp_22":
    "selected security group is missing rule permitting inbound traffic to tcp port 22 required for ssh\n",
}
SUBNET_NAME_DEFAULT = "skydentity-subnet"
VOLUME_TIER_NAME_DEFAULT = "general-purpose"
VPC_NAME_DEFAULT = "skydentity-vpc"
ZONE_NAME_DEFAULT = "us-south-3"


def read_credential_file(creds_file_path):
    try:
        with open(os.path.expanduser(creds_file_path), 'r',
                  encoding='utf-8') as f:
            return yaml.safe_load(f)
    except FileNotFoundError:
        return False


def get_api_key(base_config):
    return base_config.get('iam_api_key')


def _get_authenticator(base_config):
    return ibm_cloud_sdk_core.authenticators.IAMAuthenticator(
        get_api_key(base_config))


def create_ibm_vpc_client(base_config):
    """Create an ibm vpc client.

    Sets the vpc client to a specific region.
    If none was specified 'us-south' is set internally.

    Args:
        kwargs: Keyword arguments.

    Returns:
        ibm vpc client
    """

    region = base_config.get("region")
    region = REGION_DEFAULT
    try:
        ibm_vpc_client = ibm_vpc.VpcV1(
            version='2022-06-30',
            authenticator=_get_authenticator(base_config))
        ibm_vpc_client.set_service_url(
            f'https://{region}.iaas.cloud.ibm.com/v1')
    except Exception:
        print(f"No registered API key found matching specified value")
        raise

    return ibm_vpc_client  # returns newly created client


def get_default_image(ibm_vpc_client) -> str:
    """Returns default image id, currently stock ubuntu 22-04.

        if user specified 'image_id' in ~/.ibm/credentials.yaml
            matching this 'region', returns it instead.
        """

    def _get_image_objects(ibm_vpc_client):
        images = []
        res = ibm_vpc_client.list_images().get_result()
        images.extend(res['images'])

        while res.get('next'):
            link_to_next = res['next']['href'].split('start=')[1].split(
                '&limit')[0]
            res = ibm_vpc_client.list_images(start=link_to_next).get_result()
            images.extend(res['images'])
        return images

    # returns default image: "ibm-ubuntu-22-04" with amd architecture
    return next((img for img in _get_image_objects(ibm_vpc_client) if
     img['name'].startswith('ibm-ubuntu-22-04') \
        and img['operating_system']['architecture'].startswith(
            'amd')))['id']


def create_vpc(ibm_vpc_client: ibm_vpc.VpcV1, base_config):
    # Set up parameter values
    address_prefix_management = 'auto'
    #address_prefix_management = 'manual'
    classic_access = False
    #Construct a dict representation of a ResourceGroupIdentityById model
    resource_group = {"id": base_config.get('resource_group_id')}

    def _create_subnet(ibm_vpc_client: ibm_vpc.VpcV1, vpc_id, zone_name,
                       resource_group_id):
        ipv4_cidr_block = None
        res = ibm_vpc_client.list_vpc_address_prefixes(vpc_id).get_result()

        # searching for the CIDR block (internal ip range) matching the
        # specified zone of a VPC (whose region has already been set)
        address_prefixes = res["address_prefixes"]
        ipv4_cidr_block = next(
            (address_prefix["cidr"] for address_prefix in address_prefixes
             if address_prefix["zone"]["name"] == zone_name),
            None,
        )
        if not ipv4_cidr_block:
            raise Exception("Failed to locate a cidr block "
                            f"Matching the zone name: {zone_name} to create "
                            "a subnet")

        subnet_prototype = {}
        subnet_prototype["zone"] = {"name": zone_name}
        subnet_prototype["ip_version"] = "ipv4"
        subnet_prototype["name"] = SUBNET_NAME_DEFAULT
        subnet_prototype["resource_group"] = {"id": resource_group_id}
        subnet_prototype["vpc"] = {"id": vpc_id}
        subnet_prototype["ipv4_cidr_block"] = ipv4_cidr_block

        subnet_data = ibm_vpc_client.create_subnet(
            subnet_prototype).get_result()
        return subnet_data

    def _create_public_gateway(ibm_vpc_client: ibm_vpc.VpcV1, vpc_id,
                               zone_name, subnet_data, resource_group_id):

        gateway_prototype = {}
        gateway_prototype["vpc"] = {"id": vpc_id}
        gateway_prototype["zone"] = {"name": zone_name}
        gateway_prototype["name"] = f"{subnet_data['name']}-gw"
        gateway_prototype["resource_group"] = {"id": resource_group_id}
        gateway_data = ibm_vpc_client.create_public_gateway(
            **gateway_prototype).get_result()
        gateway_id = gateway_data["id"]

        ibm_vpc_client.set_subnet_public_gateway(subnet_data["id"],
                                                 {"id": gateway_id})
        return gateway_id

    def _build_security_group_rule_prototype_model(missing_rule, sg_id=None):
        direction, protocol, port = missing_rule.split("_")
        remote = {"cidr_block": "0.0.0.0/0"}

        try:  # port number was specified
            port = int(port)
            port_min = port
            port_max = port
        except Exception:
            port_min = 1
            port_max = 65535

            # only valid if security group already exists
            if port == "sg":
                if not sg_id:
                    return None
                remote = {"id": sg_id}

        return {
            "direction": direction,
            "ip_version": "ipv4",
            "protocol": protocol,
            "remote": remote,
            "port_min": port_min,
            "port_max": port_max,
        }

    def _create_sg_rules(ibm_vpc_client: ibm_vpc.VpcV1, vpc_create_response):

        sg_id = vpc_create_response["default_security_group"]["id"]

        # update sg name
        ibm_vpc_client.update_security_group(
            sg_id,
            security_group_patch={"name": CLUSTER_SECURITY_GROUP_NAME_DEFAULT})

        # open private tcp traffic between VSIs within the security group
        sg_rule_prototype = _build_security_group_rule_prototype_model(
            "inbound_tcp_sg", sg_id=sg_id)
        ibm_vpc_client.create_security_group_rule(
            sg_id, sg_rule_prototype).get_result()

        # add all other required rules configured by the specific backend
        for rule in REQUIRED_RULES.keys():
            sg_rule_prototype = _build_security_group_rule_prototype_model(
                rule)
            if sg_rule_prototype:
                ibm_vpc_client.create_security_group_rule(
                    sg_id, sg_rule_prototype).get_result()

        return sg_id

    response = ibm_vpc_client.create_vpc(
        address_prefix_management=address_prefix_management,
        classic_access=classic_access,
        name=VPC_NAME_DEFAULT,
        resource_group=resource_group,
    ).get_result()
    subnet_data = _create_subnet(ibm_vpc_client, response["id"],
                                 ZONE_NAME_DEFAULT, resource_group.get('id'))
    _create_public_gateway(ibm_vpc_client, response["id"], ZONE_NAME_DEFAULT,
                           subnet_data, resource_group.get('id'))
    sg_id = _create_sg_rules(ibm_vpc_client, response)

    return {
        "vpc_id": response["id"],
        "subnet_id": subnet_data["id"],
        "security_group_id": sg_id,
    }


def create_instance(name, base_config, ibm_vpc_client: ibm_vpc.VpcV1,
                    vpc_config):
    """
    Creates a new VM instance with the specified name,
    based on the provided base_config configuration dictionary
    Args:
        name(str): name of the instance.
        base_config(dict): specific node relevant data.
        node type segment of the cluster's config file,
            e.g. ray_head_default.
    """
    # Create security group stanza from VPC creation config
    security_group_identity_model = {"id": vpc_config["security_group_id"]}

    # Create subnet identity stanza from VPC create config
    subnet_identity_model = {"id": vpc_config["subnet_id"]}

    # Create primary network interface stanza for instance
    primary_network_interface = {
        "name": "eth0",
        "subnet": subnet_identity_model,
        "security_groups": [security_group_identity_model],
    }

    boot_volume_profile = {
        "capacity": base_config.get("boot_volume_capacity", 100),
        "name": f"boot-volume-{uuid4().hex[:4]}",
        "profile": {
            "name": base_config.get("volume_tier_name",
                                    VOLUME_TIER_NAME_DEFAULT)
        },
    }

    boot_volume_attachment = {
        "delete_volume_on_instance_delete": True,
        "volume": boot_volume_profile,
    }

    #TODO(dmatch01): Determine if key_id needed
    #key_identity_model = {"id": base_config.get("key_id")}

    instance_prototype = {}
    # Instance name
    instance_prototype["name"] = name

    # Instance keys
    ###instance_prototype["keys"] = [key_identity_model]

    # Instance type profile name
    instance_prototype["profile"] = {"name": INSTANCE_PROFILE_NAME_DEFAULT}

    # Instance resource group id
    instance_prototype["resource_group"] = {
        "id": base_config.get("resource_group_id")
    }

    # Instance vpc id
    instance_prototype["vpc"] = {"id": vpc_config["vpc_id"]}

    # Instance operating system image id
    instance_prototype["image"] = {"id": get_default_image(ibm_vpc_client)}

    # Instance provisioning zone
    instance_prototype["zone"] = {"name": ZONE_NAME_DEFAULT}

    # Instance boot volume
    instance_prototype["boot_volume_attachment"] = boot_volume_attachment

    # Instance network interface
    instance_prototype["primary_network_interface"] = primary_network_interface

    # TODO(dmatch01): Determine if metadata_service_model is needed
    """
    metadata_service_model = {}
    metadata_service_model['enabled'] = True
    metadata_service_model['protocol'] = 'https'
    metadata_service_model['response_hop_limit'] = 5
    instance_prototype['metadata_service'] = metadata_service_model
    """
    try:
        resp = ibm_vpc_client.create_instance(instance_prototype)
    except ibm_cloud_sdk_core.ApiException as e:
        if e.code == 400 and "already exists" in e.message:
            return name
        elif e.code == 400 and "over quota" in e.message:
            print(f"Create VM instance {name} failed due to quota limit.")
        else:
            print(f"""Create VM instance for {name}
                failed with status code {str(e.code)}
                .\nFailed instance prototype:\n""")
        raise e
    return resp.result


def check_credentials(creds_file_path) -> tuple[bool, str, any]:
    """Checks if the user has access credentials to this cloud."""

    required_fields = ['iam_api_key', 'resource_group_id']
    ibm_cos_fields = ['access_key_id', 'secret_access_key']
    help_str = ('    Store your API key and Resource Group id '
                f'in {creds_file_path} in the following format:\n'
                '      iam_api_key: <IAM_API_KEY>\n'
                '      resource_group_id: <RESOURCE_GROUP_ID>')
    base_config = read_credential_file(creds_file_path)

    if not base_config:
        return (False, 'Missing credential file at '
                f'{os.path.expanduser(creds_file_path)}.\n' + help_str, None)

    if set(required_fields) - set(base_config):
        return (False, f"The following IBM required fields is missing: "
                f"""{", ".join(list(
                            set(required_fields) - set(base_config)))}""" +
                '\n' + help_str, None)

    if set(ibm_cos_fields) - set(base_config):
        print(f"IBM Storage is missing the "
              "following fields in "
              f"""{", ".join(list(
                            set(ibm_cos_fields) - set(base_config)))}""")

    # verifies ability of user to create a client,
    # e.g. bad API KEY.
    try:
        return True, '', base_config
    except Exception as e:
        print(f'{str(e)}' + help_str)
        return False, f'{str(e)}' + help_str, None


def get_args(argumentList) -> tuple[str, str]:
    """
    Process the command line args.
    Args:
        argumentList: command line arguments list.
    Returns:
        creds_file: IBM credentials file.
        name_of_instance: name of instance you want to use.
    """
    # Options
    options = "hc:n:"

    # Long options
    long_options = ["help", "creds_file", "name_of_instance"]

    # Default Value
    creds_file = ''
    name_of_instance = ''
    try:
        # Parsing argument
        arguments, values = getopt.getopt(argumentList, options, long_options)

        # checking each argument
        for currentArgument, currentValue in arguments:

            if currentArgument in ("-h", "--help"):
                print(
                    f"provision_ibm_vm.py --creds_file <full path to IBM credential file>  --name_of_instance <name of instance>."
                )
                sys.exit(0)
            elif currentArgument in ("-c", "--creds_file"):
                creds_file = currentValue
            elif currentArgument in ("-n", "--name_of_instance"):
                name_of_instance = currentValue

    except getopt.error as err:
        # output error, and return with an error code
        print(str(err))
        sys.exit(2)

    if not creds_file:
        print(
            f"Error: missing required parameter  '--creds_file <full path to IBM credential file>'."
        )
        sys.exit(2)

    if not name_of_instance:
        name_of_instance = INSTANCE_NAME_DEFAULT
    print(
        f"Credentials File: {creds_file}, Instance Name: {name_of_instance}.")

    return creds_file, name_of_instance


def create_instance_artifacts(creds_file, name) -> Dict[str, Any]:
    """
    returns dict of {instance_id:instance_data} of node.

    Args:
        base_config(dict): specific node relevant data.
            node type segment of the cluster's config file,
            e.g. ray_head_default.
            a template shared by all nodes
            when creating multiple nodes (count>1).
    """
    print(f"Creating Instance: {name}")
    valid_creds, error_str, base_config = check_credentials(creds_file)
    if not valid_creds:
        raise Exception(error_str)
    try:
        # First create a sdk client
        ibm_vpc_client = create_ibm_vpc_client(base_config)

        # Next create a VPC
        vpc_config = create_vpc(ibm_vpc_client, base_config)

        # Now create a VM instance
        inst_resp = create_instance(name, base_config, ibm_vpc_client,
                                    vpc_config)

    except ibm_cloud_sdk_core.ApiException as e:
        if e.code == 400 and "already exists" in e.message:
            return name
        elif e.code == 400 and "over quota" in e.message:
            print(f"Create VM instance {name} failed due to quota limit.")
        else:
            print(f"""Create VM instance for {name}
                failed with status code {str(e.code)}
                .\nFailed instance prototype:\n""")
        raise e

    print(f"VM instance {name} created successfully.")


def main(argv):
    creds_file, instance_name = get_args(argv)
    create_instance_artifacts(creds_file, instance_name)


if __name__ == "__main__":
    main(sys.argv[1:])
