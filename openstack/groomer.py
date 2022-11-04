# Copyright (C) 2021 BROADSoftware
#
# This file is part of EzCluster
#
# EzCluster is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# EzCluster is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with EzCluster.  If not, see <http://www.gnu.org/licenses/lgpl-3.0.html>.

import logging
import os
import re
from misc import ERROR, appendPath, setDefaultInMap

logger = logging.getLogger("ezcluster.plugins.openstack")

CONFIG="config"
CLUSTER="cluster"
DATA="data"

PROJECTS="projects"

NAME="name"
OPENSTACK="openstack"
PROJECT="project"
FUNC="func"

def terra_name(n):
    return n.replace('.', "_")


# ----------------------------------------------------------------------------- Config
KEY_PAIR="key_pair"
LOCAL_PRIVATE_KEY_PATH="local_private_key_path"
DNS_ZONE="dns_zone"

def groom_config(model):
    # Ensure local_key_path is valid
    for pname, prj in model[CONFIG][PROJECTS].items():
        if not os.path.exists(prj[KEY_PAIR][LOCAL_PRIVATE_KEY_PATH]):
            ERROR("Project[{}].key_pair.local_key_path: File '{}' not found".format(pname, prj[KEY_PAIR][LOCAL_PRIVATE_KEY_PATH]))
        if not prj[DNS_ZONE].endswith("."):
            prj[DNS_ZONE] = prj[DNS_ZONE] + "."


# ---------------------------------------------------------------------------- Security groups

SECURITY_GROUPS="security_groups"
OUTBOUND_RULES="outbound_rules"
INBOUND_RULES="inbound_rules"
PROTOCOL="protocol"
FROM_PORT="from_port"
TO_PORT="to_port"
PORT="port"
ICMP_TYPE="icmp_type"
REMOTE_CIDR="remote_cidr"
REMOTE_SG="remote_sg"
ID="id"
_TF_NAME="_tf_name"
INTERNAL_SG="internal_sg"
EXTERNAL_SG="external_sg"
_EXTERNAL_SG="_external_sg"

PORT_FROM_STRING = {
    "ftp-data": 20,
    "ftp": 21,
    "ssh": 22,
    "telnet": 23,
    "smtp": 25,
    "tftp": 69,
    "http": 80,
    "pop3": 110,
    "sftp": 115,
    "ntp": 123,
    "imap3": 220,
    "https": 443
}

def is_number(x):
    try:
        int(x)
        return True
    except ValueError:
        return False

cidrCheck = re.compile("^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/[0-9]{1,2}$")

# Form ICMP protocol, ports are ICMP type (cf https://github.com/gophercloud/gophercloud/blob/master/openstack/networking/v2/extensions/security/rules/requests.go
# Security group openstack name will be prefixed by cluster_id


def groom_security_group_rules(model, rule, rule_name):
    if rule[PROTOCOL] == "tcp" or rule[PROTOCOL] == "udp":
        if PORT in rule:
            if FROM_PORT in rule or TO_PORT in rule:
                ERROR("security_group[{}]: Both 'port' and 'from_port'/'to_port' are defined".format(rule_name))
            if is_number(rule[PORT]):
                rule[FROM_PORT] = rule[TO_PORT] = rule[PORT]
            else:
                rule[PORT] = rule[PORT].lower()
                if rule[PORT] == "all":
                    rule[FROM_PORT] = 0
                    rule[TO_PORT] = 0
                elif rule[PORT] in PORT_FROM_STRING:
                        rule[FROM_PORT] = PORT_FROM_STRING[rule[PORT]]
                        rule[TO_PORT] = PORT_FROM_STRING[rule[PORT]]
                else:
                    ERROR("security_group[{}].port: '{}' is not a valid port name".format(rule_name, rule[PORT]))
        else:
            if FROM_PORT not in rule or TO_PORT not in rule:
                ERROR("security_group[{}]: 'from_port' and 'to_port' must be both defined if 'port' is not and protocol is udp or tcp".format(rule_name))
    elif rule[PROTOCOL] == "icmp":
        if ICMP_TYPE in rule:
            rule[FROM_PORT] = rule[ICMP_TYPE]
            rule[TO_PORT] = rule[ICMP_TYPE]
        else:
            rule[FROM_PORT] = None
            rule[TO_PORT] = None
    else:
        pass # Nothing to do
    if REMOTE_CIDR in rule:
        if REMOTE_SG in rule:
            ERROR("security_group[{}]: remote_cidr and remote_sg can't be both defined".format(rule_name))
        if not cidrCheck.match(rule[REMOTE_CIDR]):
            ERROR("security_group[{}]: Invalid remote_cidr".format(rule_name))
    elif REMOTE_SG in rule:
        if rule[REMOTE_SG] in model[DATA][INTERNAL_SG]:
            rule[_EXTERNAL_SG] = False
        else:
            model[DATA][EXTERNAL_SG].add(rule[REMOTE_SG])
            rule[_EXTERNAL_SG] = True
    else:
        ERROR("security_group[{}]: One of remote_cidr or remote_sg must be defined".format(rule_name))

def groom_security_groups(model):
    # A first loop to find our local sg
    for sg in model[CLUSTER][OPENSTACK][SECURITY_GROUPS]:
        if sg[NAME] in model[DATA][INTERNAL_SG]:
            ERROR("Duplicate security_group.name: '{}'".format(sg[NAME]))
        model[DATA][INTERNAL_SG].add(sg[NAME])
        if not sg[NAME].startswith(model[CLUSTER][ID] + "."):
            ERROR("security_groups[{}]: All defined security group name must be prefixed with '{}'".format(sg[NAME], model[CLUSTER][ID] + "."))
    for sg in model[CLUSTER][OPENSTACK][SECURITY_GROUPS]:
        for idx, rule in enumerate(sg[INBOUND_RULES]):
            rule_name = "security_groups[{}].inbound_rules[{}]".format(sg[NAME], idx)
            rule[_TF_NAME] = "{}_ingress_{}".format(sg[NAME], idx)
            groom_security_group_rules(model, rule, rule_name)
        for idx, rule in enumerate(sg[OUTBOUND_RULES]):
            rule_name = "security_groups[{}].outbound_rules[{}]".format(sg[NAME], idx)
            rule[_TF_NAME] = "{}_egress_{}".format(sg[NAME], idx)
            groom_security_group_rules(model, rule, rule_name)


# ---------------------------------------------------------------------------------------- Flavors

FLAVORS="flavors"
INTERNAL_FLAVORS="insternal_flavors"


def groom_flavors(model):
    for flavor in model[CLUSTER][OPENSTACK][FLAVORS]:
        prefix = "{}.{}.".format(model[CLUSTER][OPENSTACK][PROJECT],model[CLUSTER][ID])
        if not flavor[NAME].startswith(prefix):
            ERROR("flavors[{}]: All defined flavor name must be prefixed with '{}'".format(flavor[NAME], prefix))
        model[DATA][INTERNAL_FLAVORS].add(flavor[NAME])

# ---------------------------------------------------------------------------------------- Roles

ROLE_BY_NAME="roleByName"
IMAGE="image"
IMAGES="images"
_IMAGE_LOGIN="_image_login"
LOGIN="login"
_SECURITY_GROUPS="_security_groups"
DEFAULTS="defaults"
FLAVOR="flavor"
_EXTERNAL_FLAVOR="_external_flavor"
DOMAIN="domain"

def groom_roles(model):
    for roleName, role in model[DATA][ROLE_BY_NAME].items():
        setDefaultInMap(role, OPENSTACK, {})
        # ---------- Handle domain
        project = model[CONFIG][PROJECTS][model[CLUSTER][OPENSTACK][PROJECT]]
        if role[DOMAIN].endswith("."):
            # Domain is absolute. Must check against our zone
            if not role[DOMAIN].endswith(project[DNS_ZONE]):
                ERROR("role[{}].domain must ends with our dns_zone ({})".format(roleName, project[DNS_ZONE]))
        else:
            role[DOMAIN] = "{}.{}".format(role[DOMAIN], project[DNS_ZONE])
        # --------  Handle image
        if IMAGE not in role[OPENSTACK]:
            if IMAGE in model[CLUSTER][OPENSTACK][DEFAULTS]:
                role[OPENSTACK][IMAGE] = model[CLUSTER][OPENSTACK][DEFAULTS][IMAGE]
            else:
                ERROR("role[{}].openstack.image is missing and there is no default value".format(roleName))
        if role[OPENSTACK][IMAGE] not in model[CONFIG][IMAGES]:
            ERROR("role[{}].openstack.image={}: Not referenced in config".format(roleName, role[OPENSTACK][IMAGE]))
        role[OPENSTACK][_IMAGE_LOGIN] =  model[CONFIG][IMAGES][role[OPENSTACK][IMAGE]][LOGIN]
        # -------- flavor
        if FLAVOR not in role[OPENSTACK]:
            if FLAVOR in model[CLUSTER][OPENSTACK][DEFAULTS]:
                role[OPENSTACK][FLAVOR] = model[CLUSTER][OPENSTACK][DEFAULTS][FLAVOR]
            else:
                ERROR("role[{}].openstack.flavor is missing and there is no default value".format(roleName))
        role[OPENSTACK][_EXTERNAL_FLAVOR] = role[OPENSTACK][FLAVOR] not in model[DATA][INTERNAL_FLAVORS]
        # -------- Security groups
        role[OPENSTACK][_SECURITY_GROUPS] = []
        if SECURITY_GROUPS not in role[OPENSTACK]:
            if SECURITY_GROUPS in model[CLUSTER][OPENSTACK][DEFAULTS]:
                role[OPENSTACK][SECURITY_GROUPS] = model[CLUSTER][OPENSTACK][DEFAULTS][SECURITY_GROUPS]
            else:
                logger.warning("role[{}] has no associated security groups")
        if SECURITY_GROUPS in role[OPENSTACK]:
            for sg_name in role[OPENSTACK][SECURITY_GROUPS]:
                if sg_name in model[DATA][INTERNAL_SG]:
                    role[OPENSTACK][_SECURITY_GROUPS].append({ "name": sg_name, "external": False})
                else:
                    role[OPENSTACK][_SECURITY_GROUPS].append({ "name": sg_name, "external": True})
                    model[DATA][EXTERNAL_SG].add(sg_name)

# ---------------------------------------------------------------------------------------- Nodes

NODES="nodes"
NETWORK="network"
AVAILABILITY_ZONE="availability_zone"

def groom_nodes(model):
    for node in model[CLUSTER][NODES]:
        setDefaultInMap(node, OPENSTACK, {})
        if NETWORK not in node[OPENSTACK]:
            if NETWORK in model[CLUSTER][OPENSTACK][DEFAULTS]:
                node[OPENSTACK][NETWORK] =  model[CLUSTER][OPENSTACK][DEFAULTS][NETWORK]
            else:
                ERROR("node[{}].openstack.network is missing and there is no default value".format(node[NAME]))
        if AVAILABILITY_ZONE not in node[OPENSTACK]:
            if AVAILABILITY_ZONE in model[CLUSTER][OPENSTACK][DEFAULTS]:
                node[OPENSTACK][AVAILABILITY_ZONE] =  model[CLUSTER][OPENSTACK][DEFAULTS][AVAILABILITY_ZONE]
            else:
                pass # availability_zone is optional

# ---------------------------------------------------------------------------------------- key pair

BASE_NAME="base_name"
PUBLIC_KEY="public_key"

def groom_key_pair(model):
    project = model[CONFIG][PROJECTS][model[CLUSTER][OPENSTACK][PROJECT]]
    model[DATA][KEY_PAIR] = { "name": "{}_{}".format(model[CLUSTER][ID], project[KEY_PAIR][BASE_NAME]), "public_key": project[KEY_PAIR][PUBLIC_KEY] }



# ___________________________________________________________________________________________________



def groom(_plugin, model):
    model[FUNC] = { "terra_name": terra_name }
    model[DATA][INTERNAL_SG] = set()
    model[DATA][EXTERNAL_SG] = set()
    model[DATA][INTERNAL_FLAVORS] = set()
    groom_config(model)
    if model[CLUSTER][OPENSTACK][PROJECT] not in model[CONFIG][PROJECTS]:
        ERROR("Unexisting project '{}' definition".format(model[CLUSTER][OPENSTACK][PROJECT]))
    setDefaultInMap(model[CLUSTER][OPENSTACK], DEFAULTS, {})
    setDefaultInMap(model[CLUSTER][OPENSTACK], SECURITY_GROUPS, [])
    setDefaultInMap(model[CLUSTER][OPENSTACK], FLAVORS, [])
    groom_security_groups(model)
    groom_flavors(model)
    groom_roles(model)
    groom_nodes(model)
    groom_key_pair(model)
    model["data"]["buildScript"] = appendPath(model["data"]["targetFolder"], "build.sh")
    return True  # Always enabled