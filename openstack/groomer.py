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
from misc import ERROR, appendPath

logger = logging.getLogger("ezcluster.plugins.openstack")

CONFIG="config"
CLUSTER="cluster"
DATA="data"

PROJECTS="projects"
KEY_PAIR="key_pair"
LOCAL_PRIVATE_KEY_PATH="local_private_key_path"

NAME="name"
OPENSTACK="openstack"
PROJECT="project"
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


FUNC="func"

def terra_name(n):
    return n.replace('.', "_")


def groom_config(model):
    # Ensure local_key_path is valid
    for pname, prj in model[CONFIG][PROJECTS].items():
        if not os.path.exists(prj[KEY_PAIR][LOCAL_PRIVATE_KEY_PATH]):
            ERROR("Project[{}].key_pair.local_key_path: File '{}' not found".format(pname, prj[KEY_PAIR][LOCAL_PRIVATE_KEY_PATH]))


# ---------------------------------------------------------------------------- Security groups


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
        ERROR("security_group[{}]: All defined security group name must be prefixed with '{}'".format(sg[NAME], model[CLUSTER][ID] + "."))
    for sg in model[CLUSTER][OPENSTACK][SECURITY_GROUPS]:
        for idx, rule in enumerate(sg[INBOUND_RULES]):
            rule_name = "security_group[{}].inbound_rules[{}]".format(sg[NAME], idx)
            rule[_TF_NAME] = "{}_ingress_{}".format(sg[NAME], idx)
            groom_security_group_rules(model, rule, rule_name)
        for idx, rule in enumerate(sg[OUTBOUND_RULES]):
            rule_name = "security_group[{}].outbound_rules[{}]".format(sg[NAME], idx)
            rule[_TF_NAME] = "{}_egress_{}".format(sg[NAME], idx)
            groom_security_group_rules(model, rule, rule_name)


# ___________________________________________________________________________________________________

def groom(_plugin, model):
    model[FUNC] = { "terra_name": terra_name }
    model[DATA][INTERNAL_SG] = set()
    model[DATA][EXTERNAL_SG] = set()
    logger.info("Openstack grommer")
    groom_config(model)
    if model[CLUSTER][OPENSTACK][PROJECT] not in model[CONFIG][PROJECTS]:
        ERROR("Unexisting project '{}' definition".format(model[CLUSTER][OPENSTACK][PROJECT]))
    groom_security_groups(model)
    model["data"]["buildScript"] = appendPath(model["data"]["targetFolder"], "build.sh")
    return True  # Always enabled