# Copyright (C) 2018 BROADSoftware
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
from misc import ERROR, setDefaultInMap, appendPath, resolveIps
import copy

OS_FAMILY = "os_family"

BOX = "box"
VAGRANT = "vagrant"
DATA = "data"
CLUSTER = "cluster"


loggerConfig = logging.getLogger("ezcluster.config")

       
SYNCED_FOLDERS = "synced_folders"


deviceFromIndex = ['sda', 'sdb', 'sdc', 'sdd', 'sde', 'sdf', 'sdg', 'sdh', 'sdi', 'sdj', 'sdk', 'sdl', 'sdm', 'sdn', 'sdo', 'sdp', 'sdq', 'sdr', 'sds', 'sdt', 'sdu', 'sdv']


def groomRoles(model):
    # Handle data disks            
    for rl in model[CLUSTER]["roles"]:
        role = model[DATA]["roleByName"][rl["name"]]
        if "data_disks" in role:
            first_port = model[DATA]["box"]["firstFreeDiskPort"]
            for i in range(0, len(role['data_disks'])):
                port = i + first_port
                role['data_disks'][i]['port'] = port
                role['data_disks'][i]['device'] = deviceFromIndex[port]
                setDefaultInMap(role['data_disks'][i], "fstype", model[DATA]["box"]["defaultFsType"])
            disksToMount = 0
            for d in role['data_disks']:
                if "mount" in d:
                    disksToMount += 1
            role["disksToMountCount"] = disksToMount
        else:
            role["disksToMountCount"] = 0


DEFAULT_ROUTER = "default_router"
ROOT_DISK_SIZE = "root_disk_size"
RESIZE_ROOT_DISK = "resizeRootDisk"

def groomNodes(model):
    resolveIps(model)
    model['data']['dataDisksByNode'] = {}
    for node in model[CLUSTER]['nodes']:
        if SYNCED_FOLDERS not in node:
            node[SYNCED_FOLDERS] = []
        role = model["data"]["roleByName"][node["role"]]
        if SYNCED_FOLDERS in role:
            node[SYNCED_FOLDERS] += role[SYNCED_FOLDERS]
        if SYNCED_FOLDERS in model["cluster"]["vagrant"]:
            node[SYNCED_FOLDERS] += model["cluster"]["vagrant"][SYNCED_FOLDERS]
        if "data_disks" in role:
            dataDisks = copy.deepcopy(role['data_disks'])
            for disk in dataDisks:
                disk["fileName"] = "../disks/{}_{}.vmdk".format(node["name"], disk["device"])
                disk["size_mb"] = disk["size"] * 1024 + 4   # +4 for lvm metadata if lvm is used in top of this disk
            model['data']['dataDisksByNode'][node["name"]] = dataDisks
        if DEFAULT_ROUTER not in node:
            if DEFAULT_ROUTER in role:
                node[DEFAULT_ROUTER] = role[DEFAULT_ROUTER]
            elif DEFAULT_ROUTER in model["cluster"]["vagrant"]:
                node[DEFAULT_ROUTER] = model["cluster"]["vagrant"][DEFAULT_ROUTER]
        model["data"][RESIZE_ROOT_DISK] = True
        if ROOT_DISK_SIZE not in node:
            if ROOT_DISK_SIZE in role:
                node[ROOT_DISK_SIZE] = role[ROOT_DISK_SIZE]
            else:
                model["data"][RESIZE_ROOT_DISK] = False



APT_CACHER_SERVER="apt_cacher_server"
APT_CACHER_MODE="apt_cacher_mode"
CONFIG = "config"


def groom(_plugin, model):
    if "boxes" not in model[CONFIG]:
        ERROR("Missing 'boxes' definition in CONFIG file")
    for box in model[CONFIG]["boxes"]:
        for name in box["names"]:
            if name == model[CLUSTER][VAGRANT][BOX]:
                model[DATA][BOX] = box
    if BOX not in model[DATA]:
        ERROR("Unable to find a box definition in CONFIG for box={}".format(model[CLUSTER][VAGRANT][BOX]))
    if model[DATA][BOX][OS_FAMILY] == "RedHat":
        if "yum_repo" not in model[CLUSTER][VAGRANT]:
            ERROR("'vagrant.yum_repo' is mandatory if 'box.os_family' == 'RedHat'")
        repoInConfig = "repositories" in model[CONFIG] and VAGRANT in model[CONFIG]["repositories"] and "yum_repo_base_url" in model[CONFIG]["repositories"][VAGRANT]
        if model[CLUSTER][VAGRANT]["yum_repo"] == "local" and not repoInConfig:
            ERROR("'repositories.vagrant.repo_yum_base_url' is not defined in CONFIG file while 'vagrant.yum_repo' is set to 'local' in '{}'".format(model[DATA]["sourceFileDir"]))
        if repoInConfig:
            # All plugins are looking up their repositories in model["data"]. So does the vagrant one.
            setDefaultInMap(model[DATA], "repositories", {})
            setDefaultInMap(model[DATA]["repositories"], VAGRANT, {})
            model[DATA]["repositories"][VAGRANT]["yum_repo_base_url"] = model[CONFIG]["repositories"][VAGRANT]["yum_repo_base_url"]
    elif model[DATA][BOX][OS_FAMILY] == "Debian":
        setDefaultInMap(model[CLUSTER][VAGRANT], APT_CACHER_MODE, "none")
        if model[CLUSTER][VAGRANT][APT_CACHER_MODE] != "none" and APT_CACHER_SERVER not in model[CLUSTER][VAGRANT]:
            ERROR("vagrant.{} must be defined if vagrant.{} is not 'none'".format(APT_CACHER_SERVER, APT_CACHER_MODE))
    else:
        pass

    groomRoles(model)
    groomNodes(model)
        
    model[DATA]["buildScript"] = appendPath(model[DATA]["targetFolder"], "build.sh")
    return True  # Always enabled
        