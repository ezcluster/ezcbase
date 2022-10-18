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

loggerConfig = logging.getLogger("ezcluster.config")

       
SYNCED_FOLDERS = "synced_folders"


deviceFromIndex = ['sda', 'sdb', 'sdc', 'sdd', 'sde', 'sdf', 'sdg', 'sdh', 'sdi', 'sdj', 'sdk', 'sdl', 'sdm', 'sdn', 'sdo', 'sdp', 'sdq', 'sdr', 'sds', 'sdt', 'sdu', 'sdv']


def groomRoles(model):
    # Handle data disks            
    for rl in model["cluster"]["roles"]:
        role = model["data"]["roleByName"][rl["name"]]
        if "data_disks" in role:
            first_port = model["data"]["box"]["firstFreeDiskPort"]
            for i in range(0, len(role['data_disks'])):
                port = i + first_port
                role['data_disks'][i]['port'] = port
                role['data_disks'][i]['device'] = deviceFromIndex[port]
                setDefaultInMap(role['data_disks'][i], "fstype", model["data"]["box"]["defaultFsType"])
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
    for node in model['cluster']['nodes']:
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


def groom(_plugin, model):
    if "boxes" not in model["config"]:
        ERROR("Missing 'boxes' definition in config file")
    for box in model["config"]["boxes"]:
        for name in box["names"]:
            if name == model["cluster"]["vagrant"]["box"]:
                model["data"]["box"] = box
    if "box" not in model["data"]:
        ERROR("Unable to find a box definition in config for box={}".format(model["cluster"]["vagrant"]["box"]))
    if model["data"]["box"]["os_family"] == "RedHat":
        if "yum_repo" not in model["cluster"]["vagrant"]:
            ERROR("'vagrant.yum_repo' is mandatory if 'box.os_family' == 'RedHat'")
        repoInConfig = "repositories" in model["config"] and "vagrant" in model["config"]["repositories"] and "yum_repo_base_url" in model["config"]["repositories"]["vagrant"]
        if model["cluster"]["vagrant"]["yum_repo"] == "local" and not repoInConfig:
            ERROR("'repositories.vagrant.repo_yum_base_url' is not defined in config file while 'vagrant.yum_repo' is set to 'local' in '{}'".format(model["data"]["sourceFileDir"]))
        if repoInConfig:
            # All plugins are lookinhg up their repositories in model["data"]. So does the vagrant one.
            setDefaultInMap(model["data"], "repositories", {})
            setDefaultInMap(model["data"]["repositories"], "vagrant", {})
            model["data"]["repositories"]["vagrant"]["yum_repo_base_url"] = model["config"]["repositories"]["vagrant"]["yum_repo_base_url"]

    groomRoles(model)
    groomNodes(model)
        
    model["data"]["buildScript"] = appendPath(model["data"]["targetFolder"], "build.sh")
    return True  # Always enabled
        