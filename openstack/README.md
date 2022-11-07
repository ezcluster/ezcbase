

Security groups defined in a cluser definition must be named: <cluster>.<name>

Flavor defined in a cluster definition must be named: <project>.<cluster>.<name>

TODO:
- Personnal config by overriding 
- Add recordset entity
- Being able to build a cluster without node, to centralize common stuff (record set, sg,...)
- Security groups templates

TODO k8s
- Update kubspray, topolvm, ubuntu and all components
- Add api server entry in metallb
- Find a configuration system to pip package version to install on m0 (Install k8s ansible module required package (Debian) on main.ymml)' 
- module: Name subnet with the network, as some commands (os port add ..) does not scope on network (Need to refer subnet by its id)
- Automate addition of VIP as allowed_addresses on each VM's port