

## TODO

use the generic disk config:

Warning: extra disk limited to 3 if disk controller id IDE (Depends of the image)


```
# -*- mode: ruby -*-
# vi: set ft=ruby :

# All Vagrant configuration is done below. The "2" in Vagrant.configure
# configures the configuration version (we support older styles for
# backwards compatibility). Please don't change it unless you know what
# you're doing.


Vagrant.configure(2) do |config|
 
  config.vm.box = "local/ubuntu2404"

  config.vm.provider "virtualbox" do |vb|
    #vb.gui = true
  end

  config.vm.define "n0" do |node|
    node.vm.network "private_network", ip: "192.168.56.10"
    node.vm.hostname = "n0.kspray1.mbp"
    #node.vm.disk :disk, size: "80GB", primary: true
    node.vm.disk :disk, size: "11GB", name: "extra1"
    node.vm.disk :disk, size: "12GB", name: "extra2"
    node.vm.disk :disk, size: "13GB", name: "extra3"
    node.vm.provider "virtualbox" do |vb|
		vb.name = "kspray1_n0"
        vb.customize ["modifyvm", :id, "--memory", "24576"]
    	vb.customize ["modifyvm", :id, "--cpus", "8"]
  		# vb.customize ['storageattach', :id, '--storagectl', 'SCSI', '--port', 2, '--device', 0, '--type', 'hdd', '--medium', '../disks/n0_sdc.vmdk']
    end
  end

# We don't trigger provisioning from vagrant, since it is executed for each vm individually. Use extra.sh main.yml instead



end


```