# HPC system administrator tutorial

This tutorial tries to teach how to install manually a basic HPC cluster.

First part will be dedicated to core installation, i.e. the bare minimum.

Second part will be dedicated to automate this installation using Ansible, and
an opensource Stack, BlueBanquise.

Third and last part will be dedicated to users environment and cluster day to day
management.

This tutorial will focus on simplicity, lightness and security.
All software used are very common and when facing an error, a quick look on the
web will most of the time solves the issue.

If you face any issues with this tutorial, do not hesitate to contact me at:
benoit.leveugle@gmail.com

## Hardware requirements

The following hardware is needed to perform this training:

**Minimal configuration to do the training:**
Laptop/workstation with 4Go RAM and 20Go disk. VT-x instructions MUST be activated in the BIOS. VMs will be used.

**Recommended configuration to do the training:**
Laptop/workstation with 8go or 16go, and 40Go disk. VT-x instructions MUST be activated in the BIOS. VMs will be used.

**Best configuration to do the training:**
A real cluster, with real physical servers.

## Useful commands

General commands:

* Load a kernel module : `modprobe mymodule -v`
* Unload a kernel module : `modprobe -r mymodule`
* List loaded kernel modules : `lsmod`
* Check listening processes and port used : `netstat -aut`
* Get hardware information (use –help for more details) : `inxi`
* Check network configuration : `ip add`
* Open a screen : `screen -S sphen`
* List screens : `screen -ls`
* Join a screen : `screen -x sphen`
* Detach a screen : use `Ctrl+a+d` on keyboard
* Change keyboard language in current terminal : `loadkeys fr` (azerty), `loadkeys us` (qwerty)
* Remount / when in read only (often in recovery mode) : `mount -o remount,rw /`
* Apply a patch on a file : `patch myfile.txt < mypatch.txt`
* Do a patch from original and modified file : `diff -Naur original.txt modified.txt`

IPMI commands for remote control :

* Boot, very useful for very slow to boot systems (bios can be replaced with pxe or cdrom or disk) : `ipmitool -I lanplus -H bmc5 -U user -P password chassis bootdev bios`
* Make boot persistent : `ipmitool -I lanplus -H bmc5 -U user -P password chassis bootdev disk options=persistent`
* Control power (reset car be replaced with soft or cycle or off or on) : `ipmitool -I lanplus -H bmc5 -U user -P password chassis power reset`
* Activate remote console (use Enter, then & then . to exit) : `ipmitool -H bmc5 -U user -P password -I lanplus -e \& sol activate`

More: https://support.pivotal.io/hc/en-us/articles/206396927-How-to-work-on-IPMI-and-IPMITOOL
Note: when using sol activate, if keyboard does not work, try using the same command into a screen, this may solve the issue.

Clush usage :

* To do a command on all nodes : `clush -bw node1,node[4-5] "hostname"`
* To copy a file on all nodes : `clush -w node1,node[4-5] –copy /root/slurm.conf –dest=/etc/slurm/slurm.conf`
* To replace a string in a file of all nodes : `clush -bw compute1[34-67] 'sed -i "s/10.0.0.1/nfsserver/g" /etc/fstab'`

## Vocabulary

### Basic concepts

Few words on vocabulary used:

* To avoid confusion around "server" word:
   * a **node** refers to a physical or virtual machine with an operating system on it.
   * a **server** refer to a software daemon listening on the network.
* A **NIC** is a network interface controller (the thing you plug the Ethernet cable in ツ).
* The system administrator, or sysadmin, will be you, the person in charge of managing the cluster.
* Pets and Cattles
  * A pet node is a key node, that you MUST keep healthy and that is considered difficult to reinstall.
  * A cattle node, is a "trashable" node, that you consider non vital to production and that is considered easy to reinstall.

>>>>>>>>>>>>>>>>>>>>>>>>

(Original black and white image from Roger Rössing, otothek_df_roe-neg_0006125_016_Sch%C3%A4fer_vor_seiner_Schafherde_auf_einer_Wiese_im_Harz.jpg)

An HPC cluster can be seen like a sheep flock. The admin sys (shepherd), the management node (shepherd dog), and the compute/login nodes (sheep). This leads to two types of nodes, like cloud computing: pets (shepherd dog) and cattle (sheep). While the safety of your pets must be absolute for good production, losing cattle is common and considered normal. In HPC, most of the time, management node, file system (io) nodes, etc, are considered as pets. On the other hand, compute nodes and login nodes are considered cattle. Same philosophy apply for file systems: some must be safe, others can be faster but “losable”, and users have to understand it and take precautions. In this tutorial, /home will be considered safe, and /scratch fast but losable.

### Basic words

An HPC cluster is an aggregate of physical compute nodes dedicated to intensive calculations.
Most of the time, these calculations are related to sciences, but can also be used in other domains, like finances.
On general HPC clusters, users will be able to login through ssh on dedicated nodes (called login nodes),
upload their code and data, then compile their code, and launch jobs (calculations) on the cluster.

To maintain the cluster synchronized and to provide features, multiple **services** are running on management node.

Most of the time, a cluster is composed of:

* An **administration node** or **management node** (pet), whose purpose is to host all core resources of the cluster.
* **IO nodes** (pet), whose purpose is to provide storage for users. Basic storage is based on NFS, and advanced storage (optional) on parallel file systems.
* **Login nodes** (cattle), whose purpose is to be the place where users interact with the cluster and with the job scheduler, and manage their code and data.
* **Compute nodes** (cattle), whose purpose is to provide calculation resources.

A node is the name given to a server inside an HPC cluster. Nodes are most of the time equipped with a **BMC**
for Baseboard Management Controller, which is kind of a small server connected on the server motherboard and allow manipulating the server remotely (power on, power off, boot order, status, console, etc.).

>>>>>>>>>>>>>>>>>>

Sometime, servers are **racked** into a **chassis** that can embed an **CMC** for Chassis Management Controller. Servers and chassis can even be
**racked** into a rack that can embed an **RMC** for Rack Management Controller.

On the **operating system** (OS), a **service** is a software daemon managed by **systemd**. For example, the DHCP server service is in charge of attributing nodes IP addresses on the network depending of their MAC address (each network interface has its own MAC). Another example, the job scheduler, is also used as a service. Etc.

Management node, called here `odin`, is the node hosting most of vital services of the cluster.

**Interconnect** network, often based on the **InfiniBand** technology (IB), is used in parallel of the Ethernet network (Eth). Interconnect is mainly used for calculations (transfer data between process of running codes) and is used to export the fast file systems, exported by the IO nodes. InfiniBand has much lower latency and much higher bandwidth than Ethernet network.

### Understanding services

As said above, management node host multiple basic services needed to run the cluster:
* The **repository** server: based on http protocol, it provides packages (rpm) to all nodes of the cluster. Service is `httpd` (Apache).
* The **tftp** server: based on tftp protocol, it provides PXE very basic files to initialize boot sequence on the remote servers. Service is `fbtftp` (Facebook Tftp).
* The **dhcp** server: provides ip for all nodes and BMC on the network. Ip are attributed using MAC addresses of network interfaces. Service is `dhcpd` (ISC DHCP).
* The **dns** server: provides link between ip and hostname, and the opposite. Service is `named` (bind9).
* The **time** server: provides a single and synchronized clock for all equipment of the cluster. More important than it seems. Service is `chronyd` (Chrony).
* The **pxe stack**: represent the aggregate of the repository server, the tftp server, the dhcp server, the dns server and the time server. Used to deploy OS on nodes on the cluster using the network.
* The **nfs** server: export simple storage spaces and allows nodes to mount these exported spaces locally (/home, /opt, etc. ). Service is `nfs-server`.
* The **LDAP** server: provides centralized users authentication for all nodes. Is optional for small clusters. Service is `slapd` (OpenLDAP).
* The **job scheduler** server: manage computational resources, and spread jobs from users on the cluster. Service is `slurmctld` (Slurm).
* The **monitoring** server: monitor the cluster to provide metrics, and raise alerts in case of issues. Service is `prometheus` (Prometheus).

### Computational resources management

The **job scheduler** is the conductor of computational resources of the cluster.

A **job** is a small script, that contains instructions on how to execute the calculation program, and that also contains information for to the job scheduler (required job duration, how much resources are needed, etc.).
When a user ask the job scheduler to execute a **job**, which is call **submitting a job**, the job enter **jobs queue**.
The job scheduler is then in charge of finding free computational resources depending of the needs of the job, then launching the job and monitoring it during its execution. Note that the job scheduler is in charge of managing all jobs to ensure maximum usage of computational resources, which is why sometime, the job scheduler will put some jobs on hold for a long time in a queue, to wait for free resources.
In return, after user has submitted a job, the job scheduler will provide user a **job ID** to allow following job state in the jobs queue and during its execution.

## Cluster description

### Architecture

The cluster structure for this training will be as follows:

>>>>>>>>>>>>>>>>>>>>>>>>

On the hardware side:

* One master node called `odin`.
* One storage node called `thor`, based one NFS, will be deployed, for /home and /software.
* One login node called `heimdall` for users to login.
* Multiple compute nodes, called `valkyries` will then be deployed on the fly with PXE.

### Network

Network information:

The whole cluster will use a single subnet 10.10.0.0/16.
IP used will be (nic name to be set depending of your hardware):

* odin: 10.10.0.1 (nic: enp0s3)
* thor : 10.10.1.1 (nic: enp0s3)
* heimdall: 10.10.2.1 (nic: enp0s3), 192.168.1.77 (nic: enp0s8) for users access
* valkyrieX: 10.10.3.X (nic: enp0s3)

Domain name will be cluster.local

Note: if you plan to test this tutorial in Virtualbox, 10.10.X.X range may
already been taken by Virtualbox NAT. In this case, use another subnet.

### Final notes before we start

All nodes will be installed with a minimal install Centos 8. Needed other rpms
are provided at <>>>>>>>>>>>>>>>>> or if you are doing this training with me, these
files are already in the /root directory of your VMs.

* To simplify this tutorial, firewall will be deactivated. You can reactivate it later.
* We will keep SELinux enforced. When facing permission denied, try setting SELinux into permissive mode to check if that's the reason, or check selinux logs.
* If you get `Pane is dead` error during pxe install, most of the time increase RAM to minimum 1200 Mo and it should be ok.
* You can edit files using `vim` which is a powerful tool, but if you feel more comfortable with, use `nano` (`nano myfile.txt`, then edit file, then use `Ctrl+O` to save, and `Ctrl+X` to exit).

## Management node installation

This part describes how to manually install `odin` management node basic services, needed to deploy and install the other servers.

Install first system with Centos DVD image, and choose minimal install as package selection (Or server with GUI if you prefer. However, more packages installed means less security and less performance).

Partition schema should be the following, without LVM but standard partitions:

*	/boot 2Go ext4
*	swap 4Go
*	/ remaining space ext4

Be extremely careful with time zone choice. This parameter is more important than it seems as time zone will be set in the kickstart file later, and MUST be the same than the one chosen here when installing `odin`. If you don’t know which one to use, choose America/Chicago, the same one chose in the kickstart example of this document.
After install and reboot, disable firewalld using:

```
systemctl disable firewalld
systemctl stop firewalld
```

Change hostname to `odin` (need to login again to see changes):

`hostnamectl set-hostname odin.cluster.local`

To start most services, we need the main NIC to be up and ready with an ip.
We will use **NetworkManager** to handle network. `nmcli` is the command to interact with NetworkManager.

Assuming main NIC name is `enp0s3`, to set `10.10.0.1/16` IP and subnet on it, use the following commands:

```
nmcli con mod enp0s3 ipv4.addresses 10.10.0.1/16
nmcli con mod enp0s3 ipv4.method manual
nmcli con up enp0s3
```

Then ensure interface is up with correct ip using:

```
ip a
```

You should see your NICs with `enp0s3` having ip `10.10.0.1` with `/16` prefix.

Time to setup basic repositories.

### Setup basic	repositories

#### Main OS

Backup and clean first default Centos repositories:

```
cp -a /etc/yum.repos.d/ /root/
rm -f /etc/yum.repos.d/*
```

The local repository allows the main server and other servers to install automatically rpm with correct dependencies without having to access web repository. All needed rpm are available in the Centos DVD.

Next step depends if you are using a Virtual Machine or a real server.

If you are using a real server, upload the Centos DVD in /root folder and mount it in /mnt (or mount it directly from CDROM):

```
mount /root/CentOS-8-x86_64-Everything.iso /mnt
```

Copy full iso (will be needed later for PXE), and use the database already on the DVD:

```
mkdir -p /var/www/html/repositories/centos/8/x86_64/os/
cp -a /mnt/* /var/www/html/repositories/centos/8/x86_64/os/
restorecon -r /var/www/html/
```

If you are using a Virtual Machine, simply create the folder and mount the ISO that you should have added into the virtual CDROM drive:

```
mkdir -p /var/www/html/repositories/centos/8/x86_64/os/
mount /dev/cdrom /var/www/html/repositories/centos/8/x86_64/os/
restorecon -r /var/www/html/
```

Now, indicate the server the repository position (here local disk). To do so, edit the file `/etc/yum.repos.d/os.repo` and add:

```
[BaseOS]
name=BaseOS
baseurl=file:///var/www/html/repositories/centos/8/x86_64/os/BaseOS
gpgcheck=0
enabled=1

[AppStream]
name=AppStream
baseurl=file:///var/www/html/repositories/centos/8/x86_64/os/AppStream
gpgcheck=0
enabled=1
```

OS repositories are split between BaseOS and AppStream. Using this file, we will reach both.

Finally, install and start the `httpd` service, to allow other servers using this repository through `http`.

```
dnf install httpd -y
systemctl enable httpd
systemctl start httpd
```

The repository server is up, and listening. We can now use it to reach repositories, as any other servers on the cluster network will.

Edit `/etc/yum.repos.d/os.repo` and set:

```
[BaseOS]
name=BaseOS
baseurl=http://10.10.0.1/repositories/centos/8/x86_64/os/BaseOS
gpgcheck=0
enabled=1

[AppStream]
name=AppStream
baseurl=http://10.10.0.1/repositories/centos/8/x86_64/os/AppStream
gpgcheck=0
enabled=1
```

Ensure it works, by installing for example `wget`:

```
dnf clean all
dnf repolist
dnf install wget
```

#### Other repositories

We will need to add extra packages as not all is contained in the Centos 8 DVD.
Create extra repository folder:

```
mkdir -p /var/www/html/repositories/centos/8/x86_64/extra/
restorecon -r /var/www/html/
```

Grab the packages from the web using wget:

>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>

Copy them into the `/var/www/html/repositories/centos/8/x86_64/extra/` folder, and then create a new repository here using the dedicated command.
We must install this command first:

```
dnf install -y createrepo
createrepo /var/www/html/repositories/centos/8/x86_64/extra/
```

Then create dedicated repository file `/etc/yum.repos.d/extra.repo` with the following content:

```
[Extra]
name=Extra
baseurl=http://10.10.0.1/repositories/centos/8/x86_64/extra
gpgcheck=0
enabled=1
```

To close this repositories part, we may install few useful packages.

If a local web browser is needed, install the following packages:

```
dnf install xorg-x11-utils xauth firefox
```

Then login on node using `ssh -X -C` to be able to launch `firefox`. Note however that this can be extremely slow.
A better way is to use ssh port forwarding features (`-L`), but this part is not covered this training.

Also, install clustershell and ipmitool, these will be used for computes nodes deployment and PXE tools.

```
dnf install clustershell ipmitool
```

### DHCP server

The DHCP server is used to assign ip addresses and hostnames to other nodes. It is the first server seen by a new node booting in PXE for installation. In this configuration, it is assumed MAC addresses of nodes are known.

Install the dhcp server package:

```
dnf install dhcp-server
```

Do not start it now, configure it first.
The configuration file is `/etc/dhcp/dhcpd.conf`.
It should be like the following, replacing MAC address here by the ones of the current cluster. It is possible to tune global values.
Unknown nodes/BMC will be given a temporary ip on the 10.0.254.x range if dhcp server do not know their MAC address.

```
 authoritative;

 subnet 10.10.0.0 netmask 255.255.0.0 {
 range 10.10.254.0 10.10.254.254; # range where unknown servers will be
 option domain-name "cluster.local";
 option domain-name-servers 10.10.0.1; # dns server ip
 option broadcast-address 10.10.255.255;
 default-lease-time 600;
 max-lease-time 7200;

 next-server 10.10.0.1; #  pxe server ip

 option client-arch code 93 = unsigned integer 16;
 if exists client-arch {
   if option client-arch = 00:00 {
     filename "undionly.kpxe";
   } elsif option client-arch = 00:07 {
     filename "ipxe.efi";
   } elsif option client-arch = 00:08 {
     filename "ipxe.efi";
   } elsif option client-arch = 00:09 {
     filename "ipxe.efi";
   }
 }

# List of nodes

host thor {
 hardware ethernet 08:00:27:18:68:BC;
 fixed-address 10.10.1.1;
 option host-name "thor";
}

host heimdall {
 hardware ethernet 08:00:27:18:58:BC;
 fixed-address 10.10.2.1;
 option host-name "heimdall";
}

host valkyrie01 {
 hardware ethernet 08:00:27:18:67:BC;
 fixed-address 10.10.3.1;
 option host-name "valkyrie01";
}

host valkyrie02 {
 hardware ethernet 08:00:27:18:68:BC;
 fixed-address 10.10.3.2;
 option host-name "valkyrie02";
}

}
```

Finally, start and enable the dhcp service:

```
systemctl enable dhcpd
systemctl start dhcpd
```

Note: if needed, you can search for nodes in `10.10.254.0-10.10.254.254` range using the following `nmap` command (install it using `dnf install nmap`):

```
nmap 10.10.254.0-254
```

This is useful to check after a cluster installation that no equipment connected on the network was forgotten in the process.

### DNS server

DNS server provides on the network ip/hostname relation to all hosts:

* ip for corresponding hostname
* hostname for corresponding ip

Install dns server package:

```
dnf install bind
```

Configuration includes 3 files: main configuration file, forward file, and reverse file. (You can separate files into more if you wish, not needed here).

Main configuration file is `/etc/named.conf`, and should be as follow:

```
options {
	listen-on port 53 { 127.0.0.1; 10.10.0.1;};
	listen-on-v6 port 53 { ::1; };
	directory 	"/var/named";
	dump-file 	"/var/named/data/cache_dump.db";
	statistics-file "/var/named/data/named_stats.txt";
	memstatistics-file "/var/named/data/named_mem_stats.txt";
	allow-query     { localhost; 10.10.0.0/16;};

	recursion no;

	dnssec-enable no;
	dnssec-validation no;
	dnssec-lookaside auto;

	/* Path to ISC DLV key */
	bindkeys-file "/etc/named.iscdlv.key";

	managed-keys-directory "/var/named/dynamic";

	pid-file "/run/named/named.pid";
	session-keyfile "/run/named/session.key";
};

logging {
        channel default_debug {
                file "data/named.run";
                severity dynamic;
        };
};

zone "." IN {
	type hint;
	file "named.ca";
};

zone"cluster.local" IN {
type master;
file "forward";
allow-update { none; };
};
zone"10.10.in-addr.arpa" IN {
type master;
file "reverse";
allow-update { none; };
};

include "/etc/named.rfc1912.zones";
include "/etc/named.root.key";
```

Note that the `10.10.in-addr.arpa` is related to first part of our range of ip. If cluster was using for example `172.16.x.x` ip range, then it would have been `16.172.in-addr.arpa`.

Recursion is disabled because no other network access is supposed available.

What contains our names and ip are the two last zone parts. They refer to two files: `forward` and `reverse`. These files are located in `/var/named/`.

First one is `/var/named/forward` with the following content:

```
$TTL 86400
@   IN  SOA     odin.cluster.local. root.cluster.local. (
        2011071001  ;Serial
        3600        ;Refresh
        1800        ;Retry
        604800      ;Expire
        86400       ;Minimum TTL
)
@       IN  NS          odin.cluster.local.
@       IN  A           10.10.0.1

odin               IN  A   10.10.0.1
thor               IN  A   10.10.1.1
heimdall           IN  A   10.10.2.1

valkyrie01         IN  A   10.10.3.1
valkyrie02         IN  A   10.10.3.2
```

Second one is /var/named/reverse:

```
$TTL 86400
@   IN  SOA     odin.cluster.local. root.cluster.local. (
        2011071001  ;Serial
        3600        ;Refresh
        1800        ;Retry
        604800      ;Expire
        86400       ;Minimum TTL
)
@       IN  NS          odin.cluster.local.
@       IN  PTR         cluster.local.

odin      IN  A   10.10.0.1

1.0        IN  PTR         odin.cluster.local.
1.1        IN  PTR         thor.cluster.local.
1.2        IN  PTR         heimdall.cluster.local.

1.3        IN  PTR         valkyrie01.cluster.local.
2.3        IN  PTR         valkyrie02.cluster.local.
```

Set rights on files:

```
chgrp named -R /var/named
chown -v root:named /etc/named.conf
restorecon -rv /var/named
restorecon -v /etc/named.conf
```

And start service:

```
systemctl enable named
systemctl start named
```

The server is up and running. We need to setup client part, even on out `odin`
management node. To do so, edit `/etc/resolv.conf` as following:

```
search cluster.local
nameserver 10.10.0.1
```

Note: you may wish to prevent other scripts (dhclient for example) to edit the file.
If using an ext4 filesystem, it is possble to lock the file using:

```
chattr +i /etc/resolv.conf
```

Use `-i` to unlock it later.

DNS is now ready. You can try to ping `odin` and see if it works.
Stop DNS service and try again to see it does not resolve ip anymore.

### Hosts file

An alternative or in complement to DNS, most system administrators setup an hosts file.

The hosts file allows to resolve locally which ip belongs to which hostname if written inside. For small clusters, it can fully replace the DNS.
On large cluster, most system administrators write inside at least key or critical hostnames and ip.

Lets create our hosts file. Edit `/etc/hosts` file and have it match the following:

```
127.0.0.1   localhost localhost.localdomain localhost4 localhost4.localdomain4
::1         localhost localhost.localdomain localhost6 localhost6.localdomain6

10.10.0.1   odin
10.10.1.1   thor
10.10.2.1   heimdall
10.10.3.1   valkyrie01
10.10.3.2   valkyrie02
```

You can now try to stop DNS server and check that now, even with the DNS stopped, we can resolve and ping `odin`.

### Time server

The time server provides date and time to ensure all nodes/servers are synchronized. This is VERY important, as many authentication tools (munge, ldap, etc.) will not work if cluster is not clock synchronized. If something fail to authenticate, one of the first debug move is to check clock are synchronized.

Install needed packages:

```
dnf install chrony
```

Configuration file is `/etc/chrony.conf`.

We will configure it to allow the local network to query time from this server.
Also, because this is a poor clock source, we use a stratum 12.

The file content should be as bellow:

```
# Define local clock as a bad clock
local stratum 12

# Allow queries from the main network
allow 10.10.0.0/16

# Record the rate at which the system clock gains/losses time.
driftfile /var/lib/chrony/drift

# Allow the system clock to be stepped in the first three updates
# if its offset is larger than 1 second.
makestep 1.0 3

# Enable kernel synchronization of the real-time clock (RTC).
rtcsync

# Specify directory for log files.
logdir /var/log/chrony
```

Then start and enable service:

```
systemctl start chronyd
systemctl enable chornyd
```

### PXE stack

PXE, for Preboot Execution Environment, is a mechanism that allows remote hosts to boot from the network and deploy operating system using configuration and packages from the management node.

It is now time to setup the PXE stack, which is composed of the dhcp server, the http server, the tftp server, the dns server, and the time server.

The http server will distribute the minimal kernel and initramfs for remote Linux booting, the kickstart autoinstall file for remote hosts to know how they should be installed, and the repositories for packages distribution. Some very basic files will be provided using tftp as this is the most compatible PXE protocol.

#### iPXE rom

Install needed packages packages (http server is already installed):

```
dnf install tftp fbtftp fbtftp_server
```

Note that the Centos already embed a very basic tftp server. But it cannot handle an HPC cluster load, and so we replace it by the Facebook python based tftp server.

We then need ipxe files. We could use native syslinux or shim.efi files, but this is just not flexible enough for new generation HPC clusters.
Also, ipxe files provided by Centos are way too old. We will build them ourselves, and include our own init script.

Grab latest ipxe version from git.

To do so, install git:

```
dnf install git
```

Also install needed tools to build C code:

```
dnf groupinstall "Development tools"
```

Then clone the ipxe repository into `/root/ipxe`:

```
mkdir /root/ipxe
cd /root/ipxe
git clone https://github.com/ipxe/ipxe.git .
```

Lets create our ipxe script, that will display a nice ascii art, so we can see it loading, and that will target the file we want.
To create something simple, lets target the file `http://${next-server}/boot.ipxe` at boot.

Create file `/root/ipxe/src/our_script.ipxe` with the following content:

```
#!ipxe

echo
echo . . . . . . . *. . . . .*. . . *. . . . .*
echo . . . . . ***. . . . . **********. . . . . ***
echo . . . .*****. . . . . .**********. . . . . .*****
echo . . .*******. . . . . .**********. . . . . .*******
echo . .**********. . . . .************. . . . .**********
echo . ****************************************************
echo .******************************************************
echo ********************************************************
echo ********************************************************
echo ********************************************************
echo .******************************************************
echo . ********. . . ************************. . . ********
echo . .*******. . . .*. . .*********. . . *. . . .*******
echo . . .******. . . . . . .*******. . . . . . . ******
echo . . . .*****. . . . . . .*****. . . . . . . *****
echo . . . . . ***. . . . . . .***. . . . . . . ***
echo . . . . . . **. . . . . . .*. . . . . . . **
echo

sleep 4

ifconf --configurator dhcp || shell

echo
echo +---------------- System information ----------------+
echo |
echo | hostname:     ${hostname}
echo | platform:     ${platform}
echo | mac:          ${net0/mac}
echo | ip:           ${net0.dhcp/ip:ipv4}
echo | netmask:      ${net0.dhcp/netmask:ipv4}
echo | dhcp-server:  ${net0.dhcp/dhcp-server:ipv4}
echo | gateway:      ${net0.dhcp/gateway:ipv4}
echo | dns-server:   ${net0.dhcp/dns:ipv4}
echo | domain:       ${net0.dhcp/domain:string}
echo | next-server:  ${net0.dhcp/next-server:ipv4}
echo | user-class:   ${user-class:string}
echo |
echo +----------------------------------------------------+
echo

sleep 4

chain http://${next-server}/boot.ipxe || shell
```

Simply put, this script will display a nice ascii art, then sleep 4s, then
request dhcp server for all information (ip, hostname, next-server, etc.),
then display some of the information obtained, then sleep 4s, then chain load to
file `http://${next-server}/boot.ipxe` with `${next-server}` obtained from the DHCP server.
The `|| shell` means: if chaining fail, launch a shell so that sys admin can debug.

Then enter the src directory and build the needed files:

```
cd src
make -j $nb_cores bin-x86_64-efi/ipxe.efi EMBED=our_script.ipxe DEBUG=intel,dhcp,vesafb
make -j $nb_cores bin/undionly.kpxe EMBED=our_script.ipxe DEBUG=intel,dhcp,vesafb
```

And finally copy these files into the `/var/lib/tftpboot/` folder so that tftp server
can provide them to the nodes booting.

```
cp bin-x86_64-efi/ipxe.efi /var/lib/tftpboot/
cp bin/undionly.kpxe /var/lib/tftpboot/
```

#### iPXE chain

Now create file `/var/www/html/boot.ipxe` that will be targeted by each node booting.
There are multiple strategy here. We could simply add basic boot information in this file and consider it done.
But we would quickly face an issue: how to handle different parameters per nodes? Maybe one kind of node need a specific console or kernel parameter that the others do not need.

To solve that, we will simply create a folder `/var/www/html/nodes/` and create one file per node inside.
Then we will ask in the `boot.ipxe` file that each node booting load its own file, related to its hostname provided by the DHCP.

Tip: we will then be able to use file links to create one file per group of nodes if needed.

Create folder:

```
mkdir /var/www/html/nodes/
```

And create `boot.ipxe` file with the following content:

```
#!ipxe
echo Chaining to node dedicated file
chain http://${next-server}/nodes/${hostname}.ipxe || shell
```

Last step for the iPXE chain is to create a file for our group of node, and link
our node to this group.

Create file `/var/www/html/nodes_groups/group_storage.ipxe` with the following content:

>>>>>>>>>>>>>>>>>>>>>

Then, link the node `thor` to this group:

```
cd /var/www/html/nodes/
ln -s ../nodes_groups/group_storage.ipxe thor.ipxe
```

Note: it is important that link are relative: you have to cd into nodes directory,
and create the link from here with a relative path.

To summarize, chain will be the following: `DHCP -> {undionly.kpxe|ipxe.efi} -> boot.ipxe -> thor.ipxe (group_storage.ipxe)` .

#### Kernel, initramfs and kickstart

We now need to provide nodes that boot a kernel, an initramfs, and a kickstart file.

The kernel and the initramfs will load in memory a very minimal Linux operating system.

The kickstart file will provide auto-installation features: what should be installed, how, etc.
We will create one kickstart file per group of nodes.

Copy current kernel and initramfs into http folder:

```
cp /boot
```
>>>>>>>>>>>>>>>>>>>>>>>

To create the kickstart file, we need an ssh public key from our `odin` management
node. Create it:

```
ssh-keygen -N ""
```
>>>>>>>>>>>>>>>>

And get the content of the public key, we will use it just bellow to generate the
kickstart file.

Now we need an sha512 password hash. Generate one using the following commande:

>>>>>>>>>>>>>>>

And keep it somewhere, we will use it just bellow to generate the kickstart file.

Then, create the kickstart file `/var/www/html/nodes_groups/group_storage.kickstart.cfg`
dedicated to storage group, with the following minimal content:

>>>>>>>>>>>>>>>>>>>>>>>

Notes:

* The ssh public key here will allow us to ssh on the remote hosts without having to provide a password.
* We install only the absolute minimal operating system. It is strongly recommended to do the minimal amount of tasks during a kickstart.
* Important note: the time zone parameter is very important. Choose here the same than the one choose when installing the OS of `odin`. If you don’t know the one used, it can be found using: `ll /etc/localtime`
* Ensure also your keyboard type is correct.
* For compatibility purpose, this kickstart example does not specify which hard drive disk to use, but only locate first one and use it. Tune it later according to your needs.

Now, ensure all services are started:

```
systemctl start httpd
systemctl enable httpd
systemctl start fbtftp_server
systemctl enable fbtftp_server
```

We can proceed with the boot of `thor` node, and then the other nodes.

## Other nodes installation

### Boot over PXE

Open 2 shell on `odin`. In the first one, launch watch logs of dhcp and tftp server using:

```
journalctl -u dhcpd -u fbtftp_server -f
```

In the second one, watch http server logs using:

```
tail -f /var/log/httpd/*
```

Now, boot the `thor` node over PXE, and watch it deploy. Also watch the logs to
understand all steps.

Once the operating system is installed, and the node has rebooted, have it boot
over disk, and ensure operating system is booted before proceeding.

Repeat this operation to deploy each nodes of your cluster.

### Configure client side

Now that other nodes are deployed and reachable over ssh, it is time to configure client side on them.

#### Set hostname

Set hostname on each nodes using the following command (tuned for each nodes of course):

```
hostnamectl set-hostname thor.cluster.local
```

#### Configure repositories

You need the nodes be able to grab packages from `odin`.

On each client node, backup current repositories, and clean them:

```
cp -a /etc/yum.repos.d/ /root/yum.repos.d.backup
rm -f /etc/yum.repos.d/*.repo
```

Now create file `/etc/yum.repos.d/os.repo` with the following content:

```
[BaseOS]
name=BaseOS
baseurl=http://10.10.0.1/repositories/centos/8/x86_64/os/BaseOS
gpgcheck=0
enabled=1

[AppStream]
name=AppStream
baseurl=http://10.10.0.1/repositories/centos/8/x86_64/os/AppStream
gpgcheck=0
enabled=1
```

And create file `/etc/yum.repos.d/extra.repo` with the following content:

```
[Extra]
name=Extra
baseurl=http://10.10.0.1/repositories/centos/8/x86_64/extra
gpgcheck=0
enabled=1
```

Now clean cache, and ensure you can reach the repositories and download packages (try to install wget for example):

```
dnf clean all
dnf update
dnf install wget -y
```

#### DNS client

On each client node, set `odin` as default DNS server, by updating `/etc/resolv.conf` file with the following content:

```
search cluster.local
nameserver 10.10.0.1
```

You can also simply upload the file from `odin` on clients, using scp.

#### Hosts file

On each client, edit `/etc/hosts` file and have it match the following:

```
127.0.0.1   localhost localhost.localdomain localhost4 localhost4.localdomain4
::1         localhost localhost.localdomain localhost6 localhost6.localdomain6

10.10.0.1   odin
10.10.1.1   thor
10.10.2.1   heimdall
10.10.3.1   valkyrie01
10.10.3.2   valkyrie02
```

You can also simply upload the file from `odin` on clients, using scp.

#### Time client

On each client, ensure time server is `odin` sp that our cluster is time synchronised.

Install needed packages:

```
dnf install chrony
```

Configuration file is `/etc/chrony.conf`. The file content should be as bellow:

```
# Source server to bind to
server 10.10.0.1 iburst

# Record the rate at which the system clock gains/losses time.
driftfile /var/lib/chrony/drift

# Allow the system clock to be stepped in the first three updates
# if its offset is larger than 1 second.
makestep 1.0 3

# Enable kernel synchronization of the real-time clock (RTC).
rtcsync

# Specify directory for log files.
logdir /var/log/chrony
```

Then start and enable service:

```
systemctl start chronyd
systemctl enable chornyd
```
