# Before building the docker

Since it's not on docker hub because blablabla, you have to :
* Edit your [config.toml](https://github.com/future-architect/vuls#step6-config) to match your infrastructure
* generate a keypair dedicated to this docker : ```ssh-keygen -t rsa -b 4096 -C "your_email@example.com"```
  * it's **highly** recommanded to use a restrained `authorized_keys` files with this key to be sure that it will be only usable from a single IP (after all it's a root executed software) : ```from="1.2.3.4,1.2.3.5" ssh-rsa [...] your_email@example.com```
* Deploy your ssh key on the targetted machines
