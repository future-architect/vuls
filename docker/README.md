# Vuls on Docker

## Table of Contens

- [What's Vuls-On-Docker?](#whats-vuls-on-docker)
- [Server Setup](#setting-up-your-machine)
	- Install Docker
	- Instal Docker Compose
- [Vuls Setup](#setting-up-vuls)
	- Locate a appropriate ssh-key
	- Edit toml
- [Start A Vuls Container](#start-a-vuls-container)
- [Scan servers with Vuls-On-Docker](#scan-servers-with-vuls-on-docker)
- [See the results in a browser](#see-the-results-in-a-browser)

## What's Vuls-On-Docker

- This is a dockernized-Vuls with DockerRepo UI in it.
- It's designed to reduce the cost of installation and the dependencies that vuls requires.
- You can run install and run Vuls on your machine with only a few commands.
- The result can be viewed with a browser

## Setting up your machine
	
1. [Install Docker](https://docs.docker.com/engine/installation/)
2. [Install Docker-Compose](https://docs.docker.com/compose/install/)
3. Make sure that you can run the following commands before you move on.

	```
	$ docker version
	$ docker-compose version
	```

4. Create a working directory for Vuls

	```
	mkdir work
	cd work
	git clone https://github.com/hikachan/vuls.git
	cd vuls/docker
	```

## Setting up Vuls

1. Locate a ssh-key in (vuls/docker/conf/id_rsa)
2. Create and ajust config.toml(vuls/docker/conf/config.toml) to your environment
	
	```
	[servers]

  	[servers.172-31-4-82]
  	host        = "172.31.4.82"
  	user        = "ec2-user"
  	keyPath     = "/opt/vuls/conf/id_rsa"
  	containers = ["container_name_a", "4aa37a8b63b9"]
	```
	
## Start A Vuls Container

- Execute the following command to build and run a Vuls Container

	``
	docker-compose up -d
	`` 

## Scan servers with Vuls-On-Docker

- Use the embedded script to scan servers for vulsrepo(or run whatever with docker exec)

	```
	docker exec -t vuls vuls prepare -config=conf/config.toml
	docker exec -t vuls scripts/scan_for_vulsrepo.sh
	```

## See the results in a browser 

```
http://${Vuls_Host}/vulsrepo/
```
