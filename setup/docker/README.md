# Vuls on Docker

## What's Vuls-On-Docker

- This is a dockernized-Vuls with vulsrepo UI in it.
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
	
4. git clone vuls
	```
	mkdir work
	cd work
	git clone https://github.com/future-architect/vuls.git
	cd vuls/setup/docker
	```



## Start A Vuls Container

- Execute the following command to build and run a Vuls Container

	```
	$ docker-compose up -d
	```

## Setting up Vuls

1. Locate ssh-keys of targer servers in (vuls/docker/conf/)
2. Create and ajust config.toml(vuls/docker/conf/config.toml) to your environment
	
	```
	[servers]

  	[servers.172-31-4-82]
  	host        = "172.31.4.82"
  	user        = "ec2-user"
  	keyPath     = "conf/id_rsa"
	```

## Fetch Vulnerability database

- Fetch Vulnerability database from NVD
	```
	$ docker exec -t vuls scripts/fetch_nvd_all.sh
	```

## Scan servers with Vuls-On-Docker

- Use the embedded script to scan servers for vulsrepo(or run whatever with docker exec)

	```
	$ docker exec -t vuls vuls prepare -config=conf/config.toml
	$ docker exec -t vuls scripts/scan_for_vulsrepo.sh
	```

## See the results in a browser 

```
http://${Vuls_Host}/vulsrepo/
```

# Update modules

- update vuls, go-cve-dictionary, vulsrepo
	```
	$ docker exec -t vuls scripts/update_modules.sh
	```

# Update Vulnerability database

- Fetch Vulnerability database from NVD
	```
	$ docker exec -t vuls scripts/fetch_nvd_last2y.sh
	```
