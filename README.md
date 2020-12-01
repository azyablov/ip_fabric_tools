# IP Fabric Tools
IP fabric tools for 210 WBXes.
The aim is to have simple set of utilities for rapid DC fabric healh checking
  

## Currently supported features

* Availability checking
* Software version verification
* NTP sync state checking
* L3 interface state and IP@ availability checking directly from source host/container or from proxy WBX in which is part of the IP fabric
* LLDP neighbours information check per Network interface


## Usage

* Do `got clone https://github.com/azyablov/ip_fabric_tools.git`
or unpack repo tarball if you are working in isolated environment without an access to Internet.

* Go to the root rectory of cloned repo `cd ip_fabric_tools`

* Create log and reports directory
```shell script
./lrp.sh
```

* Then create your JSON file with node param in `nodes` diretory in accordance with [sample file](nodes/input_sample.json)

* If you are working in isolated environment, then load your docker image (which you can save by using `docker save` on any docker host): 
```shell script
docker image load --input output/ip_fabric_tools_l3topo.tar.gz
```
* Or pull from docker hub
```shell script
docker image rm azyablov/ip_fabric_tools_l3topo
```

Finally, run your container

```shell script
docker-compose up
```

In `l3topo.log` you can find neccessary to troubleshoot.
To change log level you should specify CLI argument`--log <YOUR_LOG_LEVEL>` in docker compose file:
```yaml
command: ["-n", "nodes.json", "--log", "debug", "-r", "reports"]
```
Reports for fabric switches pushed into `reports` directory.

## Input JSON file format 

TBD