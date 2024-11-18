## Trace Your Container

Before moving on, please consider giving us a GitHub star ⭐️. Thank you!

#### About Trace Your Container

Trace Your Container is an observability tool that helps you understand the details happened under the docker container

It is leveraging eBPF technology to expose the information about the events occuring in your docker engine, eg: create a container, delete a container, remove a file and collect the system calls of the specific container. 

Currently, Only supports for the kernel version **6.8.0-48-generic**. So if your kernel version is not this one, you could consider about installing Virtual Machine. I have provided a simple guildance for you. 

#### Quickstart
* Install VM: (you can download the vagrant CLI at first: https://developer.hashicorp.com/vagrant/install  and Virtualbox)
```bash
vagrant up
```

* Directly use the docker image: 
```bash
docker run -it --rm  --privileged --ulimit nproc=4096 -v /lib/modules:/lib/modules:ro -v /etc/localtime:/etc/localtime:ro -v /sys/fs/bpf:/sys/fs/bpf --pid=host --cgroupns=host  tonyliu666/ebpf-for-mac:v1
```
* or you can build the image: 
```bash
docker build -t ebpf-program .
```
Then: 
```bash
docker run -it --rm  --privileged --ulimit nproc=4096 -v /lib/modules:/lib/modules:ro -v /etc/localtime:/etc/localtime:ro --pid=host --cgroupns=host  ebpf-program
```
In the ebpf-program container: 
```bash
cd app 
```
```bash
make docker
```

Then enjoy it! 

**parameters explaination** : 
* --privileged: elevated privileges to perform tasks that involve accessing kernel tracing features
* --ulimit: Due to limitation of sizes of ebpf hashOfMap, I would like to set the process limits of the running container
* /lib/modules: share the linux headers on your host with the container so that it can leverage the header files in kernel. 
* --pid=host: share pid namespace with your host
* --cgroupns=host: share the namespaces with your host

**Demo Video**: 

#### Contributing
Welcome any who has some interests on my project to contribute your codes. 