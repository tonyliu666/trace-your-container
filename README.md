## Trace Your Container

Before moving on, please consider giving us a GitHub star ⭐️. Thank you!

#### About Trace Your Container

Trace Your Container is an observability tool that helps you understand the details happened under the docker container

It is leveraging eBPF technology to expose the information about the events occuring in your docker engine, eg: create a container, delete a container, remove a file and collect the system calls of the specific container. 

#### Quickstart

* Directly use the docker image: 
> docker run -it --rm  --privileged --ulimit nproc=4096 -v /lib/modules:/lib/modules:ro -v /etc/localtime:/etc/localtime:ro --pid=host --cgroupns=host  tonyliu666/ebpf-for-mac:v1

**parameters explaination** : 
* --privileged: elevated privileges to perform tasks that involve accessing kernel tracing features
* --ulimit: Due to limitation of sizes of ebpf hashOfMap, I would like to set the process limits of the running container
* /lib/modules: share the linux headers on your host with the container so that it can leverage the header files in kernel. 
* --pid=host: share pid namespace with your host
* --cgroupns=host: share the namespaces with your host


* After running the above command: 
1. cd app 
2. make docker