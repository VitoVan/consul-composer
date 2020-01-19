package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/events"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/api/types/network"
	docker "github.com/docker/docker/client"
	"github.com/docker/go-connections/nat"
	consul "github.com/hashicorp/consul/api"
)

type Fuck struct {
	Shit                   string `json:",omitempty"`
	DestinationServiceName string `json:",omitempty"`
	DestinationServiceID   string `json:",omitempty"`
}

func PrintJson(data ...interface{}) {
	list := make([]interface{}, len(data))
	for index, item := range data {
		jsonBytes, _ := json.MarshalIndent(item, "", "  ")
		list[index] = string(jsonBytes)
	}
	log.Output(2, fmt.Sprintln(list...))
}

func GetFirstPort(ports nat.PortMap) (port int) {
	if ports != nil {
		for key, _ := range ports {
			keys := strings.Split(string(key), "/")
			if keys[1] == "tcp" {
				port, _ = strconv.Atoi(keys[0])
				return port
			}
		}
	}
	return
}

func GetFirstIP(networks map[string]*network.EndpointSettings) (ip string) {
	if networks != nil {
		for _, val := range networks {
			if val.IPAddress != "" {
				return val.IPAddress
			}
		}
	}
	return
}

func GetServiceInfo(container types.ContainerJSON) (name string, id string, ip string, port int) {
	name = container.Config.Labels["consul.hashicorp.com/connect-service"]
	port, _ = strconv.Atoi(container.Config.Labels["consul.hashicorp.com/connect-service-port"])
	ip = GetFirstIP(container.NetworkSettings.Networks)
	id = strings.ReplaceAll(container.Name, "/", "")
	if port == 0 {
		port = GetFirstPort(container.NetworkSettings.Ports)
	}
	if len(name) == 0 {
		name = container.Config.Labels["com.docker.compose.service"]
	}
	if len(name) == 0 {
		name = id
	}
	return
}

// Register service to Consul when a Container start
func register(ctn types.ContainerJSON, dockerClient *docker.Client, consulClient *consul.Client, ctx context.Context) {
	// log.Println(ctn.Config.Labels)

	name, id, ip, port := GetServiceInfo(ctn)

	log.Println("\n-")
	log.Println("Registering: ", id)

	var connectInject bool = true
	if ctn.Config.Labels["consul.hashicorp.com/connect-inject"] == "false" {
		connectInject = false
	}
	// Define Sidecar Proxy
	var connect *consul.AgentServiceConnect
	if connectInject {
		connect = &consul.AgentServiceConnect{
			SidecarService: &consul.AgentServiceRegistration{
				Port: 9999,
				Checks: consul.AgentServiceChecks{
					&consul.AgentServiceCheck{
						Name:     "Basic Proxy TCP Check",
						TCP:      fmt.Sprintf("%s:%d", ip, 9999),
						Interval: "5s",
					},
					&consul.AgentServiceCheck{
						Name:         "Proxy Alias TCP Check",
						AliasService: id,
					},
				},
				Proxy: &consul.AgentServiceConnectProxyConfig{},
			},
		}
	}

	// Register Service
	err := consulClient.Agent().ServiceRegister(&consul.AgentServiceRegistration{
		ID:      id,
		Name:    name,
		Address: ip,
		Port:    port,
		Check: &consul.AgentServiceCheck{
			Name:     "Basic TCP Check",
			TCP:      fmt.Sprintf("%s:%d", ip, port),
			Interval: "5s",
		},
		Connect: connect,
	})
	if err != nil {
		log.Println("Service Register Failed:", err)
	}

	sidecarID := id + "-sidecar-proxy"
	// Start Sidecar Container
	ctnBody, err := dockerClient.ContainerCreate(ctx, &container.Config{
		Image: "vitovan/consul-envoy:1.6.2",
		Env:   os.Environ(),
		Cmd:   []string{"-sidecar-for", id},
	}, &container.HostConfig{
		NetworkMode: container.NetworkMode(fmt.Sprintf("container:%s", id)),
		// Sidecar Container will be removed when stopped
		AutoRemove: true,
	}, nil, sidecarID)

	if err != nil {
		log.Println("Sidecar Creation Failed:", err)
	} else {
		log.Println("Sidecar Created:", sidecarID)
	}

	err = dockerClient.ContainerStart(ctx, ctnBody.ID, types.ContainerStartOptions{})

	if err != nil {
		log.Println("Sidecar Start Failed:", err)
	} else {
		log.Println("Sidecar Started:", sidecarID)
	}

	log.Println("Service Register Finished:", id)
}

// Deregister Service from Consul when Container die
func deregister(container types.ContainerJSON, dockerClient *docker.Client, consulClient *consul.Client, ctx context.Context) {
	_, id, _, _ := GetServiceInfo(container)
	log.Println("\n-")
	log.Println("Deregistering:", id)
	err := consulClient.Agent().ServiceDeregister(id)
	if err != nil {
		log.Println("Deregister Failed", err)
	} else {
		log.Println("Deregistered:", id)
	}

	if !strings.Contains(container.Name, "sidecar-proxy") {
		err = dockerClient.ContainerRemove(ctx, container.ID, types.ContainerRemoveOptions{})
		if err != nil {
			log.Println("Container Deletion Failed", err)
		} else {
			log.Println("Container Deleted:", container.Name)
		}

		sidecarID := id + "-sidecar-proxy"
		ctns, err := dockerClient.ContainerList(ctx, types.ContainerListOptions{Filters: filters.NewArgs(filters.KeyValuePair{
			Key:   "name",
			Value: sidecarID,
		})})

		timeout := 10 * time.Second
		if err == nil && len(ctns) > 0 {
			err = dockerClient.ContainerStop(ctx, ctns[0].ID, &timeout)
			if err != nil {
				log.Println("Sidecar Container Failed to Stop", err)
			} else {
				log.Println("Sidecar Container Stopped:", sidecarID)
			}
		}
	}

	log.Println("Service Deregistration Finished:", id)
}

func insertHooks(dockerClient *docker.Client, consulClient *consul.Client, ctx context.Context) {
	events, errs := dockerClient.Events(ctx, types.EventsOptions{
		Filters: filters.NewArgs(filters.KeyValuePair{
			Key:   "type",
			Value: events.ContainerEventType,
		}),
	})
	for {
		select {
		case err := <-errs:
			if err != nil && err != io.EOF {
				log.Println(err)
			}
			return
		case e := <-events:
			switch status := e.Status; status {
			case "start":
				container, err := dockerClient.ContainerInspect(ctx, e.ID)
				if err == nil && !strings.Contains(container.Name, "sidecar-proxy") {
					register(container, dockerClient, consulClient, ctx)
				}
			case "die":
				container, err := dockerClient.ContainerInspect(ctx, e.ID)
				if err == nil {
					deregister(container, dockerClient, consulClient, ctx)
				}
			}
		}
	}
}

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	dockerClient, err := docker.NewClientWithOpts(docker.FromEnv)
	if err != nil {
		panic(err)
	}
	ctx := context.Background()
	dockerClient.NegotiateAPIVersion(ctx)
	consulClient, err := consul.NewClient(consul.DefaultConfig())
	if err != nil {
		panic(err)
	}
	log.Println("Start Listen ......")
	insertHooks(dockerClient, consulClient, ctx)
}
