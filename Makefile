build:
	go build -mod=vendor app.go
run:
	go run -mod=vendor app.go
deps:
	go mod vendor
docker:
	docker run \
	-e CONSUL_GRPC_ADDR=consul:8502  \
	-e CONSUL_HTTP_ADDR=http://consul:8500 \
	--net ${DOCKER_NETWORK}  \
	-v /var/run/docker.sock:/var/run/docker.sock \
	--rm -w /work -it -v `pwd`:/work  golang make run
