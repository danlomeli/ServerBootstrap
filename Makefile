TAG?=latest
SRC_VERSION?=20250715
IMAGE_NAME?=ubuntu-bootstrap
IMAGE_PATH:=ghcr.io/danlomeli/fp-docker/$(IMAGE_NAME)

build:
	@echo "Building $(IMAGE_PATH)-$(SRC_VERSION):$(TAG)..."
	@docker build --build-arg TARGETARCH=amd64 -t $(IMAGE_PATH)-$(SRC_VERSION):$(TAG) .

build-nocache:
	@echo "Building $(IMAGE_PATH)-$(SRC_VERSION):$(TAG) without cache..."
	@docker build --no-cache --build-arg TARGETARCH=amd64 -t $(IMAGE_PATH)-$(SRC_VERSION):$(TAG) .

push:
	@echo "Pushing $(IMAGE_PATH)-$(SRC_VERSION):$(TAG)..."
	@echo $$GITHUB_READ_WRITE_PACKAGES_ONLY_PAT | docker login ghcr.io -u PAT --password-stdin && docker push $(IMAGE_PATH)-$(SRC_VERSION):$(TAG)

pull:
	@echo "Pulling $(IMAGE_PATH)-$(SRC_VERSION):$(TAG)..."
	@echo $$GITHUB_READ_WRITE_PACKAGES_ONLY_PAT | docker login ghcr.io -u PAT --password-stdin && docker pull $(IMAGE_PATH)-$(SRC_VERSION):$(TAG)

run:
	@echo "Running $(IMAGE_PATH)-$(SRC_VERSION):$(TAG)..."
	@docker run -it --name ubuntu-bootstrap --privileged -v /sys/fs/cgroup:/sys/fs/cgroup:ro $(IMAGE_PATH)-$(SRC_VERSION):$(TAG)

run-local:
	@echo "Running locally built image..."
	@docker run -it --name ubuntu-bootstrap --privileged -v /sys/fs/cgroup:/sys/fs/cgroup:ro $(IMAGE_PATH)-$(SRC_VERSION):$(TAG)

clean:
	@echo "Cleaning up containers and images..."
	@docker rm -f ubuntu-bootstrap 2>/dev/null || true
	@docker rmi $(IMAGE_PATH)-$(SRC_VERSION):$(TAG) 2>/dev/null || true

shell:
	@echo "Connecting to running container..."
	@docker exec -it ubuntu-bootstrap /bin/bash

.PHONY: build build-nocache push pull run run-local clean shell