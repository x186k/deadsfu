


VER := $(shell git describe  --abbrev=0 --tags)

# lets just skip building a proper dependency tree
# thus, always build




# tag examples
# git tag -a v1.4 -m "my version 1.4"

all: build-push




build-push:
	# you CANNOT do a build with dirty directory
	@status=$$(git status --porcelain); \
	if [ ! -z "$${status}" ]; \
	then \
		echo "Error - working directory is dirty. Commit those changes!"; \
		exit 1; \
	fi
	
	@test -n "$(VER)"  # $$VER
	git tag -m "" -a ${VER}
	# if no tag specified, it defaults to latest:, SO DONT ADD :${VER}
	docker build -t x186k/deadsfu --build-arg VERSION=${VER} .
	docker push x186k/deadsfu



	








