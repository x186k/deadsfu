


VERSION := $(shell git describe  --abbrev=0 --tags)

# lets just skip building a proper dependency tree
# thus, always build

all: build-push




build-push:
	@test -n "$(VERSION)"  # $$VERSION
	docker build -t x186k/deadsfu:${VERSION} --build-arg VERSION=${VERSION} .
	docker push x186k/deadsfu:${VERSION}



	








