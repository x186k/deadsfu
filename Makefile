


# VER := $(shell git describe  --abbrev=0 --tags)

# lets just skip building a proper dependency tree
# thus, always build




# tag examples
# git tag -a v1.4 -m "my version 1.4"

all:


release: dockerbuild binbuild


# implies push
dockerbuild:
	test "$$(git describe --tags)" = "$(VER)"
	# if no tag specified, it defaults to latest:, SO DONT ADD :$(VER)
	docker build -t deadsfu --build-arg VERSION=$(VER) .
	docker image tag deadsfu x186k/deadsfu:latest
	docker image tag deadsfu x186k/deadsfu:$(VER)
	docker image push --all-tags x186k/deadsfu

	

PLATFORMS := linux/amd64 windows/amd64 darwin/amd64 darwin/arm64 linux/arm64

temp = $(subst /, ,$@)
os = $(word 1, $(temp))
arch = $(word 2, $(temp))
ext = $(if $(findstring windows,$(os)),.exe)

binname = deadsfu$(ext)
bintarname = dist/deadsfu-$(os)-$(arch).tar.gz
goflags = -ldflags "-X main.Version=$(VER)"

binbuild: cleardist $(PLATFORMS)
	test "$$(git describe --tags)" = "$(VER)"
	gh release upload $(VER) --clobber ./dist/*

cleardist:
	rm -rf dist
	mkdir dist

$(PLATFORMS):
	GOOS=$(os) GOARCH=$(arch) go build -o $(binname) $(goflags) .
	tar -czf $(bintarname) $(binname)
	rm $(binname)
	openssl md5 -r $(bintarname) | sed 's/ .*//g'  >$(bintarname).md5

.PHONY: release $(PLATFORMS)




