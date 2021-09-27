


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
	docker build -t x186k/deadsfu:$(VER) --build-arg VERSION=$(VER) .
	docker push x186k/deadsfu:$(VER)



	

PLATFORMS := linux/amd64 windows/amd64 darwin/amd64 darwin/arm64 linux/arm64

temp = $(subst /, ,$@)
os = $(word 1, $(temp))
arch = $(word 2, $(temp))
binname = dist/$(os)-$(arch)
bintarname = $(binname).tar.gz
goflags = -X main.Version="$(VER)"

binbuild: cleardist $(PLATFORMS)
	test "$$(git describe --tags)" = "$(VER)"
	gh release create $(VER) --notes "" ./dist/*

cleardist:
	rm -rf dist
	mkdir dist

$(PLATFORMS):
	GOOS=$(os) GOARCH=$(arch) go build -o $(binname) $(goflags) .
	tar -czf $(bintarname) $(binname)
	rm $(binname)
	md5 -q $(bintarname) >$(bintarname).md5

.PHONY: release $(PLATFORMS)




