PLATFORMS := linux/amd64 darwin/amd64 windows/amd64 linux/arm/7

temp = $(subst /, ,$@)
os = $(word 1, $(temp))
arch = $(word 2, $(temp))
archversion = $(word 3, $(temp))
revision := $(shell git rev-parse --short HEAD)

build_dir:
	mkdir -p build

clean:
	rm build/* 2> /dev/null || true

release: clean $(PLATFORMS)

$(PLATFORMS):
	GOOS=$(os) GOARCH=$(arch) go build -ldflags "-X 'github.com/maxlaverse/synocrypto/cli/synocrypto/cmd.GitRevision=$(revision)'" -o 'build/synocrypto' .
	cd build; \
	  tar -cvf synocrypto-$(os)-$(arch)$(archversion).tar synocrypto;\
	  gzip synocrypto-$(os)-$(arch)$(archversion).tar
	rm build/synocrypto