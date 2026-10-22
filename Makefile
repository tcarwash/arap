.PHONY: test race vet build desktop vectors cddl package keyserver-smoke confidence-demo pixelqso-demo signing-demo enrollment-demo

test:
	go test ./...

race:
	go test -race ./...

vet:
	go vet ./...

build:
	mkdir -p bin
	go build -trimpath -o bin/arap ./cmd/arap
	go build -trimpath -o bin/arap-keyserver ./cmd/arap-keyserver

desktop: build
	PATH="$(CURDIR)/bin:$$PATH" python3 desktop/arap_desktop.py

vectors:
	scripts/check-vectors.sh

cddl:
	scripts/check-cddl.sh

package:
	@if [ -n "$(TARGET)" ]; then scripts/package-desktop.sh "$(TARGET)"; else scripts/package-desktop.sh; fi

keyserver-smoke: build
	python3 scripts/check-keyserver-compose.py

confidence-demo:
	bash scripts/confidence-demo.sh

pixelqso-demo:
	bash scripts/pixelqso-demo.sh

signing-demo: confidence-demo pixelqso-demo

enrollment-demo:
	bash scripts/enrollment-demo.sh
