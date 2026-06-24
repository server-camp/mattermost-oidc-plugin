# Mattermost / Mostlymatter OIDC Plugin Makefile
PLUGIN_ID  ?= mattermost-oidc
PLUGIN_VERSION ?= $(shell python3 -c "import json; print(json.load(open('plugin.json'))['version'])")
BUNDLE_NAME ?= $(PLUGIN_ID)-$(PLUGIN_VERSION).tar.gz

# Build targets
GO          ?= go
GOFLAGS     ?= -mod=readonly
CGO_ENABLED ?= 0

# Server platforms
SERVER_PLATFORMS := linux/amd64 linux/arm64 darwin/amd64 darwin/arm64

.PHONY: all server webapp bundle clean deploy test lint

all: bundle

## Build the Go server plugin binaries for all platforms
server:
	@echo "Building server plugin..."
	@cd server && \
	for platform in $(SERVER_PLATFORMS); do \
		os=$$(echo $$platform | cut -d'/' -f1); \
		arch=$$(echo $$platform | cut -d'/' -f2); \
		echo "  Building for $$os/$$arch..."; \
		CGO_ENABLED=$(CGO_ENABLED) GOOS=$$os GOARCH=$$arch \
			$(GO) build $(GOFLAGS) -trimpath -ldflags="-s -w" -o dist/plugin-$$os-$$arch ./...; \
	done
	@echo "Server build complete."

## Build the webapp bundle
webapp:
	@echo "Building webapp..."
	@cd webapp && npm install && npm run build
	@echo "Webapp build complete."

## Create the plugin bundle (.tar.gz)
bundle: server webapp
	@echo "Creating plugin bundle..."
	@rm -rf dist
	@mkdir -p dist/$(PLUGIN_ID)
	@cp plugin.json dist/$(PLUGIN_ID)/
	@mkdir -p dist/$(PLUGIN_ID)/server/dist
	@cp server/dist/* dist/$(PLUGIN_ID)/server/dist/
	@mkdir -p dist/$(PLUGIN_ID)/webapp/dist
	@cp webapp/dist/main.js dist/$(PLUGIN_ID)/webapp/dist/
	@mkdir -p dist/$(PLUGIN_ID)/assets
	@if [ -d assets ]; then cp -r assets/* dist/$(PLUGIN_ID)/assets/ 2>/dev/null || true; fi
	@cd dist && tar -czf $(BUNDLE_NAME) $(PLUGIN_ID)
	@echo "Plugin bundle created: dist/$(BUNDLE_NAME)"

## Deploy to a running Mattermost / Mostlymatter instance (requires MM_SERVICESETTINGS_SITEURL and MM_ADMIN_TOKEN)
deploy: bundle
	@echo "Deploying plugin..."
	@curl -s -f \
		-H "Authorization: Bearer $(MM_ADMIN_TOKEN)" \
		-F "plugin=@dist/$(BUNDLE_NAME)" \
		-F "force=true" \
		$(MM_SERVICESETTINGS_SITEURL)/api/v4/plugins
	@echo "\nPlugin deployed."

## Run Go tests with race detection
test:
	@echo "Running server tests..."
	@cd server && $(GO) test ./... -v -race -count=1
	@echo "Tests complete."

## Run Go linting (requires golangci-lint)
lint:
	@echo "Running linter..."
	@cd server && golangci-lint run ./...
	@echo "Lint complete."

## Clean build artifacts
clean:
	@rm -rf dist
	@rm -rf server/dist
	@rm -rf webapp/dist
	@rm -rf webapp/node_modules
	@echo "Clean complete."

## Print help
help:
	@echo "Mattermost / Mostlymatter OIDC Plugin Build System"
	@echo ""
	@echo "Targets:"
	@echo "  all      - Build the complete plugin bundle (default)"
	@echo "  server   - Build server binaries for all platforms"
	@echo "  webapp   - Build the webapp bundle"
	@echo "  bundle   - Create the .tar.gz plugin bundle"
	@echo "  test     - Run Go tests with race detection"
	@echo "  lint     - Run Go linting (requires golangci-lint)"
	@echo "  deploy   - Deploy to a running Mattermost / Mostlymatter instance"
	@echo "  clean    - Remove all build artifacts"
	@echo "  help     - Show this help"
	@echo ""
	@echo "Environment variables:"
	@echo "  MM_SERVICESETTINGS_SITEURL - Mattermost / Mostlymatter server URL (for deploy)"
	@echo "  MM_ADMIN_TOKEN             - Admin auth token (for deploy)"
