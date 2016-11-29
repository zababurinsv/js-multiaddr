deps:
	@npm install
test: deps
	@npm run test:node
.PHONY: test deps
