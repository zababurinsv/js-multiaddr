deps:
	@npm install
test: deps
	@npm test
.PHONY: test deps
