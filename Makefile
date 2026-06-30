PYTHON ?= python3
BUILD_DIR ?= build
DOCS_DIR := $(BUILD_DIR)/docs
HTML_DIR := $(DOCS_DIR)/html
PRMINXML_SOURCES := $(wildcard prminxml/*.xml)

.PHONY: all dist docs lint-docs clean

all: dist docs

dist:
	$(PYTHON) -m build

lint-docs:
	@for file in $(PRMINXML_SOURCES); do \
		echo "Linting $$file"; \
		riscos-prminxml -f lint "$$file"; \
	done

docs: lint-docs
	@mkdir -p "$(HTML_DIR)"
	@for file in $(PRMINXML_SOURCES); do \
		echo "Building $$file"; \
		riscos-prminxml -f html5+xml -O "$(HTML_DIR)" "$$file"; \
	done

clean:
	rm -rf build dist *.egg-info

