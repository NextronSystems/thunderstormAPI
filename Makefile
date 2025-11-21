.PHONY: help venv test lint release release-test

VENV_NAME   = venv
VENV_PYTHON = $(VENV_NAME)/bin/python
VENV_STAMP  = $(VENV_NAME)/.venv-stamp

help:
	@echo "make venv"
	@echo "       create local virtualenv"
	@echo "make test"
	@echo "       run tests"
	@echo "make lint"
	@echo "       run pylint and mypy"

venv: $(VENV_STAMP)

$(VENV_STAMP): requirements.txt
	python3 -m venv $(VENV_NAME)
	$(VENV_PYTHON) -m pip install -U pip
	$(VENV_PYTHON) -m pip install -r requirements.txt
	touch $(VENV_STAMP)

test: venv
	$(VENV_PYTHON) -m pytest -v

lint: venv
	$(VENV_PYTHON) -m pylint thunderstormAPI thunderstorm_cli.py
	$(VENV_PYTHON) -m mypy thunderstormAPI thunderstorm_cli.py

release: venv
	rm -rf ./dist/*
	$(VENV_PYTHON) -m pip install --upgrade setuptools wheel twine
	$(VENV_PYTHON) setup.py sdist bdist_wheel
	$(VENV_PYTHON) -m twine check dist/*
	$(VENV_PYTHON) -m twine upload dist/*

release-test: venv
	rm -rf ./dist/*
	$(VENV_PYTHON) -m pip install --upgrade setuptools wheel twine
	$(VENV_PYTHON) setup.py sdist bdist_wheel
	$(VENV_PYTHON) -m twine check dist/*
	$(VENV_PYTHON) -m twine upload --repository-url https://test.pypi.org/legacy/ dist/*