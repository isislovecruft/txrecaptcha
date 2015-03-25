
.PHONY: install test
.DEFAULT: install test

TRIAL:=$(shell which trial)
VERSION:=$(shell git describe)

all:
	python setup.py build

test:
	$(TRIAL) ./test/test_*.py

pep8:
	find txrecaptcha/*.py | xargs pep8

pylint:
	pylint --rcfile=./.pylintrc ./txrecaptcha/

pyflakes:
	pyflakes ./txrecaptcha/

install:
	TXRECAPTCHA_INSTALL_DEPENDENCIES=0 python setup.py install --record installed-files.txt

force-install:
	TXRECAPTCHA_INSTALL_DEPENDENCIES=0 python setup.py install --force --record installed-files.txt

uninstall:
	touch installed-files.txt
	cat installed-files.txt | xargs rm -rf
	rm installed-files.txt

reinstall: uninstall force-install

docs:
	python setup.py build_sphinx --version "$(VERSION)"
	cd build/sphinx/html && \
		zip -r ../"$(VERSION)"-docs.zip ./ && \
		echo "Your package documents are in build/sphinx/$(VERSION)-docs.zip"

clean-docs:
	-rm -rf build/sphinx

clean-coverage-html:
	-rm -rf coverage-html

clean: clean-docs clean-coverage-html
	-rm -rf build
	-rm -rf dist
	-rm -rf txrecaptcha.egg-info
	-rm -rf _trial_temp

coverage-test:
	coverage run --rcfile=".coveragerc" $(TRIAL) ./test/test_*.py
	coverage report --rcfile=".coveragerc"

coverage-html:
	coverage html --rcfile=".coveragerc"

coverage: coverage-test coverage-html
