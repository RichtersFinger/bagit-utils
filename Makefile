SHELL := /bin/bash
VENV := venv
VERSION =
INSTALLNAME := bagItUtils

_:
	echo "Missing target."

venv:
	[ -d "${VENV}" ] || python3 -m venv venv

test:
	python3 -m unittest discover tests/

build-dist: venv
	[ "${VERSION}" != "" ] && \
		VERSIONENV="VERSION=${VERSION}" || \
		echo "Using default version"
	source "${VENV}/bin/activate" && \
		pip install --upgrade pip wheel setuptools && \
		${VERSIONENV} python3 setup.py sdist bdist_wheel || \
		python3 setup.py sdist bdist_wheel

publish: venv
	source "${VENV}/bin/activate" && \
		pip install --upgrade pip twine && \
		python3 -m twine upload dist/*

clean:
	git clean -dfX
