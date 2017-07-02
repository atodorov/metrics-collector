#!/bin/bash

pylint -d invalid-name -d redefined-outer-name -d missing-docstring -d too-few-public-methods src/*.py tests/*.py
if [ $? -ne 0 ]; then
    exit 1
fi

PYTHONPATH=src/ nosetests --with-coverage --cover-branches --cover-package=src
if [ $? -ne 0 ]; then
    exit 1
fi

coverage report -m
