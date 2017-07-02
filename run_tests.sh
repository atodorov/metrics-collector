#!/bin/bash

pylint -d invalid-name -d redefined-outer-name -d missing-docstring -d too-few-public-methods src/*.py tests/*.py
if [ $? -ne 0 ]; then
    exit 1
fi

PYTHONPATH=src/ coverage run --source=src/ --branch -m unittest -v tests/*.py
if [ $? -ne 0 ]; then
    exit 1
fi

coverage report -m
