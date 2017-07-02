#!/bin/bash

pylint -d invalid-name -d redefined-outer-name -d missing-docstring -d too-few-public-methods src/*.py tests/*.py
