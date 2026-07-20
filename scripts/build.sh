#!/bin/bash
pip install -r requirements.txt -t /var/task/lib
export PYTHONPATH=/var/task/lib:$PYTHONPATH