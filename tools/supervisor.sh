#!/bin/bash

source "/home/jelte/py/bin/activate"
mkdir -p logs

# Wrap the 'supervisorctl' command
OPTIONS="$@"
CONF_FILE="tools/supervisord.conf"
if [ ! -e /tmp/supervisor.sock ]; then
    supervisord -c $CONF_FILE
fi
supervisorctl -c $CONF_FILE $OPTIONS

