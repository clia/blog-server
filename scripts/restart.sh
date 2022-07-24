#!/bin/bash

old_dir=`pwd`
current_dir=`dirname $0`
cd ${current_dir}
sh kill.sh
sleep 1
sh start.sh
cd ${old_dir}
