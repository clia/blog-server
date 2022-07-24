#!/bin/bash

old_dir=`pwd`
dir_root=$(cd `dirname $0`; pwd)
cd ${dir_root}

pid_file="blog-server.pid"
if [ ! -f ${pid_file} ]; then
    echo "pid file is not exists!"
    exit 1
fi

pid=`cat ${pid_file}`
while [ -x /proc/${pid} ]
do
    echo "pid ${pid} is killing ......"
    kill -9 ${pid}
    sleep 1
done
echo "pid ${pid} is killed"

cd ${old_dir}
