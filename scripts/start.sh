#!/bin/bash

old_dir=`pwd`
dir_root=$(cd `dirname $0`; pwd)
filename="blog-server"
cd ${dir_root}

if [ -e ${dir_root}/server.out ]; then
    mv ${dir_root}/server.out ${dir_root}"/server.out.`date +"%Y%m%d%H%M%S"`"
fi

RUST_LOG="info,blog_server=trace" nohup ./${filename} clia.tech clia@163.com > ${dir_root}/server.out 2>&1 &
sleep 1
ps -eaf | grep "${filename}" | grep -v "grep"
cd ${old_dir}
