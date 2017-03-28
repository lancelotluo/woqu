prog=`basename $0`
BASE_DIR=`pwd`

reinstall=false
install_path=/home/work/nginx
#openssl=../third-lib/libressl/output
#openssl_path=./third-lib/libressl/stgw_engine_portable-2.2.5/
openssl_path=./third-lib/openssl/stgw_engine_openssl-1.0.2j/

pcre_path=${BASE_DIR}/third-lib/pcre-8.36
ngx_src=${BASE_DIR}/nginx-1.11.1
protobuf_path=${BASE_DIR}/third-lib/protobuf/
protobuf_lib_path=${protobuf_path}/protobuf_lib/lib
protobuf_c_path=${protobuf_path}/protobuf_c_lib/
stgw_engine_proto_lib_path=${protobuf_path}/stgw_engine_proto/
third_module_path=${BASE_DIR}/third-modules/

function syntax()
{
    echo "Usage: $prog [options]"
    echo "Options:"
    echo "  --install_path=path:  install nginx to the path specified [default /usr/local/l7/l7_nginx]"
    echo "  --with-openssl=path:  path of openssl source code [default ./openssl-1.0.1j]"
    echo "  --with-openssl-opt=opts:  options to add when compile openssl"
    echo "  -h | --help:  show this usage" 
    exit 1;
}

function build_stgw_engine_proto()
{
    cd $stgw_engine_proto_lib_path
    ${protobuf_c_path}/bin/protoc-c --c_out=. engine.proto  common.proto &&
    gcc -c engine.pb-c.c -I../protobuf_c_lib/include/ &&
    gcc -c common.pb-c.c -I../protobuf_c_lib/include/ &&
    ar cr libstgw_engine_protoc.a engine.pb-c.o common.pb-c.o

    if [[ $? -ne 0 ]];then
        echo "fail to build stgw engine proto"
        exit -1
    fi
    cd ${BASE_DIR}
}

cd $ngx_src

[[ -f Makefile ]] && make clean
openssl_opt="-fPIC "
export CFLAGS="-g -O2"
./configure --prefix=$install_path \
--sbin-path=$install_path/nginx \
--conf-path=$install_path/nginx.conf \
--pid-path=$install_path/nginx.pid \
--with-cc-opt="-I ${protobuf_path}/protobuf_c_lib/include -I ${stgw_engine_proto_lib_path}" \
--with-ld-opt="-lrt -L$luajit_lib_path -L${stgw_engine_proto_lib_path} -lstgw_engine_protoc -L${protobuf_c_path}/lib -lprotobuf-c " \
--with-http_ssl_module \
--with-http_realip_module \
--with-http_addition_module \
--with-http_v2_module \
--with-http_gzip_static_module \
--with-pcre=$pcre_path \
--with-openssl="../${openssl_path}" \
--with-openssl-opt="$openssl_opt" \
--with-http_stub_status_module \
--with-debug

if [ $? -ne 0 ]; then
    echo "fail to configure for nginx"
    exit -1;
fi

make

if [ $? -ne 0 ]; then
    echo "fail to make nginx"
    exit -1;
fi

echo "done"
