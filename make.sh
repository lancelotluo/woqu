prog=`basename $0`
BASE_DIR=`pwd`

reinstall=false
install_path=$HOME/nginx
#openssl=../third-lib/libressl/output
#openssl_path=./third-lib/libressl/stgw_engine_portable-2.2.5/
openssl_path=./proto-quic/src/third_party/boringssl/src/
boringssl_lib=${BASE_DIR}/proto-quic/lib/
proto_quic_src=${BASE_DIR}/proto-quic/src/

pcre_path=${BASE_DIR}/third-lib/pcre-8.40
ngx_src=${BASE_DIR}/nginx-1.11.1
protobuf_path=${BASE_DIR}/proto-quic/src/third_party/protobuf/src/
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

cd $ngx_src

[[ -f Makefile ]] && make clean
openssl_opt="-fPIC "
export CFLAGS="-g -O2"
./configure --prefix=$install_path \
--sbin-path=$install_path/nginx \
--conf-path=$install_path/nginx.conf \
--pid-path=$install_path/nginx.pid \
--with-cc-opt="-I ${protobuf_path} -I ${stgw_engine_proto_lib_path} -I ${proto_quic_src}" \
--with-ld-opt="-lrt -L${boringssl_lib} -lcrcrypto -lboringssl" \
--with-http_ssl_module \
--with-http_realip_module \
--with-http_addition_module \
--with-http_v2_module \
--with-http_quic_module \
--with-http_gzip_static_module \
--with-pcre=$pcre_path \
--with-openssl="../${openssl_path}" \
--with-openssl-opt="$openssl_opt" \
--with-http_stub_status_module \
--with-stream \
--with-boringssl_so="YES" \
--with-debug
#--add-module=${third_module_path}/ngx_http_quic_module/ \

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

#CPP = g++   
#CPPFLAGS = ${CFLAGS} -Wall -std=gnu++11
#LINK =  $(CPP)
