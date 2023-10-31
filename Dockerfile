FROM openresty/openresty:centos


COPY . /usr/local/openresty/zhongkui-waf

WORKDIR /usr/local/openresty/zhongkui-waf

RUN yum -y install vim wget git gcc make pcre-devel openssl openssl-devel && \
    cd /usr/local/src  && cp /usr/local/openresty/zhongkui-waf/srcs/libmaxminddb-1.7.1.tar.gz ./ && tar -zxf libmaxminddb-1.7.1.tar.gz && cd ./libmaxminddb-1.7.1 && ./configure && make && make install && echo /usr/local/lib >> /etc/ld.so.conf.d/local.conf && ldconfig &&\
    mkdir -p /usr/local/openresty/nginx/logs/hack && chmod -R 744 /usr/local/openresty/nginx/logs/hack && \
    cp /usr/local/openresty/zhongkui-waf/srcs/waf.conf /etc/nginx/conf.d && \
    openresty -s reload

EXPOSE 80 443

CMD ["openresty", "-s" , "reload"]
