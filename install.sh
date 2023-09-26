
echo "
  ______                       _  __     _ 
 |__  / |__   ___  _ __   __ _| |/ /   _(_)
   / /| '_ \ / _ \| '_ \ / _\` | ' / | | | |
  / /_| | | | (_) | | | | (_| | . \ |_| | |
 /____|_| |_|\___/|_| |_|\__, |_|\_\__,_|_|
                         |___/             
"

OPENRESTY_PATH=/usr/local/openresty
ZHONGKUI_PATH=$OPENRESTY_PATH/zhongkui-waf
GEOIP_DATABASE_PATH=/usr/local/share/GeoIP

cd /usr/local/src
if [ ! -x "openresty-1.21.4.2.tar.gz" ]; then  
    wget https://openresty.org/download/openresty-1.21.4.2.tar.gz
fi
tar zxf openresty-1.21.4.2.tar.gz
cd openresty-1.21.4.2

./configure --prefix=$OPENRESTY_PATH \
--with-http_ssl_module \
--with-http_v2_module \
--with-http_realip_module \
--with-http_sub_module \
--with-http_stub_status_module \
--with-http_auth_request_module \
--with-http_secure_link_module \
--with-stream \
--with-stream_ssl_module \
--with-stream_realip_module \
--without-http_fastcgi_module \
--without-mail_pop3_module \
--without-mail_imap_module \
--without-mail_smtp_module

make && make install
echo -e "\033[37m[openresty安装成功]\033[0m"


cd /usr/local/src
if [ ! -x "zhongkui-waf-master.zip" ]; then
    wget -O /usr/local/src/zhongkui-waf-master.zip https://github.com/bukaleyang/zhongkui-waf/archive/refs/heads/master.zip --no-check-certificate
fi
unzip zhongkui-waf-master.zip
mv ./zhongkui-waf-master $ZHONGKUI_PATH

mkdir -p $OPENRESTY_PATH/nginx/logs/hack
chmod -R 744 $OPENRESTY_PATH/nginx/logs/hack

echo -e "\033[37m[zhongkui-waf安装成功]\033[0m"


cd /usr/local/src
if [ ! -x "libmaxminddb-1.7.1.tar.gz" ]; then
    wget https://github.com/maxmind/libmaxminddb/releases/download/1.7.1/libmaxminddb-1.7.1.tar.gz
fi
tar -zxf libmaxminddb-1.7.1.tar.gz
cd ./libmaxminddb-1.7.1
./configure
make && make install
echo /usr/local/lib >> /etc/ld.so.conf.d/local.conf
ldconfig
echo -e "\033[37m[libmaxminddb安装成功]\033[0m"


# =================maxminddb数据库文件自动更新start=================
cd /usr/local/src
if [ ! -x "geoipupdate_6.0.0_linux_386.tar.gz" ]; then
    wget https://github.com/maxmind/geoipupdate/releases/download/v6.0.0/geoipupdate_6.0.0_linux_386.tar.gz
fi
tar -zxf geoipupdate_6.0.0_linux_386.tar.gz
mv ./geoipupdate_6.0.0_linux_386/geoipupdate /usr/local/bin/geoipupdate


if [ -x "/usr/local/bin/geoipupdate" ]; then
    # 将配置文件GeoIP.conf写入到/usr/local/etc/目录
echo "
AccountID your AccountID
LicenseKey your LicenseKey
#EditionIDs GeoLite2-ASN GeoLite2-City GeoLite2-Country
EditionIDs GeoLite2-City
DatabaseDirectory $GEOIP_DATABASE_PATH
" >> /usr/local/etc/GeoIP.conf

    echo -e "\033[37m[GeoIP.conf安装成功]\033[0m"

    echo "32 8 * * 1,3 /usr/local/bin/geoipupdate" | crontab -
    echo -e "\033[37m[geoipupdate安装成功]\033[0m"

    mkdir -p $GEOIP_DATABASE_PATH
    /usr/local/bin/geoipupdate
fi
# =================maxminddb数据库文件自动更新end=================

