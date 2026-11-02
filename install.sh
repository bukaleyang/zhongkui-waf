#!/bin/bash

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

# 固定版本，安装时下载并校验，避免运行时自动升级
LEGO_VERSION=5.5.2
LEGO_LINUX_AMD64_SHA256=2a35505089e7772c92e1e9ac144df91151ef2eca8568630db0ff91fca06d9bef
LEGO_LINUX_ARM64_SHA256=15b14ec2ab14fde69cc8396eb0204c5ce4327e31a486953225a6059b26db3e8c

cd /usr/local/src
if [ ! -x "openresty-1.25.3.2.tar.gz" ]; then
    wget https://openresty.org/download/openresty-1.25.3.2.tar.gz
fi
tar zxf openresty-1.25.3.2.tar.gz
cd openresty-1.25.3.2

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
echo -e "\033[34m[openresty安装成功]\033[0m"


cd /usr/local/src
if [ ! -x "zhongkui-waf-master.zip" ]; then
    wget -O /usr/local/src/zhongkui-waf-master.zip https://github.com/bukaleyang/zhongkui-waf/archive/refs/heads/master.zip --no-check-certificate
fi
unzip zhongkui-waf-master.zip
mv ./zhongkui-waf-master $OPENRESTY_PATH/zhongkui-waf

mkdir -p $OPENRESTY_PATH/nginx/logs/hack
echo -e "\033[34m[hack目录已创建]\033[0m"
echo -e "\033[34m[zhongkui-waf安装成功]\033[0m"


# =================lego免费证书客户端安装start=================
case "$(uname -m)" in
    x86_64|amd64)
        LEGO_ARCH=amd64
        LEGO_SHA256=$LEGO_LINUX_AMD64_SHA256
        ;;
    aarch64|arm64)
        LEGO_ARCH=arm64
        LEGO_SHA256=$LEGO_LINUX_ARM64_SHA256
        ;;
    *)
        echo "unsupported CPU architecture for lego: $(uname -m)"
        exit 1
        ;;
esac

LEGO_ARCHIVE=lego_v${LEGO_VERSION}_linux_${LEGO_ARCH}.tar.gz
LEGO_URL=https://github.com/go-acme/lego/releases/download/v${LEGO_VERSION}/${LEGO_ARCHIVE}
cd /usr/local/src

verify_lego() {
    if command -v sha256sum >/dev/null 2>&1; then
        echo "$LEGO_SHA256  $LEGO_ARCHIVE" | sha256sum -c -
    elif command -v shasum >/dev/null 2>&1; then
        echo "$LEGO_SHA256  $LEGO_ARCHIVE" | shasum -a 256 -c -
    else
        echo "sha256sum or shasum is required to verify lego"
        return 1
    fi
}

if [ ! -f "$LEGO_ARCHIVE" ] || ! verify_lego; then
    rm -f "$LEGO_ARCHIVE"
    wget -O "$LEGO_ARCHIVE" "$LEGO_URL" || exit 1
    verify_lego || { echo "lego checksum verification failed"; exit 1; }
fi

LEGO_TMP=$(mktemp -d)
tar -xzf "$LEGO_ARCHIVE" -C "$LEGO_TMP" lego || { rm -rf "$LEGO_TMP"; exit 1; }
mkdir -p "$ZHONGKUI_PATH/bin" "$ZHONGKUI_PATH/admin/ssl-certs"
install -m 0755 "$LEGO_TMP/lego" "$ZHONGKUI_PATH/bin/lego" || { rm -rf "$LEGO_TMP"; exit 1; }
rm -rf "$LEGO_TMP"

"$ZHONGKUI_PATH/bin/lego" --version || { echo "lego failed to run after installation"; exit 1; }

mkdir -p "$ZHONGKUI_PATH/data/acme/webroot/.well-known/acme-challenge"
mkdir -p "$ZHONGKUI_PATH/data/acme/logs"
chmod 700 "$ZHONGKUI_PATH/data/acme"
if id nginx >/dev/null 2>&1; then
    chown -R nginx "$ZHONGKUI_PATH/data/acme" "$ZHONGKUI_PATH/admin/ssl-certs"
fi
echo -e "\033[34m[lego v${LEGO_VERSION}安装并校验成功]\033[0m"
# =================lego免费证书客户端安装end=================


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
echo -e "\033[34m[libmaxminddb安装成功]\033[0m"


cd /usr/local/src
if [ ! -x "libinjection-master.zip" ]; then
    wget -O /usr/local/src/libinjection-master.zip https://github.com/client9/libinjection/archive/refs/heads/master.zip
fi
unzip libinjection-master.zip
cd ./libinjection-master
make all
mv ./src/libinjection.so $OPENRESTY_PATH/lualib/libinjection.so
echo -e "\033[34m[libinjection安装成功]\033[0m"


cd /usr/local/src
if [ ! -x "luaossl-rel-20220711.tar.gz" ]; then
    wget -O /usr/local/src/luaossl-rel-20220711.tar.gz https://github.com/wahern/luaossl/archive/refs/tags/rel-20220711.tar.gz
fi
tar -zxf luaossl-rel-20220711.tar.gz
cd ./luaossl-rel-20220711
make all5.1 includedir=$OPENRESTY_PATH/luajit/include/luajit-2.1 && make install5.1
echo -e "\033[34m[luaossl安装成功]\033[0m"


cd /usr/local/src
if [ ! -x "luafilesystem-master.zip" ]; then
    wget -O /usr/local/src/luafilesystem-master.zip https://github.com/lunarmodules/luafilesystem/archive/refs/heads/master.zip
fi
unzip luafilesystem-master.zip
cd ./luafilesystem-master
make INCS=-I$OPENRESTY_PATH/luajit/include/luajit-2.1
mv ./src/lfs.so $OPENRESTY_PATH/lualib/lfs.so
echo -e "\033[34m[luafilesystem安装成功]\033[0m"


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

    echo -e "\033[34m[GeoIP.conf安装成功]\033[0m"

    echo "32 8 * * 1,3 /usr/local/bin/geoipupdate" | crontab -
    echo -e "\033[34m[geoipupdate安装成功]\033[0m"

    mkdir -p $GEOIP_DATABASE_PATH
    /usr/local/bin/geoipupdate
fi
# =================maxminddb数据库文件自动更新end=================
