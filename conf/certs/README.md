# ca-bundle.pem

威胁情报拉取使用的根证书包，来源：<https://curl.se/ca/cacert.pem>（Mozilla 根证书，curl.se 打包）。

## 更新

```bash
cd /usr/local/openresty/zhongkui-waf/conf/certs
curl -fsSL https://curl.se/ca/cacert.pem -o ca-bundle.pem.new
grep -m1 'Certificate data from Mozilla' ca-bundle.pem.new   # 确认下载到的是证书包
mv ca-bundle.pem.new ca-bundle.pem
/usr/local/openresty/nginx/sbin/nginx -t && /usr/local/openresty/nginx/sbin/nginx -s reload
```

- 根证书变动很少，半年到一年检查一次即可。
- 替换后必须 reload 才会生效。
- 文件缺失会导致 nginx 启动失败（`lua_ssl_trusted_certificate` 是硬依赖）。
- 如有企业 TLS 中间人代理，把企业根证书追加到本文件末尾即可。
- 也可以直接指向系统 CA 包（如 `/etc/ssl/certs/ca-certificates.crt`），但各发行版路径不同，所以默认随包提供。
