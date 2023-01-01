## Zhongkui-WAF

钟馗是中国民间传说中能打鬼驱邪的神，中国民间常挂钟馗神像辟邪除灾。在网络上，总有一些坏家伙，他们隐藏在网络后面，通过各种各样的手段来攻击我们的Web应用，如妖似鬼，并且大多数时候你不能及时发现和拦截这些攻击行为。因此，我们需要安装WAF（Web Application Firewall），它像钟馗一样识别和拦截网络中的恶鬼（非法的请求），使它们现出原形并将它们挡在门外，从而保护我们的Web应用。

zhongkui-waf基于`lua-nginx-module`，多维度检查和拦截恶意网络请求，简单易用，具有高性能、轻量级的特点。 

### 主要特性

+ 多种工作模式，可随时切换
    1. 关闭模式：放行所有网络请求
    2. 保护模式（protection）：拦截攻击请求并记录攻击日志
    3. 监控模式（monitor）：记录攻击日志但不拦截攻击请求
+ IP黑名单、白名单
+ HTTP Method白名单
+ URL黑名单、白名单
+ URL恶意参数拦截
+ 恶意Header拦截
+ 请求体检查
+ 上传文件类型黑名单，防止webshell上传
+ 恶意Cookie拦截
+ CC攻击拦截，并自动拉黑IP地址，可限时或永久拉黑
+ Sql注入、XSS、SSRF等攻击拦截
+ 可设置仅允许指定国家的IP访问
+ 支持Redis
+ 攻击日志记录，包含IP地址、IP所属地区、攻击时间、防御动作、拦截规则等

### 安装

#### waf

强烈推荐使用`OpenResty`。

如果你使用`Nginx`，则需要安装`LuaJIT`和`lua-nginx-module`模块，并下载[lua-resty-redis库](https://github.com/openresty/lua-resty-redis)到`path-to-zhongkui-waf/lib/resty`目录。

假设`OpenResty`安装路径为：`/usr/local/openresty`，下载`zhongkui-waf`文件并放置在`/usr/local/openresty/zhongkui-waf`目录。

修改`nginx.conf`，在`http`模块下添加`zhongkui-waf`相关配置：

```nginx
lua_shared_dict dict_cclimit 10m;
lua_shared_dict dict_blackip 10m;
lua_shared_dict dic_logfile_lock 12k;

lua_package_path "/usr/local/openresty/zhongkui-waf/?.lua;/usr/local/openresty/zhongkui-waf/lib/?.lua;;";
init_by_lua_file  /usr/local/openresty/zhongkui-waf/init.lua; 
access_by_lua_file /usr/local/openresty/zhongkui-waf/waf.lua;
```

#### libmaxminddb库

IP地理位置识别需要下载MaxMind的IP地址数据文件及安装该IP数据文件的读取库。

1. 从MaxMind官网下载[GeoLite2 City](https://www.maxmind.com/en/accounts/current/geoip/downloads)数据文件，后续可使用[官方工具](https://github.com/maxmind/geoipupdate)对该数据文件自动更新。

2. 安装`libmaxminddb`库

    ```bash
    wget -P /usr/local/src https://github.com/maxmind/libmaxminddb/releases/download/1.7.1/libmaxminddb-1.7.1.tar.gz
    tar -zxvf libmaxminddb-1.7.1.tar.gz
    cd libmaxminddb-1.7.1
    ./configure
    make && make install
    echo /usr/local/lib >> /etc/ld.so.conf.d/local.conf
    ldconfig
    ```

    Windows系统用户要自行编译，生成`libmaxminddb.dll`文件，具体参考`maxmind/libmaxminddb`官方文档[using-cmake](https://github.com/maxmind/libmaxminddb#using-cmake)。


安装完成后重启`OpenResty`，使用测试命令：

```bash
curl http://localhost/?t=../../etc/passwd
```

看到waf返回的禁止访问信息则说明安装成功。

### 配置

zhongkui-waf所有的配置可以在`config.lua`文件中修改，修改完后要执行`nginx -s reload`命令来重新载入配置。

### Copyright and License

This library is licensed under the Apache License, Version 2.

Copyright 2023 bukale2022@163.com

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

