## Zhongkui-WAF

钟馗是中国传统文化中的一个神话人物，被誉为“捉鬼大师”，专门驱逐邪恶之物。`Zhongkui-WAF`的命名灵感来源于这一神话人物，寓意着该软件能够像钟馗一样，有效地保护Web应用免受各种恶意攻击和威胁。

`Zhongkui-WAF`基于`lua-nginx-module`，可以多维度检查和拦截恶意网络请求，具有简单易用、高性能、轻量级的特点。它的配置简单，你可以根据实际情况设置不同的安全规则和策略。

### 主要特性

+ 多种工作模式，可随时切换
    1. 关闭模式：放行所有网络请求
    2. 保护模式（protection）：拦截攻击请求并记录攻击日志
    3. 监控模式（monitor）：记录攻击日志但不拦截攻击请求
+ 支持规则自动排序，开启后按规则命中次数降序排序，可提高拦截效率
+ IP黑名单、白名单，支持网段配置，"127.0.0.1/24"或"127.0.0.1/255.255.255.0"
+ HTTP Method白名单
+ URL黑名单、白名单
+ URL恶意参数拦截
+ 恶意Header拦截
+ 请求体检查
+ 上传文件类型黑名单，防止webshell上传
+ 恶意Cookie拦截
+ CC攻击拦截，浏览器验证失败后可以自动限时或永久拉黑IP地址
+ Sql注入、XSS、SSRF等攻击拦截
+ 可设置仅允许指定国家的IP访问
+ 敏感数据（身份证号码、手机号码、银行卡号、密码）脱敏及关键词过滤
+ 支持Redis，开启后IP请求频率、IP黑名单等数据将从Redis中读写
+ 攻击日志记录，包含IP地址、IP所属地区、攻击时间、防御动作、拦截规则等

### 安装

#### OpenResty

由于`Zhongkui-WAF`基于`lua-nginx-module`，所以要先安装`Nginx`或`OpenResty`，强烈推荐使用`OpenResty`。

如果你使用`Nginx`，则需要安装以下第三方模块：

1. 安装`LuaJIT`和`lua-nginx-module`模块
2. 下载[lua-resty-redis库](https://github.com/openresty/lua-resty-redis)到`path-to-zhongkui-waf/lib/resty`目录
3. 安装[lua-cjson库](https://www.kyne.com.au/~mark/software/lua-cjson.php)

#### zhongkui-waf

假设`OpenResty`安装路径为：`/usr/local/openresty`，下载`zhongkui-waf`文件并放置在`/usr/local/openresty/zhongkui-waf`目录。

修改`nginx.conf`，在`http`模块下添加`zhongkui-waf`相关配置：

```nginx
lua_shared_dict dict_cclimit 10m;
lua_shared_dict dict_accesstoken 10m;
lua_shared_dict dict_blackip 10m;
lua_shared_dict dict_locks 100k;
lua_shared_dict dict_config 5m;
lua_shared_dict dict_config_rules_hits 5m;

lua_package_path "/usr/local/openresty/zhongkui-waf/?.lua;/usr/local/openresty/zhongkui-waf/lib/?.lua;;";
init_by_lua_file  /usr/local/openresty/zhongkui-waf/init.lua;
init_worker_by_lua_file /usr/local/openresty/zhongkui-waf/init_worker.lua;
access_by_lua_file /usr/local/openresty/zhongkui-waf/waf.lua;
body_filter_by_lua_file /usr/local/openresty/zhongkui-waf/body_filter.lua;
header_filter_by_lua_file /usr/local/openresty/zhongkui-waf/header_filter.lua;
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

看到拦截信息则说明安装成功。

### 配置

`Zhongkui-WAF`的基本配置在`config.lua`文件中，你可以对它进行修改。

ip黑名单列表可以配置在`config.lua`文件中，也可以配置在`path-to-zhongkui-waf/rules/ipBlackList`文件中。

不管是基本配置还是规则文件，修改完后都要执行`nginx -s reload`命令来重新载入配置。

`path-to-zhongkui-waf/rules`目录下是一系列规则文件，文件内容都是`json`格式。你可以新增自己的规则，也可以对每条规则进行单独设置，如打开、关闭或者修改其拦截动作等。

拦截动作有如下几种：

+ `allow`：允许当前请求并记录日志。
+ `deny`：拒绝当前请求，返回HTTP状态码403并记录日志。
+ `redirect`：拒绝当前请求，返回拦截页面并记录日志。
+ `coding`：对匹配到的内容进行过滤，替换为`*`。
+ `redirect_js`：浏览器验证，JavaScript重定向。
+ `redirect_302`：浏览器验证，302重定向。

一些配置项是通用的：

+ `state`：是该条规则的开关状态，`on`是开启，`off`是关闭。
+ `description`：是对该规则的描述，起到方便管理的作用。

配置项`redirect`是`Zhongkui-WAF`的私钥，用于浏览器验证请求签名等，应妥善保管，安装后建议修改下，格式为任意字符组合，建议长度长一点。

### CC攻击防御

cc攻击的配置文件是`path-to-zhongkui-waf/rules/cc.json`，可按单`URL`和单`IP`进行统计，超过阈值时直接拒绝请求或对浏览器进行验证，验证失败后可自动屏蔽IP地址。

配置项说明：

+ `countType`：统计类型，值为"url"或"ip"。
+ `duration`：统计时长，单位是秒。
+ `threshold`：阈值，单位是次。
+ `action`：cc攻击处置动作，`redirect_js`、`redirect_302`仅适用于网页或H5，APP或API等环境，应设置为：`deny`。
+ `autoIpBlock`：在浏览器验证失败后自动屏蔽IP，`on`是开启，`off`是关闭。拉黑日志保存在`./logPath/ipBlock.log`文件中。
+ `ipBlockTimeout`：ip禁止访问时间，单位是秒，如果设置为`0`则永久禁止并保存在`./rules/ipBlackList`文件中。

#### 敏感数据过滤

开启敏感信息过滤后，`Zhongkui-WAF`将对响应数据进行过滤。

`Zhongkui-WAF`内置了对响应内容中的身份证号码、手机号码、银行卡号、密码信息进行脱敏处理。需要注意的是，内置的敏感信息脱敏功能目前仅支持处理中华人民共和国境内使用的数据格式（如身份证号、电话号码、银行卡号），暂不支持处理中国境外的身份证号、电话号码、银行卡号等数据格式。但你可以使用正则表达式配置不同的规则，以过滤请求响应内容中任何你想要过滤掉的数据。

敏感信息过滤配置在在`sensitive.json`文件中。

例如：

```json
{
	"rules": [{
			"state": "on",
			"action": "coding",
			"codingRange": "4,-5",
			"rule": "(?:(?:\\+|00)86)?1(?:(?:3[\\d])|(?:4[5-79])|(?:5[0-35-9])|(?:6[5-7])|(?:7[0-8])|(?:8[\\d])|(?:9[189]))\\d{8}",
			"description": "mobile number"
		},
		{
			"state": "on",
			"action": "coding",
			"codingRange": "$1",
			"rule": "(?:password|passwd)\"\\s*[:=]\\s*\"(\\S+)\"",
			"description": "password"
		}
	],
	"words": ["fuck", "bitch", "balabala"]
}
```

`action`是匹配到该条规则后的响应动作，目前敏感信息过滤只有`coding`这一种有效，即对敏感信息脱敏处理。

`rule`是要处理的信息的匹配规则，通常是一个正则表达式。

`codingRange`是匹配到的字符串中要处理的子字符串范围，有两种形式：

1. 直接标明要处理的子字符串的起始位置：
    1. 如字符串`15800000000`的`codingRange`为 `“4,7”`，则会将对从第四个位置开始到第七个位置之间的所有字符进行处理，结果为`158****0000`。
    2. 起始位置也可以是一个负数，如字符串`15800000000`的`codingRange`为 `“4,-5”`，则会将对从第四个位置开始到倒数第五个位置之间的所有字符进行处理，结果为`158****0000`。
2. 使用`$`字面量加数字，比如：`$0`指的是由该模式匹配的整个子串，而`$1`指第一个带括号的捕获子串。

`words`是一个数组，可以用来配置一些需要过滤掉的关键词。

### Copyright and License

ZhongKui-WAF is licensed under the Apache License, Version 2.

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

