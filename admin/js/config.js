layui.use(['form','element','util','jquery','popup','tag'], function() {
    var form = layui.form;
    var popup = layui.popup;
    var $ = layui.$;
    var	tag = layui.tag;

    form.verify({
        fileExtRule: function(value, elem) {
            var regex = /^$|^("[a-zA-Z0-9]+")(,("[a-zA-Z0-9]+"))*$/
            if (regex.test(value) == false) {
                return "上传文件类型黑名单格式不正确";
            }
        },
        pathRule: function(value, elem) {
            var regex = /^[^'"\s]+$/
            if (regex.test(value) == false) {
                return "路径格式不正确";
            }
        },
        secretRule: function(value, elem) {
            var regex = /^[a-zA-Z0-9]+$/
            if (regex.test(value) == false) {
                return "密钥格式不正确，只能包含字母和数字";
            }
        },
        uriRule: function(value, elem) {
            var regex = /^[^'"\s]+$/
            if (regex.test(value) == false) {
                return "URI格式不正确";
            }
        }
    });

    $(function(){
        $.get('/defense/basic/get', {}, function(data) {
            if (data && data.data) {
                $.each(JSON.parse(data.data), function(key, value) {
                    if (key == "fileExtBlackList") {
                        if (Array.isArray(value)) {
                            var fileExtBlackList = $('#fileExtBlackList');
                            if (fileExtBlackList.length) {
                                var html = '';
                                $.each(value, function(idx, val) {
                                    html += '<button lay-id="' + idx + '" type="button" class="tag-item tag-item-normal">' + val + '</button>';
                                });
                                fileExtBlackList.html(html);

                                tag.render("fileExtBlackList", {
                                    tagText: '<i class="layui-icon layui-icon-add-1"></i>添加扩展名'
                                });
                            }
                        }
                    } else if (key == "methodWhiteList") {
                        if (Array.isArray(value)) {
                            $.each(value, function(idx, val) {
                                $("[name='methodWhiteList'][value='" + val + "']").prop('checked', true);
                            });
                        }
                    } else if (value == "on" || value === true) {
                        $("[name='" + key + "']").prop('checked', true);
                    } else if (value == "off" || value === false) {
                        $("[name='" + key + "']").prop('checked', false);
                    } else {
                        $("[name='" + key + "']").val(value);
                    }
                });

                form.render(null, 'form_config');
            }
        }, "json");
        // 阻止回车触发表单提交
        $('input').on('keydown', function (e) {
            if (e.keyCode === 13) {
                e.preventDefault();
                return false;
            }
        });
    });

    form.on('submit(config_save)', function(data) {
        var field = data.field;
        var elem = data.elem;

        var formObj = $(elem).parents('[lay-filter="form_config"]');

        formObj.find(':checkbox[lay-filter="config_switch"]').each(function(i, el) {
            var name = $(el).attr('name');
            field[name] = $(el).prop('checked') ? 'on' : 'off';
        });

        formObj.find(':checkbox[lay-filter="config_switch_boolean"]').each(function(i, el) {
            var name = $(el).attr('name');
            field[name] = $(el).prop('checked') ? 'true' : 'false';
        });

        formObj.find('input:text[lay-filter="config_input"]').each(function(i, el) {
            var name = $(el).attr('name');
            field[name] = $(el).val().trim();
        });

        var methodWhiteList = $('input[name="methodWhiteList"]');
        if (methodWhiteList.length) {
            var arr = [];
            $('input[name="methodWhiteList"]:checked').each(function() {
                arr.push($(this).val());
            });
            field.methodWhiteList = arr;
        }

        var fileExtBlackList = $('#fileExtBlackList');
        if (fileExtBlackList.length) {
            var arr = [];
            $('#fileExtBlackList').find('button').not(":last").each(function(i, el) {
                arr.push($(el).text().replace('ဆ','').trim())
            });
          //  var str = arr.map(item => `"${item}"`).join(',');
            field.fileExtBlackList = arr;
        }

        $.post('/defense/basic/update', {config: JSON.stringify(field)}, function(data) {
            if (data && data.code == 200) {
                popup.success("已保存");
            } else {
                popup.failure(data.msg);
            }          
        },'json');

        return false; // 阻止默认 form 跳转
    });
});