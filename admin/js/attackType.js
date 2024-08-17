let attackTypeArray = [
    {"type":"sqli","name_en":"SQL Injection","name_cn":"SQL注入"},
    {"type":"xss","name_en":"XSS","name_cn":"XSS"},
    {"type":"acl","name_en":"ACL","name_cn":"ACL(访问控制列表)"},
    {"type":"file_ext","name_en":"file ext","name_cn":"上传文件类型黑名单"},
    {"type":"blackurl","name_en":"URL Blacklist","name_cn":"URL黑名单"},
    {"type":"blackip","name_en":"IP Blacklist","name_cn":"IP黑名单"},
    {"type":"unsafe_method","name_en":"unsafe http method","name_cn":"不允许的HTTP方法"},
    {"type":"bot","name_en":"Bot","name_cn":"Bot"},
    {"type":"bot_trap","name_en":"bot trap","name_cn":"Bot陷阱"},
    {"type":"directory_traversal","name_en":"Directory Traversal","name_cn":"目录穿越"},
    {"type":"commandi","name_en":"Command Injection","name_cn":"命令注入"},
    {"type":"rce","name_en":"Remote Code Exec","name_cn":"代码执行"},
    {"type":"codei","name_en":"Code Injection","name_cn":"代码注入"},
    {"type":"backdoor","name_en":"backdoor","name_cn":"后门"},
    {"type":"data_leak","name_en":"Data Leak","name_cn":"信息泄露"},
    {"type":"read_file","name_en":"Read File","name_cn":"文件读取"},
    {"type":"unknown","name_en":"unknown","name_cn":"未知"}
]

function initAttackTypeSelect(id, success) {
    var mySelect = document.getElementById(id);

    for (let i in attackTypeArray) {
        let obj = attackTypeArray[i];
        var option = document.createElement('option');
        option.text = obj.name_cn;
        option.value = obj.type;

        mySelect.appendChild(option);
    }

    if (success) {
        success();
    }
}

function getAttackTypeText(attackType) {
    attackType = attackType.toLowerCase();
    for (let i in attackTypeArray) {
        let obj = attackTypeArray[i];
        if (attackType === obj.type) {
            return obj.name_cn;
        }
    }
    return attackType;
}