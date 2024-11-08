let action = {
    "deny": "拒绝访问",
    "allow": "允许访问",
    "redirect": "拒绝访问并返回拦截页面",
    "captcha": "人机验证",
    "coding": "打码"
}

function initActionSelect(id, exclude, success) {
    var mySelect = document.getElementById(id);

    for (let key in action) {
        var option = document.createElement('option');
        if (exclude && exclude === key) {
            continue;
        }
        option.text = action[key];
        option.value = key;

        mySelect.appendChild(option);
    }

    if (success) {
        success();
    }
}

function getActionText(actionType) {
    actionType = actionType.toLowerCase();
    for (let key in action) {
        if (actionType === key) {
            return action[key];
        }
    }
    return;
}