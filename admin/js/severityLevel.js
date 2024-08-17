let severityLevelArray = [
    { "type": "low", "name_en": "low", "name_cn": "低危" },
    { "type": "medium", "name_en": "medium", "name_cn": "中危" },
    { "type": "high", "name_en": "high", "name_cn": "高危" },
    { "type": "critical", "name_en": "critical", "name_cn": "严重" }
]

function initSeverityLevelSelect(id, success) {
    var mySelect = document.getElementById(id);

    for (let i in severityLevelArray) {
        let obj = severityLevelArray[i];
        var option = document.createElement('option');
        option.text = obj.name_cn;
        option.value = obj.type;

        mySelect.appendChild(option);
    }

    if (success) {
        success();
    }
}

function getSeverityLevelText(severityLevel) {
    severityLevel = severityLevel.toLowerCase();
    for (let i in severityLevelArray) {
        let obj = severityLevelArray[i];
        if (severityLevel === obj.type) {
            return obj.name_cn;
        }
    }
    return severityLevel;
}