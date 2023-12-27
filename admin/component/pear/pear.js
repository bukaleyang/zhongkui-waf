window.rootPath = (function (src) {
	src = document.currentScript
		? document.currentScript.src
		: document.scripts[document.scripts.length - 1].src;
	return src.substring(0, src.lastIndexOf("/") + 1);
})();

layui.config({
	base: rootPath + "module/",
	version: "3.40.0"
}).extend({
	admin: "admin", 	         // 框架布局组件
	common: "common",            // 公共方法封装
	menu: "menu",		         // 数据菜单组件
	frame: "frame", 	         // 内容页面组件
	tab: "tab",			         // 多选项卡组件
	echarts: "echarts",          // 数据图表组件
	echartsTheme: "echartsTheme",// 数据图表主题
	drawer: "drawer",	         // 抽屉弹层组件
	tag:"tag",			         // 多标签页组件
	popup:"popup",               // 弹层封装
	count:"count",			     // 数字滚动
	topBar: "topBar",		     // 置顶组件
	button: "button",		     // 加载按钮
	loading: "loading",		     // 加载组件
	convert:"convert",		     // 数据转换
	yaml:"yaml",			     // yaml 解析组件
	context: "context",		     // 上下文组件
	theme: "theme",			     // 主题转换
	message: "message",          // 通知组件
	toast: "toast",              // 消息通知
	fullscreen:"fullscreen"     //全屏组件
}).use(['layer', 'theme', 'jquery'], function () {
	layui.theme.changeTheme(window, false);
	var $ = layui.$;
	$.ajaxSetup({
		complete(xhr, status) {
			if (xhr.status == 401) {
				window.parent.location.href = '/login.html';
			}
	}});
});