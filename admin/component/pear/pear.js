window.rootPath = (function (src) {
	src = document.currentScript
		? document.currentScript.src
		: document.scripts[document.scripts.length - 1].src;
	return src.substring(0, src.lastIndexOf("/") + 1);
})();

layui.config({
	base: rootPath + "module/",
	version: "3.50.0"
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

/**
 * 分页条数记忆（项目自有，上游没有，升级 pear.js 时不得删除本段）
 *
 * 为什么放在这里同步执行：layui.table 是内置模块，layui.js 解析完就已注册，此刻可直接接管；
 * 若改成 layui.use 异步加载一个模块再接管，加载完成会晚于页面脚本里的 table.render，
 * 首次渲染就取不到已保存的条数（现象：部分页面永远回到默认 10 条/页）。
 */
(function () {
	var $ = layui.$;
	var PREFIX = 'waf:table:limit:';

	// 优先用 view 之后的相对路径（换部署目录也有效）；不在 view 下则退回完整 pathname，避免共用一个 key
	function storageKey() {
		var p = location.pathname;
		return PREFIX + (p.split('/view/')[1] || p.replace(/^\/+|\/+$/g, '') || 'root');
	}

	function getLimit(defLimit, limits) {
		try {
			var saved = parseInt(localStorage.getItem(storageKey()), 10);
			if (saved > 0 && (!limits || limits.indexOf(saved) !== -1)) {
				return saved;
			}
		} catch (e) { }

		return defLimit;
	}

	// 分页器切换条数后保存（layui 的分页条数下拉是原生 select，事件冒泡到 document）
	if ($) {
		$(document).on('change', '.layui-laypage-limits select', function () {
			var limit = parseInt(this.value, 10);
			if (!limit || limit < 1) {
				return;
			}

			try {
				localStorage.setItem(storageKey(), limit);
			} catch (e) { }
		});
	}

	function patch(table) {
		if (!table || table.__wafLimitPatched) {
			return;
		}

		var render = table.render;
		table.render = function (options) {
			if (options && options.page) {
				var page = (typeof options.page === 'object' && options.page) ? options.page : null;
				var limit = getLimit(options.limit || (page && page.limit) || 10, options.limits || (page && page.limits));

				options.limit = limit;
				// page 为对象时（如 page: {limit: 10}），layui 会再用 page.limit 覆盖 limit，这里同步改掉
				if (page) {
					page.limit = limit;
				}
			}

			return render.call(table, options);
		};
		table.__wafLimitPatched = true;
	}

	if (layui.table) {
		patch(layui.table);
	} else {
		// 兜底：正常情况下 layui.table 此时已就绪，若未就绪则等模块可用后立即接管
		layui.use(['table'], function () {
			patch(layui.table);
		});
	}
})();