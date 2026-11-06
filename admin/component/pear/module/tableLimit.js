layui.define(['jquery', 'table'], function (exports) {
	var table = layui.table;
	var $ = layui.$;
	var PREFIX = 'waf:table:limit:';

	// 用 view 之后的相对路径做 key，各页面互不影响，换部署目录也有效
	function storageKey() {
		return PREFIX + (location.pathname.split('/view/')[1] || 'unknown');
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

	// 分页器切换条数后保存
	$(document).on('change', '.layui-laypage-limits select', function () {
		var limit = parseInt(this.value, 10);
		if (!limit || limit < 1) {
			return;
		}

		try {
			localStorage.setItem(storageKey(), limit);
		} catch (e) { }
	});

	// 接管 render：开启分页的表自动套用记住的条数，页面无需改 limit
	var render = table.render;
	table.render = function (options) {
		if (options && options.page) {
			var page = typeof options.page === 'object' ? options.page : {};
			options.limit = getLimit(options.limit || page.limit || 10, options.limits || page.limits);
		}

		return render.call(table, options);
	};

	exports('tableLimit', getLimit);
});
