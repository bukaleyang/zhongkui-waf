/**
 * 时间范围筛选：预设档位（滚动窗口 + 自然日）+ 自定义区间，跨度上限按自然日计算
 * @author yangjl
 */
(function (window) {
	'use strict';

	// 滚动窗口用"最近 X"，自然日用"今天 / 近 X 天"
	var PRESETS = {
		'1h':    { text: '最近 1 小时',  title: '从 1 小时前到当前时刻',    start: function (now) { return hoursAgo(now, 1); } },
		'24h':   { text: '最近 24 小时', title: '从 24 小时前到当前时刻',   start: function (now) { return hoursAgo(now, 24); } },
		'today': { text: '今天',         title: '今天 00:00:00 到当前时刻', start: function (now) { return dayStart(now, 0); } },
		'7d':    { text: '近 7 天',      title: '含今天共 7 个自然日',       start: function (now) { return dayStart(now, -6); } },
		'30d':   { text: '近 30 天',     title: '含今天共 30 个自然日',      start: function (now) { return dayStart(now, -29); } }
	};

	var DEFAULT_PRESET = '24h';
	var MAX_SPAN_DAYS = 90; // 与 admin/lua/events.lua、ip_blocking.lua 的 MAX_SPAN_DAYS 保持一致
	var ACTIVE_CLASS = 'pear-btn-primary';

	function pad(n) {
		return n < 10 ? '0' + n : '' + n;
	}

	function format(d) {
		return d.getFullYear() + '-' + pad(d.getMonth() + 1) + '-' + pad(d.getDate()) + ' ' +
			pad(d.getHours()) + ':' + pad(d.getMinutes()) + ':' + pad(d.getSeconds());
	}

	function nowStr() {
		return format(new Date());
	}

	function hoursAgo(now, hours) {
		return new Date(now.getTime() - hours * 3600 * 1000);
	}

	// 自然日按日历偏移，不能减 86400 秒的整数倍
	function dayStart(now, offsetDays) {
		var d = new Date(now.getTime());
		d.setHours(0, 0, 0, 0);
		d.setDate(d.getDate() + offsetDays);
		return d;
	}

	// 含头含尾的自然日天数，与后端 date_only_timestamp 口径一致
	function dayCount(start, end) {
		var s = new Date(start.slice(0, 10).replace(/-/g, '/'));
		var e = new Date(end.slice(0, 10).replace(/-/g, '/'));
		return Math.round((e - s) / 86400000) + 1;
	}

	function init(opts) {
		var $ = opts.$;
		var laydate = opts.laydate;
		var $start, $end, $presets;
		var bound = false;
		var initialRange = range(DEFAULT_PRESET);

		function range(key) {
			var p = PRESETS[key];
			if (!p) {
				return null;
			}
			var now = new Date(); // 起止取同一基准时刻，避免跨度多出 1 秒
			return { startTime: format(p.start(now)), endTime: format(now) };
		}

		function highlight(key) {
			$presets.find('.tr-preset').removeClass(ACTIVE_CLASS)
				.filter('[data-preset="' + key + '"]').addClass(ACTIVE_CLASS);
		}

		function apply(key) {
			var r = range(key); // 自定义档位返回 null，保留当前区间
			if (r) {
				$start.val(r.startTime);
				$end.val(r.endTime);
			}
			highlight(key);
		}

		// laydate 运行时的 min/max 需要解析后的对象（month 从 0 开始）
		function toPickerDate(str) {
			var d = new Date(String(str).replace(/-/g, '/'));
			return {
				year: d.getFullYear(), month: d.getMonth(), date: d.getDate(),
				hours: d.getHours(), minutes: d.getMinutes(), seconds: d.getSeconds()
			};
		}

		// 打开面板前刷新可选范围：不能选未来，结束不能早于开始
		function refreshBounds(pickerId, isEnd) {
			var inst = laydate.getInst(pickerId);
			if (!inst) {
				return;
			}
			var now = nowStr();
			var start = $.trim($start.val());
			var end = $.trim($end.val());

			if (isEnd) {
				inst.config.min = toPickerDate(start || '1970-01-01 00:00:00');
				inst.config.max = toPickerDate(now);
			} else {
				inst.config.max = toPickerDate(end && end < now ? end : now);
			}
		}

		// 工具栏模板在表格首次渲染后才存在，绑定与初始值都放这里
		function bindPickers() {
			if (bound) {
				return;
			}
			bound = true;

			$start = $(opts.start);
			$end = $(opts.end);
			$presets = $(opts.presets);

			$presets.find('.tr-preset').each(function () {
				var p = PRESETS[$(this).attr('data-preset')];
				if (p) {
					$(this).attr('title', p.title);
				}
			});
			$start.val(initialRange.startTime);
			$end.val(initialRange.endTime);
			highlight(DEFAULT_PRESET);

			var base = { type: 'datetime', format: 'yyyy-MM-dd HH:mm:ss', max: nowStr() };

			// 手动选时间即切到自定义：change 覆盖面板内改动，done 覆盖点确定
			function markCustom() {
				highlight('custom');
			}

			// click 必须先于 render 绑定，否则面板会按旧范围渲染完才刷新
			$start.on('click', function () { refreshBounds('tr-start-picker', false); });
			laydate.render($.extend({}, base, {
				id: 'tr-start-picker',
				elem: opts.start,
				value: $start.val(),
				change: markCustom,
				done: markCustom
			}));

			$end.on('click', function () { refreshBounds('tr-end-picker', true); });
			laydate.render($.extend({}, base, {
				id: 'tr-end-picker',
				elem: opts.end,
				value: $end.val(),
				change: markCustom,
				done: markCustom
			}));
		}

		function validate() {
			var start = $.trim($start.val());
			var end = $.trim($end.val());

			if (!start) {
				return { msg: '请选择时间范围' };
			}

			// 结束时间随请求固定，否则翻页时后端重算 now 会让窗口滑动、数据错位
			if (!end) {
				end = nowStr();
				$end.val(end);
			}

			if (start > end) {
				return { msg: '开始时间不能晚于结束时间' };
			}
			if (end > nowStr()) {
				return { msg: '结束时间不能晚于当前时间' };
			}

			var days = dayCount(start, end);
			if (days > MAX_SPAN_DAYS) {
				return { msg: '查询范围最多 ' + MAX_SPAN_DAYS + ' 个自然日（当前 ' + days + ' 天），请缩小范围' };
			}

			return { startTime: start, endTime: end };
		}

		// 回填后端实际生效范围
		function sync(res) {
			if (!res) {
				return;
			}
			if (res.startTime) {
				$start.val(res.startTime);
			}
			if (res.endTime) {
				$end.val(res.endTime);
			}
		}

		return {
			defaultRange: initialRange,
			apply: apply,
			reset: function () { apply(DEFAULT_PRESET); },
			bindPickers: bindPickers,
			validate: validate,
			sync: sync
		};
	}

	window.TimeRangeFilter = { init: init };
})(window);
