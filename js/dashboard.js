/*
 * Dashboard: fetches the JSON feed and fills the page.
 * XSS defence (protection 2): every value from the log is put on the page with
 * textContent, which treats it as plain text. It is never written with innerHTML,
 * so <script> typed by an attacker as a username is shown as text, not run.
 */
(function () {
    'use strict';
    var root = document.getElementById('monitor');
    if (!root) { return; }
    var feed = root.getAttribute('data-feed');

    function cell(tr, text, cls) {
        var td = document.createElement('td');
        td.textContent = text === null || text === undefined ? '' : String(text);
        if (cls) { td.className = cls; }
        tr.appendChild(td);
    }

    function fillTable(id, rows, columns, emptyText) {
        var body = document.querySelector('#' + id + ' tbody');
        body.textContent = '';
        if (!rows.length) {
            var tr = document.createElement('tr');
            var td = document.createElement('td');
            td.colSpan = columns.length || 1;
            td.textContent = emptyText;
            tr.appendChild(td);
            body.appendChild(tr);
            return;
        }
        rows.forEach(function (row) {
            var tr = document.createElement('tr');
            columns.forEach(function (c) { cell(tr, c(row), null); });
            body.appendChild(tr);
        });
    }

    var cardsDef = [
        ['Successful log-ins', 'login_success'], ['Failed log-ins', 'login_failed'],
        ['Accounts locked now', 'accounts_locked'], ['IPs blocked now', 'ips_blocked'],
        ['OTPs sent', 'otp_sent'], ['OTPs failed', 'otp_failed'], ['Alert emails sent', 'alerts_sent']
    ];

    function query() {
        var p = new URLSearchParams();
        [['from', 'f-from'], ['to', 'f-to'], ['type', 'f-type'], ['username', 'f-username'], ['ip', 'f-ip']]
            .forEach(function (pair) {
                var v = document.getElementById(pair[1]).value.trim();
                if (v) { p.set(pair[0], v); }
            });
        return p.toString();
    }

    function render(data) {
        document.getElementById('updated').textContent = data.updated;

        var cards = document.getElementById('summary-cards');
        cards.textContent = '';
        cardsDef.forEach(function (def) {
            var box = document.createElement('div');
            box.className = 'stat';
            var num = document.createElement('div');
            num.className = 'stat-number';
            num.textContent = String(data.summary[def[1]]);
            var lab = document.createElement('div');
            lab.className = 'stat-label';
            lab.textContent = def[0];
            box.appendChild(num); box.appendChild(lab);
            cards.appendChild(box);
        });

        BarChart.draw(document.getElementById('hour-chart'), data.hours.labels, data.hours.values);

        fillTable('top-ips', data.top_ips,
            [function (r) { return r.ip_address; }, function (r) { return r.failures; },
             function (r) { return Number(r.blocked) > 0 ? 'Yes' : 'No'; }], 'No failures in 24 hours.');

        fillTable('blocked-ips', data.blocked_ips || [],
            [function (r) { return r.ip_address; },
             function (r) { return Number(r.active) > 0 ? 'Blocked now' : 'Expired'; },
             function (r) { return r.blocked_until; }, function (r) { return r.reason; },
             function (r) { return r.created_at; }], 'No IP has been blocked yet.');

        fillTable('flags', data.flags,
            [function (r) { return r.severity; }, function (r) { return r.pattern; }, function (r) { return r.target; },
             function (r) { return r.description; }, function (r) { return r.created_at; }], 'No flags yet. Run scripts/monitor.php.');

        fillTable('events', data.events,
            [function (r) { return r.created_at; }, function (r) { return r.event_type; },
             function (r) { return r.username_typed; }, function (r) { return r.ip_address; },
             function (r) { return r.user_agent; }, function (r) { return r.details; }], 'No events match.');

        var select = document.getElementById('f-type');
        if (select.options.length <= 1) {
            data.types.forEach(function (t) {
                var opt = document.createElement('option');
                opt.value = t; opt.textContent = t;
                select.appendChild(opt);
            });
        }
    }

    function load() {
        fetch(feed + '?' + query(), { credentials: 'same-origin' })
            .then(function (r) {
                if (r.status === 403) { window.location.href = 'login'; throw new Error('forbidden'); }
                return r.json();
            })
            .then(render)
            .catch(function () { /* keep the last data on screen */ });
    }

    document.getElementById('filters').addEventListener('submit', function (e) { e.preventDefault(); load(); });
    load();
    setInterval(load, 60000);
})();