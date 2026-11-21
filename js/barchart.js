/* A tiny bar chart drawn on a <canvas>, so the dashboard needs no outside library. */
var BarChart = (function () {
    'use strict';

    function draw(canvas, labels, values) {
        var ctx = canvas.getContext('2d');
        var w = canvas.width, h = canvas.height;
        var pad = { l: 40, r: 10, t: 10, b: 30 };
        var max = Math.max(5, Math.max.apply(null, values));
        var plotW = w - pad.l - pad.r, plotH = h - pad.t - pad.b;
        var slot = plotW / values.length;

        ctx.clearRect(0, 0, w, h);
        ctx.font = '11px Arial';
        ctx.fillStyle = '#516173';
        ctx.strokeStyle = '#dde5ed';

        for (var g = 0; g <= 4; g++) {
            var y = pad.t + plotH - (plotH * g / 4);
            ctx.beginPath(); ctx.moveTo(pad.l, y); ctx.lineTo(w - pad.r, y); ctx.stroke();
            ctx.textAlign = 'right';
            ctx.fillText(String(Math.round(max * g / 4)), pad.l - 6, y + 4);
        }

        values.forEach(function (v, i) {
            var bh = plotH * v / max;
            var x = pad.l + i * slot + slot * 0.15;
            ctx.fillStyle = '#c0392b';
            ctx.fillRect(x, pad.t + plotH - bh, slot * 0.7, bh);
            if (i % 3 === 0) {
                ctx.fillStyle = '#516173';
                ctx.textAlign = 'center';
                ctx.fillText(labels[i], x + slot * 0.35, h - 10);
            }
        });
    }

    return { draw: draw };
})();
