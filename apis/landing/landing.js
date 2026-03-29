/* --- Copy to clipboard for install block --- */
var installBlock = document.querySelector('.install-block');
if (installBlock) {
  installBlock.addEventListener('click', function() {
    navigator.clipboard.writeText('npx @mbeato/apimesh-mcp-server').then(function() {
      var h = document.querySelector('.copy-hint');
      h.textContent = 'copied';
      setTimeout(function() { h.textContent = 'copy'; }, 1500);
    });
  });
}

/* --- Mesh network animation --- */
(function() {
  var c = document.getElementById('mesh');
  var ctx = c.getContext('2d');
  var dpr = window.devicePixelRatio || 1;
  var w, h, nodes = [], raf;
  var CONNECT_DIST = 140;
  var NODE_COUNT = 40;

  function resize() {
    var wrap = c.parentElement;
    w = wrap.offsetWidth;
    h = wrap.offsetHeight;
    c.width = w * dpr;
    c.height = h * dpr;
    c.style.width = w + 'px';
    c.style.height = h + 'px';
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  }

  function init() {
    resize();
    nodes = [];
    for (var i = 0; i < NODE_COUNT; i++) {
      nodes.push({
        x: Math.random() * w,
        y: Math.random() * h,
        vx: (Math.random() - 0.5) * 0.3,
        vy: (Math.random() - 0.5) * 0.3,
        r: 1.5 + Math.random() * 1,
        pulse: Math.random() * Math.PI * 2,
        active: Math.random() < 0.15
      });
    }
  }

  function draw() {
    ctx.clearRect(0, 0, w, h);

    /* Draw connections */
    for (var i = 0; i < nodes.length; i++) {
      for (var j = i + 1; j < nodes.length; j++) {
        var dx = nodes[i].x - nodes[j].x;
        var dy = nodes[i].y - nodes[j].y;
        var dist = Math.sqrt(dx * dx + dy * dy);
        if (dist < CONNECT_DIST) {
          var alpha = (1 - dist / CONNECT_DIST) * 0.12;
          ctx.strokeStyle = 'rgba(255,255,255,' + alpha + ')';
          ctx.lineWidth = 0.5;
          ctx.beginPath();
          ctx.moveTo(nodes[i].x, nodes[i].y);
          ctx.lineTo(nodes[j].x, nodes[j].y);
          ctx.stroke();
        }
      }
    }

    /* Draw nodes */
    var t = Date.now() * 0.001;
    for (var k = 0; k < nodes.length; k++) {
      var n = nodes[k];
      var glow = n.active ? 0.15 + Math.sin(t * 1.5 + n.pulse) * 0.1 : 0;

      /* Active node glow */
      if (n.active) {
        ctx.fillStyle = 'rgba(61,220,132,' + glow + ')';
        ctx.beginPath();
        ctx.arc(n.x, n.y, 8, 0, Math.PI * 2);
        ctx.fill();
      }

      /* Node dot */
      var nodeAlpha = n.active ? 0.6 : 0.2;
      ctx.fillStyle = n.active ? 'rgba(61,220,132,' + nodeAlpha + ')' : 'rgba(255,255,255,' + nodeAlpha + ')';
      ctx.beginPath();
      ctx.arc(n.x, n.y, n.r, 0, Math.PI * 2);
      ctx.fill();
    }

    /* Occasionally toggle active states */
    if (Math.random() < 0.005) {
      var ri = Math.floor(Math.random() * nodes.length);
      nodes[ri].active = !nodes[ri].active;
    }

    /* Update positions */
    for (var m = 0; m < nodes.length; m++) {
      var nd = nodes[m];
      nd.x += nd.vx;
      nd.y += nd.vy;
      if (nd.x < 0 || nd.x > w) nd.vx *= -1;
      if (nd.y < 0 || nd.y > h) nd.vy *= -1;
      nd.x = Math.max(0, Math.min(w, nd.x));
      nd.y = Math.max(0, Math.min(h, nd.y));
    }

    raf = requestAnimationFrame(draw);
  }

  init();
  draw();
  window.addEventListener('resize', function() { resize(); });

  /* Pause when not visible */
  document.addEventListener('visibilitychange', function() {
    if (document.hidden) { cancelAnimationFrame(raf); }
    else { draw(); }
  });
})();

/* --- Scroll reveal --- */
var observer = new IntersectionObserver(function(entries) {
  entries.forEach(function(entry) {
    if (entry.isIntersecting) {
      entry.target.classList.add('visible');
      /* Trigger code typing when code block enters view */
      if (entry.target.querySelector('#code-typed')) typeCode();
    }
  });
}, { threshold: 0.15, rootMargin: '0px 0px -40px 0px' });

document.querySelectorAll('.reveal').forEach(function(el) { observer.observe(el); });

/* --- Code typing animation --- */
var codeLines = [
  '{',
  '  <span class="key">"url"</span>: <span class="str">"https://example.com"</span>,',
  '  <span class="key">"score"</span>: <span class="num">72</span>,',
  '  <span class="key">"grade"</span>: <span class="str">"B"</span>,',
  '  <span class="key">"headers"</span>: {',
  '    <span class="key">"strict-transport-security"</span>: <span class="bool">true</span>,',
  '    <span class="key">"content-security-policy"</span>: <span class="bool">false</span>,',
  '    <span class="key">"x-frame-options"</span>: <span class="bool">true</span>',
  '  },',
  '  <span class="key">"x402"</span>: { <span class="key">"paid"</span>: <span class="num">0.005</span>, <span class="key">"currency"</span>: <span class="str">"USDC"</span> }',
  '}'
];
var codeTyped = false;

function typeCode() {
  if (codeTyped) return;
  codeTyped = true;
  var el = document.getElementById('code-typed');
  var i = 0;
  var out = '';

  function nextLine() {
    if (i >= codeLines.length) {
      el.innerHTML = out;
      el.classList.add('typed');
      return;
    }
    out += (i > 0 ? '\n' : '') + codeLines[i];
    el.innerHTML = out + '<span class="code-cursor"></span>';
    i++;
    setTimeout(nextLine, 60 + Math.random() * 40);
  }
  nextLine();
}

/* --- Smooth scroll for nav links --- */
document.querySelectorAll('a[href^="#"]').forEach(function(a) {
  a.addEventListener('click', function(e) {
    var target = document.querySelector(this.getAttribute('href'));
    if (target) {
      e.preventDefault();
      target.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }
  });
});

/* --- Dynamic tool grid --- */
(function() {
  fetch('/api/tools')
    .then(function(r) { return r.json(); })
    .then(function(data) {
      var grid = document.getElementById('tool-grid');
      var count = document.querySelector('.section-count');
      if (count) count.textContent = data.count + ' endpoints';
      // Update hero count
      var heroLabel = document.querySelector('.hero-label');
      if (heroLabel) heroLabel.innerHTML = '<span class="dot"></span> ' + data.count + ' tools live on Base';

      grid.innerHTML = data.tools.map(function(t) {
        var name = t.name.replace(/-/g, ' ').replace(/\b\w/g, function(c) { return c.toUpperCase(); });
        var desc = t.description;
        if (desc.length > 80) desc = desc.substring(0, 77) + '...';
        return '<a href="https://' + t.subdomain + '.apimesh.xyz" target="_blank" class="tool stagger" style="text-decoration:none;color:inherit">' +
          '<div class="tool-header">' +
            '<span class="tool-name">' + name + '</span>' +
            '<span class="tool-price">' + t.price + '</span>' +
          '</div>' +
          '<div class="tool-desc">' + desc + '</div>' +
        '</a>';
      }).join('');
    })
    .catch(function() {});
})();
