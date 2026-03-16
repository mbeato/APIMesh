/* APIMesh Auth Pages — form handling, code input widget, strength bar */
(function () {
  "use strict";

  /* --- Utility: show/hide error messages --- */
  function showError(msg) {
    var el = document.getElementById("error-msg");
    if (!el) return;
    el.textContent = msg;
    el.classList.add("visible");
  }

  function hideError() {
    var el = document.getElementById("error-msg");
    if (!el) return;
    el.textContent = "";
    el.classList.remove("visible");
  }

  function showSuccess(msg) {
    var el = document.getElementById("success-msg");
    if (!el) return;
    el.textContent = msg;
    el.classList.add("visible");
  }

  /* --- Utility: URL params --- */
  function getParam(name) {
    var params = new URLSearchParams(window.location.search);
    return params.get(name) || "";
  }

  /* --- Utility: set button loading state --- */
  function setLoading(btn, loading, originalText) {
    if (loading) {
      btn.disabled = true;
      btn.setAttribute("data-original-text", btn.textContent);
      btn.textContent = "...";
    } else {
      btn.disabled = false;
      btn.textContent = originalText || btn.getAttribute("data-original-text") || "Submit";
    }
  }

  /* ============================================================
     Mesh Canvas Animation (adapted from landing.js)
     ============================================================ */
  function initMesh() {
    var c = document.getElementById("mesh");
    if (!c) return;
    var ctx = c.getContext("2d");
    var dpr = window.devicePixelRatio || 1;
    var w, h;
    var nodes = [];
    var raf;
    var CONNECT_DIST = 140;
    var NODE_COUNT = 30;

    function resize() {
      w = window.innerWidth;
      h = window.innerHeight;
      c.width = w * dpr;
      c.height = h * dpr;
      c.style.width = w + "px";
      c.style.height = h + "px";
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
          active: Math.random() < 0.15,
        });
      }
    }

    function draw() {
      ctx.clearRect(0, 0, w, h);

      for (var i = 0; i < nodes.length; i++) {
        for (var j = i + 1; j < nodes.length; j++) {
          var dx = nodes[i].x - nodes[j].x;
          var dy = nodes[i].y - nodes[j].y;
          var dist = Math.sqrt(dx * dx + dy * dy);
          if (dist < CONNECT_DIST) {
            var alpha = (1 - dist / CONNECT_DIST) * 0.12;
            ctx.strokeStyle = "rgba(255,255,255," + alpha + ")";
            ctx.lineWidth = 0.5;
            ctx.beginPath();
            ctx.moveTo(nodes[i].x, nodes[i].y);
            ctx.lineTo(nodes[j].x, nodes[j].y);
            ctx.stroke();
          }
        }
      }

      var t = Date.now() * 0.001;
      for (var k = 0; k < nodes.length; k++) {
        var n = nodes[k];
        var glow = n.active ? 0.15 + Math.sin(t * 1.5 + n.pulse) * 0.1 : 0;

        if (n.active) {
          ctx.fillStyle = "rgba(61,220,132," + glow + ")";
          ctx.beginPath();
          ctx.arc(n.x, n.y, 8, 0, Math.PI * 2);
          ctx.fill();
        }

        var nodeAlpha = n.active ? 0.6 : 0.2;
        ctx.fillStyle = n.active
          ? "rgba(61,220,132," + nodeAlpha + ")"
          : "rgba(255,255,255," + nodeAlpha + ")";
        ctx.beginPath();
        ctx.arc(n.x, n.y, n.r, 0, Math.PI * 2);
        ctx.fill();
      }

      if (Math.random() < 0.005) {
        var ri = Math.floor(Math.random() * nodes.length);
        nodes[ri].active = !nodes[ri].active;
      }

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
    window.addEventListener("resize", resize);

    document.addEventListener("visibilitychange", function () {
      if (document.hidden) {
        cancelAnimationFrame(raf);
      } else {
        draw();
      }
    });
  }

  /* ============================================================
     Password Strength Bar (signup page only)
     ============================================================ */
  function initStrengthBar() {
    var passwordInput = document.getElementById("password");
    var container = document.getElementById("strength-container");
    var fill = document.getElementById("strength-fill");
    var label = document.getElementById("strength-label");

    if (!passwordInput || !container || !fill || !label) return;

    var colors = ["#ef4444", "#f97316", "#eab308", "#22c55e", "#22c55e"];
    var labels = ["Weak", "Fair", "Good", "Strong", "Strong"];
    var widths = ["20%", "40%", "60%", "80%", "100%"];

    passwordInput.addEventListener("input", function () {
      var val = passwordInput.value;
      if (!val) {
        container.classList.remove("visible");
        return;
      }
      container.classList.add("visible");

      if (typeof zxcvbn === "function") {
        var result = zxcvbn(val);
        var score = result.score;
        fill.style.width = widths[score];
        fill.style.backgroundColor = colors[score];
        label.textContent = labels[score];
        label.style.color = colors[score];
      } else {
        /* zxcvbn not loaded yet — show basic feedback based on length */
        var s = val.length < 6 ? 0 : val.length < 8 ? 1 : val.length < 12 ? 2 : 3;
        fill.style.width = widths[s];
        fill.style.backgroundColor = colors[s];
        label.textContent = labels[s];
        label.style.color = colors[s];
      }
    });
  }

  /* ============================================================
     Six-Digit Code Input Widget (verify page only)
     ============================================================ */
  function initCodeInputs() {
    var inputs = document.querySelectorAll(".code-input");
    if (!inputs.length) return;

    var submitting = false;

    inputs.forEach(function (input, idx) {
      input.addEventListener("input", function (e) {
        /* Allow only digits */
        input.value = input.value.replace(/\D/g, "");
        if (input.value && idx < inputs.length - 1) {
          inputs[idx + 1].focus();
        }
        checkAutoSubmit();
      });

      input.addEventListener("keydown", function (e) {
        if (e.key === "Backspace" && !input.value && idx > 0) {
          inputs[idx - 1].focus();
          inputs[idx - 1].value = "";
          e.preventDefault();
        }
      });

      input.addEventListener("paste", function (e) {
        e.preventDefault();
        var paste = (e.clipboardData || window.clipboardData)
          .getData("text")
          .replace(/\D/g, "")
          .slice(0, 6);
        for (var i = 0; i < paste.length && i < inputs.length; i++) {
          inputs[i].value = paste[i];
        }
        if (paste.length > 0) {
          var focusIdx = Math.min(paste.length, inputs.length - 1);
          inputs[focusIdx].focus();
        }
        checkAutoSubmit();
      });

      /* Select text on focus for easy overwrite */
      input.addEventListener("focus", function () {
        input.select();
      });
    });

    function checkAutoSubmit() {
      var code = "";
      inputs.forEach(function (inp) {
        code += inp.value;
      });
      if (code.length === 6 && !submitting) {
        submitting = true;
        submitVerification(code);
      }
    }

    function submitVerification(code) {
      var email = getParam("email");
      hideError();

      fetch("/auth/verify", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email: email, code: code }),
      })
        .then(function (res) {
          return res.json().then(function (data) {
            return { status: res.status, data: data };
          });
        })
        .then(function (result) {
          if (result.data.success && result.data.redirect) {
            window.location.href = result.data.redirect;
          } else {
            showError(result.data.error || "Verification failed.");
            /* Clear inputs for retry */
            inputs.forEach(function (inp) {
              inp.value = "";
            });
            inputs[0].focus();
            submitting = false;
          }
        })
        .catch(function () {
          showError("Network error. Please try again.");
          submitting = false;
        });
    }
  }

  /* ============================================================
     Resend Code Button (verify page only)
     ============================================================ */
  function initResend() {
    var btn = document.getElementById("resend-btn");
    if (!btn) return;

    btn.addEventListener("click", function () {
      var email = getParam("email");
      if (!email) return;

      btn.disabled = true;
      hideError();

      fetch("/auth/resend-code", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email: email }),
      })
        .then(function (res) {
          return res.json();
        })
        .then(function (data) {
          if (data.error) {
            showError(data.error);
            btn.disabled = false;
          } else {
            showSuccess("Code resent! Check your inbox.");
            startCooldown(btn, 60);
          }
        })
        .catch(function () {
          showError("Network error. Please try again.");
          btn.disabled = false;
        });
    });
  }

  function startCooldown(btn, seconds) {
    var remaining = seconds;
    btn.disabled = true;
    btn.textContent = "Resend (" + remaining + "s)";

    var timer = setInterval(function () {
      remaining--;
      if (remaining <= 0) {
        clearInterval(timer);
        btn.disabled = false;
        btn.textContent = "Resend code";
      } else {
        btn.textContent = "Resend (" + remaining + "s)";
      }
    }, 1000);
  }

  /* ============================================================
     Signup Form Handler
     ============================================================ */
  function initSignupForm() {
    var form = document.getElementById("signup-form");
    if (!form) return;

    var btn = document.getElementById("submit-btn");
    var originalText = btn.textContent;

    form.addEventListener("submit", function (e) {
      e.preventDefault();
      hideError();

      var email = document.getElementById("email").value.trim();
      var password = document.getElementById("password").value;

      if (!email || !password) {
        showError("Email and password are required.");
        return;
      }

      setLoading(btn, true);

      fetch("/auth/signup", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email: email, password: password }),
      })
        .then(function (res) {
          return res.json().then(function (data) {
            return { status: res.status, data: data };
          });
        })
        .then(function (result) {
          if (result.data.success && result.data.redirect) {
            window.location.href = result.data.redirect;
          } else {
            showError(result.data.error || "Signup failed.");
            setLoading(btn, false, originalText);
          }
        })
        .catch(function () {
          showError("Network error. Please try again.");
          setLoading(btn, false, originalText);
        });
    });
  }

  /* ============================================================
     Login Form Handler
     ============================================================ */
  function initLoginForm() {
    var form = document.getElementById("login-form");
    if (!form) return;

    var btn = document.getElementById("submit-btn");
    var originalText = btn.textContent;

    form.addEventListener("submit", function (e) {
      e.preventDefault();
      hideError();

      var email = document.getElementById("email").value.trim();
      var password = document.getElementById("password").value;

      if (!email || !password) {
        showError("Email and password are required.");
        return;
      }

      setLoading(btn, true);

      fetch("/auth/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email: email, password: password }),
      })
        .then(function (res) {
          return res.json().then(function (data) {
            return { status: res.status, data: data };
          });
        })
        .then(function (result) {
          if (result.data.success && result.data.redirect) {
            window.location.href = result.data.redirect;
          } else if (result.data.error === "email_not_verified" && result.data.redirect) {
            /* Unverified user — redirect to verify page */
            window.location.href = result.data.redirect;
          } else {
            showError(result.data.error || "Invalid email or password.");
            setLoading(btn, false, originalText);
          }
        })
        .catch(function () {
          showError("Network error. Please try again.");
          setLoading(btn, false, originalText);
        });
    });
  }

  /* ============================================================
     Account Page Logout Handler
     ============================================================ */
  function initLogout() {
    var btn = document.getElementById("logout-btn");
    if (!btn) return;

    btn.addEventListener("click", function () {
      fetch("/auth/logout", { method: "POST" })
        .then(function () {
          window.location.href = "/login";
        })
        .catch(function () {
          window.location.href = "/login";
        });
    });
  }

  /* ============================================================
     Verify Page: populate email display
     ============================================================ */
  function initVerifyEmail() {
    var display = document.getElementById("email-display");
    if (!display) return;
    var email = getParam("email");
    display.textContent = email || "your email";
  }

  /* ============================================================
     Init — run on DOMContentLoaded
     ============================================================ */
  document.addEventListener("DOMContentLoaded", function () {
    initMesh();
    initStrengthBar();
    initCodeInputs();
    initResend();
    initSignupForm();
    initLoginForm();
    initLogout();
    initVerifyEmail();
  });
})();
