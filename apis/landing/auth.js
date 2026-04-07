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
        headers: { "Content-Type": "application/json", "X-Requested-With": "XMLHttpRequest" },
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
        headers: { "Content-Type": "application/json", "X-Requested-With": "XMLHttpRequest" },
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
      var confirmEl = document.getElementById("confirm-password");
      var confirm = confirmEl ? confirmEl.value : password;

      if (!email || !password) {
        showError("Email and password are required.");
        return;
      }

      if (password !== confirm) {
        showError("Passwords do not match.");
        return;
      }

      var tosCheckbox = document.getElementById("tos-agree");
      if (tosCheckbox && !tosCheckbox.checked) {
        showError("You must agree to the Terms of Service and Privacy Policy.");
        return;
      }

      setLoading(btn, true);

      fetch("/auth/signup", {
        method: "POST",
        headers: { "Content-Type": "application/json", "X-Requested-With": "XMLHttpRequest" },
        body: JSON.stringify({ email: email, password: password, tos_agree: true }),
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
        headers: { "Content-Type": "application/json", "X-Requested-With": "XMLHttpRequest" },
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
      fetch("/auth/logout", { method: "POST", headers: { "X-Requested-With": "XMLHttpRequest" } })
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
     Forgot Password Page Handler
     ============================================================ */
  function initForgotPassword() {
    var step1 = document.getElementById("forgot-step-1");
    var step2 = document.getElementById("forgot-step-2");
    if (!step1 || !step2) return;

    var storedEmail = "";

    /* --- Step 1: Send reset code --- */
    var form1 = document.getElementById("forgot-password-form");
    var btn1 = document.getElementById("submit-btn");
    if (!form1 || !btn1) return;
    var originalText1 = btn1.textContent;

    form1.addEventListener("submit", function (e) {
      e.preventDefault();
      hideError();

      var email = document.getElementById("email").value.trim();
      if (!email) {
        showError("Email is required.");
        return;
      }

      setLoading(btn1, true);

      fetch("/auth/forgot-password", {
        method: "POST",
        headers: { "Content-Type": "application/json", "X-Requested-With": "XMLHttpRequest" },
        body: JSON.stringify({ email: email }),
      })
        .then(function (res) {
          return res.json().then(function (data) {
            return { status: res.status, data: data };
          });
        })
        .then(function (result) {
          if (result.status === 429) {
            showError(result.data.error || "Too many requests. Try again later.");
            setLoading(btn1, false, originalText1);
            return;
          }
          if (result.data.error && result.status !== 200) {
            showError(result.data.error);
            setLoading(btn1, false, originalText1);
            return;
          }
          /* Always shows success (anti-enumeration) */
          storedEmail = email;
          step1.classList.add("hidden");
          step2.classList.remove("hidden");
          /* Focus first code input */
          var firstInput = step2.querySelector(".code-input");
          if (firstInput) firstInput.focus();
        })
        .catch(function () {
          showError("Network error. Please try again.");
          setLoading(btn1, false, originalText1);
        });
    });

    /* --- Step 2: Code input widget (no auto-submit, part of form) --- */
    var codeInputs = step2.querySelectorAll(".code-input");
    codeInputs.forEach(function (input, idx) {
      input.addEventListener("input", function () {
        input.value = input.value.replace(/\D/g, "");
        if (input.value && idx < codeInputs.length - 1) {
          codeInputs[idx + 1].focus();
        }
      });

      input.addEventListener("keydown", function (e) {
        if (e.key === "Backspace" && !input.value && idx > 0) {
          codeInputs[idx - 1].focus();
          codeInputs[idx - 1].value = "";
          e.preventDefault();
        }
      });

      input.addEventListener("paste", function (e) {
        e.preventDefault();
        var paste = (e.clipboardData || window.clipboardData)
          .getData("text")
          .replace(/\D/g, "")
          .slice(0, 6);
        for (var i = 0; i < paste.length && i < codeInputs.length; i++) {
          codeInputs[i].value = paste[i];
        }
        if (paste.length > 0) {
          var focusIdx = Math.min(paste.length, codeInputs.length - 1);
          codeInputs[focusIdx].focus();
        }
      });

      input.addEventListener("focus", function () {
        input.select();
      });
    });

    /* --- Step 2: Reset password form submit --- */
    var form2 = document.getElementById("reset-password-form");
    var btn2 = document.getElementById("reset-btn");
    if (!form2 || !btn2) return;
    var originalText2 = btn2.textContent;

    /* Error display for step 2 */
    function showError2(msg) {
      var el = document.getElementById("error-msg-2");
      if (!el) return;
      el.textContent = msg;
      el.classList.add("visible");
    }

    function hideError2() {
      var el = document.getElementById("error-msg-2");
      if (!el) return;
      el.textContent = "";
      el.classList.remove("visible");
    }

    form2.addEventListener("submit", function (e) {
      e.preventDefault();
      hideError2();

      /* Gather code from 6 inputs */
      var code = "";
      codeInputs.forEach(function (inp) {
        code += inp.value;
      });

      if (code.length !== 6) {
        showError2("Please enter the 6-digit code.");
        return;
      }

      var password = document.getElementById("password").value;
      var confirmEl = document.getElementById("confirm-password");
      var confirm = confirmEl ? confirmEl.value : password;

      if (!password) {
        showError2("New password is required.");
        return;
      }

      if (password !== confirm) {
        showError2("Passwords do not match.");
        return;
      }

      setLoading(btn2, true);

      fetch("/auth/reset-password", {
        method: "POST",
        headers: { "Content-Type": "application/json", "X-Requested-With": "XMLHttpRequest" },
        body: JSON.stringify({ email: storedEmail, code: code, password: password }),
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
            showError2(result.data.error || "Reset failed.");
            setLoading(btn2, false, originalText2);
          }
        })
        .catch(function () {
          showError2("Network error. Please try again.");
          setLoading(btn2, false, originalText2);
        });
    });
  }

  /* ============================================================
     Settings Page Handler (session list, revocation, change password)
     ============================================================ */
  function initSettings() {
    var page = document.getElementById("settings-page");
    if (!page) return;

    /* --- Utility: relative time --- */
    function timeAgo(dateStr) {
      var diff = (Date.now() - new Date(dateStr + "Z").getTime()) / 1000;
      if (diff < 60) return "just now";
      if (diff < 3600) return Math.floor(diff / 60) + " minutes ago";
      if (diff < 86400) return Math.floor(diff / 3600) + " hours ago";
      return Math.floor(diff / 86400) + " days ago";
    }

    /* --- Utility: settings page error/success messages --- */
    function showMsg(id, msg) {
      var el = document.getElementById(id);
      if (!el) return;
      el.textContent = msg;
      el.classList.add("visible");
    }

    function hideMsg(id) {
      var el = document.getElementById(id);
      if (!el) return;
      el.textContent = "";
      el.classList.remove("visible");
    }

    /* --- Session list loader --- */
    var sessionListEl = document.getElementById("session-list");

    function loadSessions() {
      fetch("/auth/sessions")
        .then(function (res) {
          if (!res.ok) throw new Error("Failed to load sessions");
          return res.json();
        })
        .then(function (sessions) {
          renderSessions(sessions);
        })
        .catch(function () {
          sessionListEl.innerHTML = '<div class="sessions-empty">Failed to load sessions.</div>';
        });
    }

    function renderSessions(sessions) {
      if (!sessions.length) {
        sessionListEl.innerHTML = '<div class="sessions-empty">No active sessions found.</div>';
        return;
      }

      sessionListEl.innerHTML = "";
      sessions.forEach(function (s) {
        var card = document.createElement("div");
        card.className = "session-card" + (s.is_current ? " current" : "");

        var info = document.createElement("div");
        info.className = "session-info";

        var device = document.createElement("div");
        device.className = "session-device";
        device.textContent = s.browser + " on " + s.os;
        if (s.is_current) {
          var badge = document.createElement("span");
          badge.className = "session-badge";
          badge.textContent = "Current session";
          device.appendChild(badge);
        }

        var meta = document.createElement("div");
        meta.className = "session-meta";
        meta.textContent = s.ip_address + " \u00B7 " + timeAgo(s.created_at);

        info.appendChild(device);
        info.appendChild(meta);
        card.appendChild(info);

        if (!s.is_current) {
          var actions = document.createElement("div");
          actions.className = "session-actions";
          var btn = document.createElement("button");
          btn.className = "btn-revoke";
          btn.textContent = "Revoke";
          btn.setAttribute("data-session-id", s.id);
          btn.addEventListener("click", function () {
            revokeSession(s.id, card);
          });
          actions.appendChild(btn);
          card.appendChild(actions);
        }

        sessionListEl.appendChild(card);
      });
    }

    /* --- Revoke individual session --- */
    function revokeSession(sessionId, cardEl) {
      hideMsg("sessions-error-msg");
      hideMsg("sessions-success-msg");

      fetch("/auth/sessions/" + encodeURIComponent(sessionId), { method: "DELETE", headers: { "X-Requested-With": "XMLHttpRequest" } })
        .then(function (res) {
          return res.json().then(function (data) {
            return { status: res.status, data: data };
          });
        })
        .then(function (result) {
          if (result.data.success) {
            cardEl.remove();
            showMsg("sessions-success-msg", "Session revoked.");
          } else {
            showMsg("sessions-error-msg", result.data.error || "Failed to revoke session.");
          }
        })
        .catch(function () {
          showMsg("sessions-error-msg", "Network error. Please try again.");
        });
    }

    /* --- Revoke all other sessions --- */
    var revokeAllBtn = document.getElementById("revoke-all-btn");
    if (revokeAllBtn) {
      revokeAllBtn.addEventListener("click", function () {
        if (!confirm("Revoke all other sessions? You will remain logged in on this device.")) return;

        hideMsg("sessions-error-msg");
        hideMsg("sessions-success-msg");
        revokeAllBtn.disabled = true;

        fetch("/auth/sessions", { method: "DELETE", headers: { "X-Requested-With": "XMLHttpRequest" } })
          .then(function (res) {
            return res.json().then(function (data) {
              return { status: res.status, data: data };
            });
          })
          .then(function (result) {
            revokeAllBtn.disabled = false;
            if (result.data.success) {
              showMsg("sessions-success-msg", "All other sessions revoked.");
              loadSessions();
            } else {
              showMsg("sessions-error-msg", result.data.error || "Failed to revoke sessions.");
            }
          })
          .catch(function () {
            revokeAllBtn.disabled = false;
            showMsg("sessions-error-msg", "Network error. Please try again.");
          });
      });
    }

    /* --- Change password form --- */
    var pwForm = document.getElementById("change-password-form");
    var pwBtn = document.getElementById("change-pw-btn");
    if (pwForm && pwBtn) {
      var pwOriginalText = pwBtn.textContent;

      pwForm.addEventListener("submit", function (e) {
        e.preventDefault();
        hideMsg("pw-error-msg");
        hideMsg("pw-success-msg");

        var currentPassword = document.getElementById("current-password").value;
        var newPassword = document.getElementById("new-password").value;
        var confirmPassword = document.getElementById("confirm-new-password").value;

        if (!currentPassword || !newPassword) {
          showMsg("pw-error-msg", "All fields are required.");
          return;
        }

        if (newPassword !== confirmPassword) {
          showMsg("pw-error-msg", "New passwords do not match.");
          return;
        }

        setLoading(pwBtn, true);

        fetch("/auth/change-password", {
          method: "POST",
          headers: { "Content-Type": "application/json", "X-Requested-With": "XMLHttpRequest" },
          body: JSON.stringify({ currentPassword: currentPassword, newPassword: newPassword }),
        })
          .then(function (res) {
            return res.json().then(function (data) {
              return { status: res.status, data: data };
            });
          })
          .then(function (result) {
            if (result.data.success) {
              showMsg("pw-success-msg", "Password changed successfully.");
              pwForm.reset();
              /* Hide strength bar */
              var sc = document.getElementById("strength-container");
              if (sc) sc.classList.remove("visible");
            } else {
              showMsg("pw-error-msg", result.data.error || "Failed to change password.");
            }
            setLoading(pwBtn, false, pwOriginalText);
          })
          .catch(function () {
            showMsg("pw-error-msg", "Network error. Please try again.");
            setLoading(pwBtn, false, pwOriginalText);
          });
      });
    }

    /* --- Password strength bar for new password field --- */
    var newPwInput = document.getElementById("new-password");
    var strengthContainer = document.getElementById("strength-container");
    var strengthFill = document.getElementById("strength-fill");
    var strengthLabel = document.getElementById("strength-label");

    if (newPwInput && strengthContainer && strengthFill && strengthLabel) {
      var colors = ["#ef4444", "#f97316", "#eab308", "#22c55e", "#22c55e"];
      var labels = ["Weak", "Fair", "Good", "Strong", "Strong"];
      var widths = ["20%", "40%", "60%", "80%", "100%"];

      newPwInput.addEventListener("input", function () {
        var val = newPwInput.value;
        if (!val) {
          strengthContainer.classList.remove("visible");
          return;
        }
        strengthContainer.classList.add("visible");

        if (typeof zxcvbn === "function") {
          var result = zxcvbn(val);
          var score = result.score;
          strengthFill.style.width = widths[score];
          strengthFill.style.backgroundColor = colors[score];
          strengthLabel.textContent = labels[score];
          strengthLabel.style.color = colors[score];
        } else {
          var s = val.length < 6 ? 0 : val.length < 8 ? 1 : val.length < 12 ? 2 : 3;
          strengthFill.style.width = widths[s];
          strengthFill.style.backgroundColor = colors[s];
          strengthLabel.textContent = labels[s];
          strengthLabel.style.color = colors[s];
        }
      });
    }

    /* --- Danger Zone: Logout all sessions --- */
    var logoutAllBtn = document.getElementById("logout-all-btn");
    if (logoutAllBtn) {
      logoutAllBtn.addEventListener("click", function () {
        if (!confirm("Log out from ALL devices? You will be redirected to the login page.")) return;

        logoutAllBtn.disabled = true;

        fetch("/auth/logout", { method: "POST", headers: { "X-Requested-With": "XMLHttpRequest" } })
          .then(function () {
            window.location.href = "/login";
          })
          .catch(function () {
            window.location.href = "/login";
          });
      });
    }

    /* --- Initial load --- */
    loadSessions();
  }

  /* ============================================================
     API Keys Page Handler (create, list, copy, revoke)
     ============================================================ */
  function initApiKeys() {
    var page = document.getElementById("keys-page");
    if (!page) return;

    var activeKeyCount = 0;
    var MAX_KEYS = 5;

    var keyListEl = document.getElementById("key-list");
    var keyCountEl = document.getElementById("key-count");
    var createSection = document.getElementById("create-key-section");
    var newKeyDisplay = document.getElementById("new-key-display");
    var createBtn = document.getElementById("create-key-btn");
    var form = document.getElementById("create-key-form");
    var labelInput = document.getElementById("key-label");
    var copyBtn = document.getElementById("copy-key-btn");
    var dismissBtn = document.getElementById("dismiss-key-btn");
    var newKeyValueEl = document.getElementById("new-key-value");

    /* --- Utility: relative time --- */
    function timeAgo(dateStr) {
      var diff = (Date.now() - new Date(dateStr + "Z").getTime()) / 1000;
      if (diff < 60) return "just now";
      if (diff < 3600) return Math.floor(diff / 60) + " minutes ago";
      if (diff < 86400) return Math.floor(diff / 3600) + " hours ago";
      return Math.floor(diff / 86400) + " days ago";
    }

    /* --- Utility: message display --- */
    function showMsg(id, msg) {
      var el = document.getElementById(id);
      if (!el) return;
      el.textContent = msg;
      el.classList.add("visible");
    }

    function hideMsg(id) {
      var el = document.getElementById(id);
      if (!el) return;
      el.textContent = "";
      el.classList.remove("visible");
    }

    /* --- Load keys from API --- */
    function loadKeys() {
      fetch("/auth/keys")
        .then(function (res) {
          if (!res.ok) throw new Error("Failed to load keys");
          return res.json();
        })
        .then(function (data) {
          renderKeys(data.keys || []);
        })
        .catch(function () {
          keyListEl.innerHTML = '<div class="keys-empty">Failed to load keys.</div>';
        });
    }

    /* --- Render key list --- */
    function renderKeys(keys) {
      activeKeyCount = 0;
      keys.forEach(function (k) {
        if (!k.revoked) activeKeyCount++;
      });

      /* Update count indicator */
      keyCountEl.textContent = activeKeyCount + " of " + MAX_KEYS + " keys used";

      /* Enable/disable create button */
      if (createBtn) {
        createBtn.disabled = activeKeyCount >= MAX_KEYS;
      }

      if (!keys.length) {
        keyListEl.innerHTML = '<div class="keys-empty">No API keys yet. Create one to get started.</div>';
        return;
      }

      keyListEl.innerHTML = "";
      keys.forEach(function (key) {
        var card = document.createElement("div");
        card.className = "key-card" + (key.revoked ? " revoked" : "");

        var info = document.createElement("div");
        info.className = "key-info";

        var topRow = document.createElement("div");
        topRow.className = "key-top-row";

        var statusDot = document.createElement("div");
        statusDot.className = "key-status " + (key.revoked ? "revoked" : "active");

        var prefix = document.createElement("span");
        prefix.className = "key-prefix";
        prefix.textContent = key.key_prefix + "...";

        var label = document.createElement("span");
        label.className = "key-label";
        label.textContent = key.label;

        topRow.appendChild(statusDot);
        topRow.appendChild(prefix);
        topRow.appendChild(label);

        var meta = document.createElement("div");
        meta.className = "key-meta";
        var lastUsed = key.last_used_at ? timeAgo(key.last_used_at) : "Never";
        meta.textContent = "Last used: " + lastUsed + " \u00B7 Created: " + timeAgo(key.created_at);

        info.appendChild(topRow);
        info.appendChild(meta);
        card.appendChild(info);

        if (!key.revoked) {
          var actions = document.createElement("div");
          actions.className = "key-actions";
          var revokeBtn = document.createElement("button");
          revokeBtn.className = "btn-revoke";
          revokeBtn.textContent = "Revoke";
          revokeBtn.addEventListener("click", function () {
            revokeKey(key.id);
          });
          actions.appendChild(revokeBtn);
          card.appendChild(actions);
        } else {
          var revokedLabel = document.createElement("div");
          revokedLabel.className = "key-actions";
          var revokedText = document.createElement("span");
          revokedText.className = "key-revoked-label";
          revokedText.textContent = "Revoked";
          revokedLabel.appendChild(revokedText);
          card.appendChild(revokedLabel);
        }

        keyListEl.appendChild(card);
      });
    }

    /* --- Create key form handler --- */
    if (form) {
      form.addEventListener("submit", function (e) {
        e.preventDefault();
        hideMsg("keys-error-msg");
        hideMsg("keys-success-msg");

        var label = labelInput.value.trim();
        if (!label) {
          showMsg("keys-error-msg", "Label is required.");
          return;
        }
        if (label.length > 64) {
          showMsg("keys-error-msg", "Label must be 64 characters or less.");
          return;
        }

        setLoading(createBtn, true);

        fetch("/auth/keys", {
          method: "POST",
          headers: { "Content-Type": "application/json", "X-Requested-With": "XMLHttpRequest" },
          body: JSON.stringify({ label: label }),
        })
          .then(function (res) {
            return res.json().then(function (data) {
              return { status: res.status, data: data };
            });
          })
          .then(function (result) {
            setLoading(createBtn, false, "Create Key");
            if (result.data.success && result.data.key) {
              /* Show one-time key display */
              newKeyValueEl.textContent = result.data.key.plaintext;
              newKeyDisplay.classList.add("visible");
              createSection.style.display = "none";
              loadKeys();
            } else {
              showMsg("keys-error-msg", result.data.error || "Failed to create key.");
            }
          })
          .catch(function () {
            setLoading(createBtn, false, "Create Key");
            showMsg("keys-error-msg", "Network error. Please try again.");
          });
      });
    }

    /* --- Copy button handler --- */
    if (copyBtn) {
      copyBtn.addEventListener("click", function () {
        var keyText = newKeyValueEl.textContent;
        if (navigator.clipboard && navigator.clipboard.writeText) {
          navigator.clipboard.writeText(keyText).then(function () {
            copyBtn.textContent = "Copied!";
            setTimeout(function () { copyBtn.textContent = "Copy"; }, 2000);
          }).catch(function () {
            fallbackCopy(keyText);
          });
        } else {
          fallbackCopy(keyText);
        }
      });
    }

    function fallbackCopy(text) {
      var textarea = document.createElement("textarea");
      textarea.value = text;
      textarea.style.position = "fixed";
      textarea.style.opacity = "0";
      document.body.appendChild(textarea);
      textarea.select();
      try {
        document.execCommand("copy");
        copyBtn.textContent = "Copied!";
        setTimeout(function () { copyBtn.textContent = "Copy"; }, 2000);
      } catch (e) {
        copyBtn.textContent = "Failed";
        setTimeout(function () { copyBtn.textContent = "Copy"; }, 2000);
      }
      document.body.removeChild(textarea);
    }

    /* --- Dismiss button handler --- */
    if (dismissBtn) {
      dismissBtn.addEventListener("click", function () {
        newKeyDisplay.classList.remove("visible");
        newKeyValueEl.textContent = "";
        createSection.style.display = "";
        labelInput.value = "";
        loadKeys();
      });
    }

    /* --- Revoke key handler --- */
    function revokeKey(keyId) {
      if (!confirm("Revoke this API key? This cannot be undone. Any applications using this key will stop working.")) return;

      hideMsg("keys-error-msg");
      hideMsg("keys-success-msg");

      fetch("/auth/keys/" + encodeURIComponent(keyId), { method: "DELETE", headers: { "X-Requested-With": "XMLHttpRequest" } })
        .then(function (res) {
          return res.json().then(function (data) {
            return { status: res.status, data: data };
          });
        })
        .then(function (result) {
          if (result.data.success) {
            showMsg("keys-success-msg", "API key revoked.");
            loadKeys();
          } else {
            showMsg("keys-error-msg", result.data.error || "Failed to revoke key.");
          }
        })
        .catch(function () {
          showMsg("keys-error-msg", "Network error. Please try again.");
        });
    }

    /* --- Initial load --- */
    loadKeys();
  }

  /* ============================================================
     Billing Page
     ============================================================ */
  function initBilling() {
    // Load balance
    fetch("/billing/balance", { credentials: "same-origin" })
      .then(function (r) { return r.json(); })
      .then(function (data) {
        var el = document.getElementById("balance-display");
        if (el && data.balance_microdollars !== undefined) {
          var dollars = (data.balance_microdollars / 100000).toFixed(2);
          el.textContent = "$" + dollars;
        }
      })
      .catch(function () {
        var el = document.getElementById("balance-display");
        if (el) el.textContent = "Error loading balance";
      });

    // Check for success/cancel feedback from Stripe redirect
    var billingStatus = getParam("billing");
    if (billingStatus === "success") {
      showSuccess("Payment successful! Credits have been added to your account.");
    } else if (billingStatus === "cancelled") {
      showError("Payment was cancelled. No charges were made.");
    }

    // Buy button handlers
    var buyButtons = document.querySelectorAll(".btn-buy[data-tier]");
    buyButtons.forEach(function (btn) {
      btn.addEventListener("click", function () {
        var tier = btn.getAttribute("data-tier");
        setLoading(btn, true);
        hideError();

        fetch("/billing/checkout", {
          method: "POST",
          credentials: "same-origin",
          headers: { "Content-Type": "application/json", "X-Requested-With": "XMLHttpRequest" },
          body: JSON.stringify({ tier: tier }),
        })
          .then(function (r) { return r.json(); })
          .then(function (data) {
            if (data.checkout_url) {
              try {
                var parsed = new URL(data.checkout_url);
                if (parsed.protocol !== "https:" || parsed.hostname !== "checkout.stripe.com") {
                  showError("Invalid checkout URL. Please try again.");
                  setLoading(btn, false);
                  return;
                }
                window.location.href = data.checkout_url;
              } catch (e) {
                showError("Invalid checkout URL. Please try again.");
                setLoading(btn, false);
              }
            } else {
              showError(data.error || "Failed to start checkout");
              setLoading(btn, false);
            }
          })
          .catch(function () {
            showError("Network error. Please try again.");
            setLoading(btn, false);
          });
      });
    });

    /* --- Transaction History --- */
    var txnBody = document.getElementById("txn-body");
    var loadMoreBtn = document.getElementById("load-more-btn");
    var txnOffset = 0;
    var TXN_LIMIT = 20;

    function formatDate(dateStr) {
      var d = new Date(dateStr + "Z");
      var month = String(d.getMonth() + 1).padStart(2, "0");
      var day = String(d.getDate()).padStart(2, "0");
      var hours = String(d.getHours()).padStart(2, "0");
      var mins = String(d.getMinutes()).padStart(2, "0");
      return d.getFullYear() + "-" + month + "-" + day + " " + hours + ":" + mins;
    }

    function formatAmount(microdollars) {
      var dollars = Math.abs(microdollars) / 100000;
      var sign = microdollars >= 0 ? "+" : "-";
      return sign + "$" + dollars.toFixed(2);
    }

    function loadTransactions(append) {
      fetch("/billing/transactions?limit=" + TXN_LIMIT + "&offset=" + txnOffset, { credentials: "same-origin" })
        .then(function (r) { return r.json(); })
        .then(function (data) {
          var txns = data.transactions || [];
          if (!append) txnBody.innerHTML = "";

          if (txns.length === 0 && txnOffset === 0) {
            txnBody.innerHTML = '<tr><td colspan="4" class="txn-empty">No transactions yet.</td></tr>';
            loadMoreBtn.style.display = "none";
            return;
          }

          txns.forEach(function (txn) {
            var tr = document.createElement("tr");

            var tdType = document.createElement("td");
            var badge = document.createElement("span");
            badge.className = "txn-type " + txn.type;
            badge.textContent = txn.type;
            tdType.appendChild(badge);

            var tdDesc = document.createElement("td");
            tdDesc.className = "txn-desc";
            tdDesc.textContent = txn.description || txn.api_name || "-";
            tdDesc.title = txn.description || "";

            var tdAmount = document.createElement("td");
            tdAmount.className = "txn-amount " + (txn.amount_microdollars >= 0 ? "positive" : "negative");
            tdAmount.textContent = formatAmount(txn.amount_microdollars);

            var tdDate = document.createElement("td");
            tdDate.className = "txn-date";
            tdDate.textContent = formatDate(txn.created_at);

            tr.appendChild(tdType);
            tr.appendChild(tdDesc);
            tr.appendChild(tdAmount);
            tr.appendChild(tdDate);
            txnBody.appendChild(tr);
          });

          loadMoreBtn.style.display = txns.length < TXN_LIMIT ? "none" : "block";
          if (loadMoreBtn) loadMoreBtn.disabled = false;
        })
        .catch(function () {
          if (!append) {
            txnBody.innerHTML = '<tr><td colspan="4" class="txn-empty">Failed to load transactions.</td></tr>';
          }
          if (loadMoreBtn) loadMoreBtn.disabled = false;
        });
    }

    if (txnBody) {
      loadTransactions(false);
    }

    if (loadMoreBtn) {
      loadMoreBtn.addEventListener("click", function () {
        if (loadMoreBtn.disabled) return;
        txnOffset += TXN_LIMIT;
        loadMoreBtn.disabled = true;
        loadTransactions(true);
      });
    }

    /* --- Alert Threshold --- */
    var alertInput = document.getElementById("alert-threshold-input");
    var setAlertBtn = document.getElementById("set-alert-btn");
    var clearAlertBtn = document.getElementById("clear-alert-btn");
    var alertStatus = document.getElementById("alert-status");

    function loadAlertThreshold() {
      fetch("/billing/alert-threshold", { credentials: "same-origin" })
        .then(function (r) { return r.json(); })
        .then(function (data) {
          if (data.threshold_microdollars) {
            var dollars = (data.threshold_microdollars / 100000).toFixed(2);
            alertInput.value = dollars;
            alertStatus.textContent = "Alert enabled: you will be emailed when balance drops below $" + dollars;
          } else {
            alertInput.value = "";
            alertStatus.textContent = "Alerts disabled. Enter a dollar amount to enable.";
          }
        })
        .catch(function () {
          alertStatus.textContent = "Failed to load alert settings.";
        });
    }

    if (alertInput && setAlertBtn) {
      loadAlertThreshold();

      setAlertBtn.addEventListener("click", function () {
        var val = parseFloat(alertInput.value);
        if (isNaN(val) || val <= 0) {
          alertStatus.textContent = "Enter a valid dollar amount (e.g. 5.00).";
          return;
        }

        var microdollars = Math.round(val * 100000);
        setAlertBtn.disabled = true;

        fetch("/billing/alert-threshold", {
          method: "POST",
          credentials: "same-origin",
          headers: { "Content-Type": "application/json", "X-Requested-With": "XMLHttpRequest" },
          body: JSON.stringify({ threshold_microdollars: microdollars }),
        })
          .then(function (r) { return r.json(); })
          .then(function (data) {
            setAlertBtn.disabled = false;
            if (data.success) {
              alertStatus.textContent = "Alert enabled: you will be emailed when balance drops below $" + val.toFixed(2);
            } else {
              alertStatus.textContent = data.error || "Failed to set alert.";
            }
          })
          .catch(function () {
            setAlertBtn.disabled = false;
            alertStatus.textContent = "Network error. Please try again.";
          });
      });
    }

    if (clearAlertBtn) {
      clearAlertBtn.addEventListener("click", function () {
        clearAlertBtn.disabled = true;

        fetch("/billing/alert-threshold", {
          method: "POST",
          credentials: "same-origin",
          headers: { "Content-Type": "application/json", "X-Requested-With": "XMLHttpRequest" },
          body: JSON.stringify({ threshold_microdollars: null }),
        })
          .then(function (r) { return r.json(); })
          .then(function (data) {
            clearAlertBtn.disabled = false;
            if (data.success) {
              alertInput.value = "";
              alertStatus.textContent = "Alerts disabled. Enter a dollar amount to enable.";
            } else {
              alertStatus.textContent = data.error || "Failed to disable alert.";
            }
          })
          .catch(function () {
            clearAlertBtn.disabled = false;
            alertStatus.textContent = "Network error. Please try again.";
          });
      });
    }
  }

  /* ============================================================
     Account Overview Page
     ============================================================ */
  function initAccountOverview() {
    var page = document.getElementById("account-overview");
    if (!page) return;

    fetch("/account/overview", { credentials: "same-origin" })
      .then(function (r) { return r.json(); })
      .then(function (data) {
        /* Balance */
        var balEl = document.getElementById("overview-balance");
        if (balEl && data.balance_microdollars !== undefined) {
          var dollars = (data.balance_microdollars / 100000).toFixed(2);
          balEl.textContent = "$" + dollars;
        }

        /* Active keys */
        var keysEl = document.getElementById("overview-active-keys");
        if (keysEl) {
          keysEl.textContent = data.active_key_count + " of " + data.max_keys;
        }

        /* Alert status */
        var alertEl = document.getElementById("overview-alert-status");
        if (alertEl) {
          if (data.alert_threshold_microdollars) {
            var threshold = (data.alert_threshold_microdollars / 100000).toFixed(2);
            alertEl.textContent = "Alert at $" + threshold;
          } else {
            alertEl.textContent = "Not configured";
          }
        }

        /* Recent transactions */
        var txnList = document.getElementById("overview-txn-list");
        if (txnList && data.recent_transactions) {
          if (data.recent_transactions.length === 0) {
            txnList.innerHTML = '<div class="overview-txn-empty">No transactions yet</div>';
            return;
          }

          txnList.innerHTML = "";
          data.recent_transactions.forEach(function (txn) {
            var row = document.createElement("div");
            row.className = "overview-txn-row";

            var left = document.createElement("div");
            left.className = "overview-txn-left";

            var badge = document.createElement("span");
            badge.className = "overview-txn-type " + txn.type;
            badge.textContent = txn.type;

            var desc = document.createElement("span");
            desc.className = "overview-txn-desc";
            desc.textContent = txn.description || txn.api_name || "-";

            left.appendChild(badge);
            left.appendChild(desc);

            var amount = document.createElement("div");
            amount.className = "overview-txn-amount " + (txn.amount_microdollars >= 0 ? "positive" : "negative");
            var dollars = Math.abs(txn.amount_microdollars) / 100000;
            amount.textContent = (txn.amount_microdollars >= 0 ? "+" : "-") + "$" + dollars.toFixed(2);

            row.appendChild(left);
            row.appendChild(amount);
            txnList.appendChild(row);
          });
        }
      })
      .catch(function () {
        var balEl = document.getElementById("overview-balance");
        if (balEl) balEl.textContent = "Error";
      });
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
    initForgotPassword();
    initSettings();
    initApiKeys();
    if (document.getElementById("billing-page")) { initBilling(); }
    if (document.getElementById("account-overview")) { initAccountOverview(); }
  });
})();
