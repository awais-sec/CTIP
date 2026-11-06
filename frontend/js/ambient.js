/* Ambient background — a quieter cousin of the same effect used on
   awaisahmed.dev: a connected particle network plus faint falling
   "digital rain" streams, in the site's cyan accent. Respects
   prefers-reduced-motion and thins out on mobile, same as the source. */
(function () {
  const cvs = document.getElementById("ambientCanvas");
  if (!cvs) return;
  const reduced = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  if (reduced) return;

  const ctx = cvs.getContext("2d");
  let W, H, particles = [], streams = [];
  const isMob = () => window.innerWidth <= 768;

  function resize() {
    W = cvs.width = window.innerWidth;
    H = cvs.height = window.innerHeight;
  }
  resize();
  window.addEventListener("resize", resize);

  function hexA(hex, a) {
    const r = parseInt(hex.slice(1, 3), 16), g = parseInt(hex.slice(3, 5), 16), b = parseInt(hex.slice(5, 7), 16);
    return `rgba(${r},${g},${b},${a})`;
  }

  function mkParticle() {
    return {
      x: Math.random() * W,
      y: Math.random() * H,
      vx: (Math.random() - 0.5) * 0.35,
      vy: Math.random() * 0.3 + 0.08,
      r: Math.random() * 1.6 + 0.5,
    };
  }
  function initParticles() {
    particles = Array.from({ length: isMob() ? 18 : 42 }, mkParticle);
  }

  const CHARS = "01アイウエ░▒▓";
  function mkStream() {
    return {
      x: Math.random() * W,
      y: Math.random() * H,
      sp: Math.random() * 1.4 + 0.5,
      len: Math.random() * 70 + 30,
      t: 0,
      ch: "0",
    };
  }
  function initStreams() {
    streams = Array.from({ length: isMob() ? 3 : 7 }, mkStream);
  }

  initParticles();
  initStreams();

  function loop() {
    ctx.clearRect(0, 0, W, H);
    const col = "#00d4ff";

    // digital-rain style streams
    streams.forEach((s) => {
      s.y += s.sp;
      s.t++;
      if (s.t % 12 === 0) s.ch = CHARS[Math.floor(Math.random() * CHARS.length)];
      if (s.y > H + s.len) {
        s.y = -s.len;
        s.x = Math.random() * W;
      }
      const g = ctx.createLinearGradient(s.x, s.y - s.len, s.x, s.y);
      g.addColorStop(0, "transparent");
      g.addColorStop(0.7, hexA(col, 0.08));
      g.addColorStop(1, hexA(col, 0.14));
      ctx.save();
      ctx.strokeStyle = g;
      ctx.lineWidth = 1;
      ctx.beginPath();
      ctx.moveTo(s.x, s.y - s.len);
      ctx.lineTo(s.x, s.y);
      ctx.stroke();
      ctx.globalAlpha = 0.4;
      ctx.fillStyle = col;
      ctx.font = "bold 9px 'DM Mono', monospace";
      ctx.textAlign = "center";
      ctx.fillText(s.ch, s.x, s.y);
      ctx.restore();
    });

    // particle network
    particles.forEach((p) => {
      p.x += p.vx;
      p.y += p.vy;
      if (p.y > H + 10) { p.y = -10; p.x = Math.random() * W; }
      if (p.x < -10) p.x = W + 10;
      if (p.x > W + 10) p.x = -10;
    });

    if (!isMob()) {
      for (let i = 0; i < particles.length; i++) {
        for (let j = i + 1; j < particles.length; j++) {
          const dx = particles[i].x - particles[j].x;
          const dy = particles[i].y - particles[j].y;
          const d = Math.sqrt(dx * dx + dy * dy);
          if (d < 110) {
            ctx.save();
            ctx.globalAlpha = (1 - d / 110) * 0.1;
            ctx.strokeStyle = col;
            ctx.lineWidth = 0.6;
            ctx.beginPath();
            ctx.moveTo(particles[i].x, particles[i].y);
            ctx.lineTo(particles[j].x, particles[j].y);
            ctx.stroke();
            ctx.restore();
          }
        }
      }
    }

    ctx.save();
    ctx.globalAlpha = 0.55;
    ctx.fillStyle = col;
    particles.forEach((p) => {
      ctx.beginPath();
      ctx.arc(p.x, p.y, p.r, 0, Math.PI * 2);
      ctx.fill();
    });
    ctx.restore();

    requestAnimationFrame(loop);
  }

  requestAnimationFrame(loop);
})();
