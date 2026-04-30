(function () {
  'use strict';

  // ==================== State ====================
  let ws = null;
  let reconnectTimer = null;
  let idleTimer = null;
  let pollTimer = null;
  let devices = [];
  let selectedIP = '';
  let currentState = null;
  let progressInterval = null;
  let overlayTimeout = 4000; // ms before controls fade

  // ==================== DOM Elements ====================
  const $ = (sel) => document.querySelector(sel);
  const $$ = (sel) => document.querySelectorAll(sel);

  const artImg = $('#art-img');
  const artPlaceholder = $('#art-placeholder');
  const titleEl = $('#title');
  const artistEl = $('#artist');
  const albumEl = $('#album');
  const qualityBadge = $('#quality-badge');
  const deviceName = $('#device-name');
  const deviceBtn = $('#device-btn');
  const deviceList = $('#device-list');
  const deviceItems = $('#device-items');
  const discoverBtn = $('#discover-btn');
  const playBtn = $('#play-btn');
  const prevBtn = $('#prev-btn');
  const nextBtn = $('#next-btn');
  const playIcon = $('#play-icon');
  const pauseIcon = $('#pause-icon');
  const volumeSlider = $('#volume-slider');
  const volumeVal = $('#volume-val');
  const muteBtn = $('#mute-btn');
  const volIcon = $('#vol-icon');
  const muteIcon = $('#mute-icon');
  const progressBar = $('#progress-bar');
  const progressFill = $('#progress-fill');
  const relTimeEl = $('#rel-time');
  const durationEl = $('#duration');
  const sourceBtn = $('#source-btn');
  const sourceList = $('#source-list');
  const eqBtn = $('#eq-btn');
  const eqList = $('#eq-list');

  // ==================== WebSocket ====================
  function connect() {
    const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    ws = new WebSocket(`${proto}//${window.location.host}/ws`);

    ws.onopen = () => {
      updateConnectionStatus(true);
      resetIdleTimer();
    };

    ws.onclose = () => {
      updateConnectionStatus(false);
      clearTimeout(reconnectTimer);
      reconnectTimer = setTimeout(connect, 2000);
    };

    ws.onmessage = (e) => {
      try {
        const msg = JSON.parse(e.data);
        handleMessage(msg);
      } catch (err) {
        console.error('Parse error:', err);
      }
    };

    ws.onerror = () => {
      ws.close();
    };
  }

  function send(action, data) {
    if (ws && ws.readyState === WebSocket.OPEN) {
      ws.send(JSON.stringify({ action, ...data }));
    }
  }

  function handleMessage(msg) {
    resetIdleTimer();

    switch (msg.type) {
      case 'devices':
        devices = msg.devices || [];
        selectedIP = msg.selected || '';
        renderDevices();
        break;

      case 'selected':
        selectedIP = msg.selected;
        renderDevices();
        break;

      case 'state':
        updateState(msg.data);
        break;
    }
  }

  function updateConnectionStatus(connected) {
    let el = $('#connection-status');
    if (!el) {
      el = document.createElement('div');
      el.id = 'connection-status';
      document.body.appendChild(el);
    }
    el.className = connected ? 'connected' : 'disconnected';
    el.textContent = connected ? 'Connected' : 'Disconnected';
  }

  // ==================== State Updates ====================
  function updateState(data) {
    currentState = data;

    // Device name
    deviceName.textContent = data.name || 'WiiM Device';

    // Track info
    const title = data.title || '';
    const artist = data.artist || '';
    const album = data.album || '';

    titleEl.textContent = title || 'Not Playing';
    artistEl.textContent = artist;
    albumEl.textContent = album;

    // Album art
    const artUrl = data.albumArtUrl || '';
    if (artUrl) {
      const proxyUrl = `/albumart?url=${encodeURIComponent(artUrl)}`;
      artImg.src = proxyUrl;
      artImg.style.display = 'block';
      artPlaceholder.style.display = 'none';
      artImg.onload = () => updateAmbientColor();
    } else {
      artImg.style.display = 'none';
      artPlaceholder.style.display = 'flex';
    }

    // Quality badge
    const quality = data.quality || '';
    if (quality) {
      qualityBadge.style.display = 'inline-block';
      qualityBadge.textContent = quality;
      qualityBadge.className = 'badge';
      if (quality.toLowerCase() === 'lossless') qualityBadge.classList.add('lossless');
      if (quality.toLowerCase() === 'hires') qualityBadge.classList.add('hires');
    } else {
      qualityBadge.style.display = 'none';
    }

    // Play state
    const state = data.state || '';
    const isPlaying = state === 'PLAYING';
    playIcon.style.display = isPlaying ? 'none' : 'block';
    pauseIcon.style.display = isPlaying ? 'block' : 'none';

    // Volume
    if (data.volume !== undefined) {
      volumeSlider.value = data.volume;
      volumeVal.textContent = data.volume;
    }

    // Mute
    if (data.mute !== undefined) {
      volIcon.style.display = data.mute ? 'none' : 'block';
      muteIcon.style.display = data.mute ? 'block' : 'none';
    }

    // Progress
    updateProgress(data.relTime, data.duration, isPlaying);
  }

  function updateProgress(relTime, duration, playing) {
    const relSecs = parseTime(relTime);
    const durSecs = parseTime(duration);

    relTimeEl.textContent = formatTime(relSecs);
    durationEl.textContent = formatTime(durSecs);

    if (durSecs > 0) {
      progressFill.style.width = `${(relSecs / durSecs) * 100}%`;
    }

    // Live progress update
    clearInterval(progressInterval);
    if (playing && relSecs < durSecs) {
      let current = relSecs;
      progressInterval = setInterval(() => {
        current++;
        if (current > durSecs) {
          clearInterval(progressInterval);
          return;
        }
        progressFill.style.width = `${(current / durSecs) * 100}%`;
        relTimeEl.textContent = formatTime(current);
      }, 1000);
    }
  }

  function parseTime(str) {
    if (!str) return 0;
    const parts = str.split(':').map(Number);
    if (parts.length === 3) return parts[0] * 3600 + parts[1] * 60 + parts[2];
    if (parts.length === 2) return parts[0] * 60 + parts[1];
    return 0;
  }

  function formatTime(secs) {
    const m = Math.floor(secs / 60);
    const s = secs % 60;
    return `${m}:${s.toString().padStart(2, '0')}`;
  }

  // ==================== Devices ====================
  function renderDevices() {
    deviceItems.innerHTML = '';

    if (devices.length === 0) {
      deviceItems.innerHTML = '<div style="padding:14px;color:var(--text-secondary);font-size:14px;">No devices found. Click Discover.</div>';
      return;
    }

    devices.forEach((d) => {
      const el = document.createElement('div');
      el.className = 'device-item' + (d.ip === selectedIP ? ' selected' : '');
      el.innerHTML = `
        <div class="status"></div>
        <div class="info">
          <div class="name">${escHtml(d.name || 'Unknown')}</div>
          <div class="detail">${escHtml(d.model || '')} · ${d.ip}</div>
        </div>
      `;
      el.onclick = () => {
        send('select', { ip: d.ip });
        closeAllDropdowns();
      };
      deviceItems.appendChild(el);
    });

    // Update selected device name
    const sel = devices.find((d) => d.ip === selectedIP);
    if (sel) {
      deviceName.textContent = sel.name || 'WiiM Device';
    }
  }

  function escHtml(str) {
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
  }

  // ==================== Ambient Color ====================
  function updateAmbientColor() {
    // Extract dominant color from album art using canvas
    const canvas = document.createElement('canvas');
    const ctx = canvas.getContext('2d');
    canvas.width = 10;
    canvas.height = 10;
    ctx.drawImage(artImg, 0, 0, 10, 10);

    const data = ctx.getImageData(0, 0, 10, 10).data;
    let r = 0, g = 0, b = 0, count = 0;

    for (let i = 0; i < data.length; i += 4) {
      r += data[i];
      g += data[i + 1];
      b += data[i + 2];
      count++;
    }

    r = Math.round(r / count);
    g = Math.round(g / count);
    b = Math.round(b / count);

    // Apply ambient glow color
    document.documentElement.style.setProperty('--accent-glow', `rgba(${r},${g},${b},0.3)`);
    document.documentElement.style.setProperty('--accent', `rgb(${r},${g},${b})`);
  }

  // ==================== Idle / Overlay ====================
  function resetIdleTimer() {
    document.body.classList.remove('idle');
    clearTimeout(idleTimer);
    idleTimer = setTimeout(() => {
      document.body.classList.add('idle');
    }, overlayTimeout);
  }

  // ==================== Dropdowns ====================
  function closeAllDropdowns() {
    $$('.dropdown-content').forEach((el) => el.classList.remove('open'));
  }

  function toggleDropdown(listEl) {
    const isOpen = listEl.classList.contains('open');
    closeAllDropdowns();
    if (!isOpen) listEl.classList.add('open');
  }

  // ==================== Event Handlers ====================

  // Discover
  discoverBtn.addEventListener('click', (e) => {
    e.stopPropagation();
    fetch('/discover').catch(() => {});
  });

  // Device selector
  deviceBtn.addEventListener('click', (e) => {
    e.stopPropagation();
    toggleDropdown(deviceList);
  });

  // Source selector
  sourceBtn.addEventListener('click', (e) => {
    e.stopPropagation();
    toggleDropdown(sourceList);
  });

  // EQ selector
  eqBtn.addEventListener('click', (e) => {
    e.stopPropagation();
    toggleDropdown(eqList);
  });

  // Close dropdowns on outside click
  document.addEventListener('click', closeAllDropdowns);

  // Source items
  $$('.source-item').forEach((item) => {
    item.addEventListener('click', (e) => {
      e.stopPropagation();
      const mode = item.dataset.mode;
      if (mode) {
        send('switch', { mode });
      }
      const eq = item.dataset.eq;
      if (eq !== undefined) {
        send('eq', { value: parseInt(eq) });
      }
      closeAllDropdowns();
    });
  });

  // Transport
  playBtn.addEventListener('click', () => {
    const isPlaying = currentState && currentState.state === 'PLAYING';
    send(isPlaying ? 'pause' : 'play');
  });

  prevBtn.addEventListener('click', () => send('prev'));
  nextBtn.addEventListener('click', () => send('next'));

  // Volume
  volumeSlider.addEventListener('input', () => {
    const v = parseInt(volumeSlider.value);
    volumeVal.textContent = v;
    send('volume', { value: v });
  });

  // Mute
  muteBtn.addEventListener('click', () => {
    const isMuted = currentState && currentState.mute;
    send('mute', { value: !isMuted });
  });

  // Progress bar seek
  function seekFromEvent(e) {
    const rect = progressBar.getBoundingClientRect();
    const pct = Math.max(0, Math.min(1, (e.clientX - rect.left) / rect.width));
    if (currentState && currentState.duration) {
      const durSecs = parseTime(currentState.duration);
      const seekSecs = Math.round(pct * durSecs);
      send('seek', { seconds: seekSecs });
      progressFill.style.width = `${pct * 100}%`;
      relTimeEl.textContent = formatTime(seekSecs);
    }
  }

  let isSeeking = false;
  progressBar.addEventListener('mousedown', (e) => {
    isSeeking = true;
    seekFromEvent(e);
  });
  document.addEventListener('mousemove', (e) => {
    if (isSeeking) seekFromEvent(e);
  });
  document.addEventListener('mouseup', () => {
    isSeeking = false;
  });

  progressBar.addEventListener('touchstart', (e) => {
    isSeeking = true;
    seekFromEvent(e.touches[0]);
  });
  document.addEventListener('touchmove', (e) => {
    if (isSeeking) seekFromEvent(e.touches[0]);
  });
  document.addEventListener('touchend', () => {
    isSeeking = false;
  });

  // Show controls on any interaction
  ['mousemove', 'keydown', 'touchstart'].forEach((evt) => {
    document.addEventListener(evt, resetIdleTimer, { passive: true });
  });

  // ==================== Init ====================
  connect();
  resetIdleTimer();
})();
