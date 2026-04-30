# WiiM Media Mirror

A zero-dependency Go web server for real-time media mirroring and control of WiiM (and UPnP-compatible) audio devices.

## Features

- **Real-time state mirroring** — Track playback state, metadata, volume, and audio quality
- **WebSocket API** — Live bidirectional control from any browser
- **UPnP Discovery** — Auto-discovers devices on your network via SSDP
- **Album art proxy** — Bypasses CORS restrictions for streaming service artwork
- **Ambient theming** — Extracts dominant color from album art for dynamic UI glow
- **Auto-hiding UI** — Controls fade after 4 seconds of inactivity; playback details persist
- **Zero external Go dependencies** — Built entirely with Go standard library

## Supported Controls

| Action | Method |
|--------|--------|
| Play / Pause / Next / Previous | WebSocket `play` / `pause` / `next` / `prev` |
| Volume | WebSocket `volume` (also tries `httpapi.asp` fallback) |
| Seek | Click or drag progress bar |
| Source switch | WiFi, Bluetooth, Line In, Optical, Coaxial, HDMI ARC, USB, Phono |
| EQ presets | Normal, Classic, Rock, Pop, Jazz, Vocal, Bass |
| Multi-room | Group join/leave/list via WebSocket |

## Building

```bash
go build -o wiimmediamirror .
```

## Running

```bash
./wiimmediamirror        # default port 8080
./wiimmediamirror 8080   # explicit port
```

Open `http://localhost:8080/` in your browser.

## Docker

```bash
docker build -t wiimmediamirror .
docker run -p 8080:8080 wiimmediamirror
```

## WebSocket Protocol

Connect to `ws://host:port/ws`.

**Incoming messages (server → client):**

| Type | Payload |
|------|---------|
| `devices` | List of discovered devices |
| `state` | Current device state (title, artist, album, volume, etc.) |
| `selected` | Currently selected device IP |

**Outgoing messages (client → server):**

| Action | Fields |
|--------|--------|
| `play` / `pause` / `next` / `prev` | — |
| `volume` | `value: 0-100` |
| `seek` | `seconds: number` |
| `switch` | `mode: string` (source name) |
| `eq` | `value: 0-6` |
| `select` | `ip: string` |
| `group_join` | `masterIP: string` |
| `group_leave` | — |
| `group_list` | — |

## Architecture

```
┌─────────────┐     WebSocket      ┌─────────────────┐
│   Browser   │ ◄────────────────► │  Go HTTP Server │
│   (UI)      │                    │   (this repo)   │
└─────────────┘                    └────────┬────────┘
                                            │
                         ┌──────────────────┼──────────────────┐
                         │                  │                  │
                    ┌────▼────┐      ┌─────▼─────┐     ┌─────▼─────┐
                    │  SSDP   │      │ UPnP/SOAP │     │httpapi.asp│
                    │Discovery│      │  Control  │     │  (HTTPS)  │
                    └────┬────┘      └─────┬─────┘     └─────┬─────┘
                         │                  │                  │
                    ┌────▼────┐      ┌─────▼─────┐     ┌─────▼─────┐
                    │ WiiM    │      │ WiiM      │     │ WiiM      │
                    │ Device  │      │ Device    │     │ Device    │
                    └─────────┘      └───────────┘     └───────────┘
```

## License

MIT
