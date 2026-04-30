package main

import (
	"bufio"
	"crypto/sha1"
	"crypto/tls"
	"embed"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"math"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

//go:embed static/*
var staticFS embed.FS

// ==================== WebSocket ====================

type websocketconn struct {
	conn   net.Conn
	reader *bufio.ReadWriter
	mu     sync.Mutex
}

func upgradeWS(w http.ResponseWriter, r *http.Request) (*websocketconn, error) {
	hj, ok := w.(http.Hijacker)
	if !ok {
		return nil, fmt.Errorf("server does not support hijacking")
	}

	key := r.Header.Get("Sec-WebSocket-Key")
	if key == "" {
		return nil, fmt.Errorf("not a websocket handshake")
	}

	hash := ComputeAcceptKey(key)

	conn, bufrw, err := hj.Hijack()
	if err != nil {
		return nil, err
	}

	wsConn := &websocketconn{conn: conn, reader: bufrw}

	lines := []string{
		"HTTP/1.1 101 Switching Protocols",
		"Upgrade: websocket",
		"Connection: Upgrade",
		"Sec-WebSocket-Accept: " + hash,
		"", "",
	}
	resp := strings.Join(lines, "\r\n")
	if _, err := bufrw.WriteString(resp); err != nil {
		conn.Close()
		return nil, err
	}
	if err := bufrw.Flush(); err != nil {
		conn.Close()
		return nil, err
	}

	return wsConn, nil
}

func (c *websocketconn) ReadMessage() ([]byte, error) {
	// Read first 2 bytes
	head, err := c.read(2)
	if err != nil {
		return nil, err
	}

	var length uint64
	length = uint64(head[1] & 0x7F)

	if length == 126 {
		data, err := c.read(2)
		if err != nil {
			return nil, err
		}
		length = uint64(binary.BigEndian.Uint16(data))
	} else if length == 127 {
		data, err := c.read(8)
		if err != nil {
			return nil, err
		}
		length = binary.BigEndian.Uint64(data)
	}

	isMasked := (head[1] & 0x80) == 0x80
	var mask []byte
	if isMasked {
		mask, err = c.read(4)
		if err != nil {
			return nil, err
		}
	}

	var payload []byte
	if length > 0 {
		payload, err = c.read(int(length))
		if err != nil {
			return nil, err
		}
		if isMasked {
			for i := uint64(0); i < length; i++ {
				payload[i] ^= mask[i%4]
			}
		}
	} else {
		payload = []byte{}
	}

	return payload, nil
}

func (c *websocketconn) WriteMessage(data []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	length := len(data)
	frame := make([]byte, 2)
	frame[0] = 0x81 // text, final

	if length <= 125 {
		frame[1] = byte(length)
	} else if length <= 65535 {
		frame[1] = 126
		size := make([]byte, 2)
		binary.BigEndian.PutUint16(size, uint16(length))
		frame = append(frame, size...)
	} else {
		frame[1] = 127
		size := make([]byte, 8)
		binary.BigEndian.PutUint64(size, uint64(length))
		frame = append(frame, size...)
	}

	frame = append(frame, data...)
	if _, err := c.reader.Write(frame); err != nil {
		return err
	}
	return c.reader.Flush()
}

func (c *websocketconn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.conn != nil {
		return c.conn.Close()
	}
	return nil
}

func (c *websocketconn) read(size int) ([]byte, error) {
	data := make([]byte, 0, size)
	for len(data) < size {
		sz := 4096
		remaining := size - len(data)
		if sz > remaining {
			sz = remaining
		}
		temp := make([]byte, sz)
		n, err := c.reader.Read(temp)
		if err != nil {
			if n > 0 {
				data = append(data, temp[:n]...)
			}
			if len(data) >= size {
				return data, nil
			}
			return data, err
		}
		data = append(data, temp[:n]...)
	}
	return data, nil
}

// ==================== Protocol (inline from websocket_protocol.go) ====================

const ( // WebSocket opcodes
	OpContinuation byte = 0x0
	OpText         byte = 0x1
	OpBinary       byte = 0x2
	OpClose        byte = 0x8
	OpPing         byte = 0x9
	OpPong         byte = 0xA
)

func ComputeAcceptKey(key string) string {
	h := sha1.New()
	h.Write([]byte(key))
	h.Write([]byte("258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

// ==================== UPnP Device ====================

type Device struct {
	IP            string `json:"ip"`
	Name          string `json:"name"`
	Model         string `json:"model"`
	UUID          string `json:"uuid"`
	Port          int    `json:"port"`
	UPnPURL       string `json:"-"`
	ControlURL    string `json:"-"`
	EventURL      string `json:"-"`
	PlayQueueURL  string `json:"-"`
	SSID          string `json:"ssid"`
	SID           string `json:"-"`
	HasHTTPAPI    bool   `json:"-"`
	Volume        int    `json:"volume"`
	Mute          bool   `json:"mute"`
	State         string `json:"state"`
	Title         string `json:"title"`
	Artist        string `json:"artist"`
	Album         string `json:"album"`
	AlbumArtURL   string `json:"albumArtUrl"`
	Duration      string `json:"duration"`
	RelTime       string `json:"relTime"`
	TrackSource   string `json:"trackSource"`
	Quality       string `json:"quality"`
	Format        string `json:"format"`
	Bitrate       string `json:"bitrate"`
}

func (d *Device) soapRequest(serviceURL, action, body string) (string, error) {
	fullURL := fmt.Sprintf("http://%s:%d%s", d.IP, d.Port, serviceURL)
	soapBody := fmt.Sprintf(`<?xml version="1.0" encoding="utf-8"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
  <s:Body>%s</s:Body>
</s:Envelope>`, body)

	req, err := http.NewRequest("POST", fullURL, strings.NewReader(soapBody))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", `text/xml; charset="utf-8"`)
	req.Header.Set("SOAPACTION", fmt.Sprintf(`"urn:schemas-upnp-org:service:AVTransport:1#%s"`, action))
	req.Header.Set("Content-Length", strconv.Itoa(len(soapBody)))

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	return string(respBody), nil
}

func (d *Device) GetInfoEx() error {
	body := `<u:GetInfoEx xmlns:u="urn:schemas-upnp-org:service:AVTransport:1"><InstanceID>0</InstanceID></u:GetInfoEx>`
	resp, err := d.soapRequest(d.ControlURL, "GetInfoEx", body)
	if err != nil {
		return err
	}

	d.State = xmlField(resp, "CurrentTransportState")

	// Parse volume from response (GetInfoEx returns CurrentVolume)
	if volStr := xmlField(resp, "CurrentVolume"); volStr != "" {
		if vol, err := strconv.Atoi(volStr); err == nil {
			d.Volume = vol
		}
	}

	// If UPnP volume is 0 or missing, try httpapi.asp
	if d.Volume <= 0 {
		if status, err := d.GetPlayerStatus(); err == nil {
			if vol, ok := status["vol"]; ok {
				if v, err := strconv.Atoi(fmt.Sprint(vol)); err == nil {
					d.Volume = v
				}
			}
			if mute, ok := status["mute"]; ok {
				d.Mute = mute == "1" || mute == 1
			}
		}
	}

	// Extract metadata first
	meta := xmlField(resp, "TrackMetaData")
	if meta != "" {
		// Unescape XML (order matters: &amp; first)
		meta = strings.ReplaceAll(meta, "&amp;", "&")
		meta = strings.ReplaceAll(meta, "&lt;", "<")
		meta = strings.ReplaceAll(meta, "&gt;", ">")
		meta = strings.ReplaceAll(meta, "&quot;", "\"")

		d.Title = xmlField(meta, "dc:title")
		artist := xmlField(meta, "upnp:artist")
		if artist == "" {
			artist = xmlField(meta, "dc:creator")
		}
		d.Artist = artist
		d.Album = xmlField(meta, "upnp:album")
		d.AlbumArtURL = xmlField(meta, "upnp:albumArtURI")
		d.TrackSource = xmlField(meta, "song:source")
		d.Quality = xmlField(meta, "song:actualQuality")
		d.Format = xmlField(meta, "song:format_s")
		d.Bitrate = xmlField(meta, "song:bitrate")
	}

	d.Duration = xmlField(resp, "TrackDuration")
	d.RelTime = xmlField(resp, "RelTime")

	return nil
}

func (d *Device) GetVolume() error {
	body := `<u:GetVolume xmlns:u="urn:schemas-upnp-org:service:RenderingControl:1"><InstanceID>0</InstanceID><Channel>Master</Channel></u:GetVolume>`
	resp, err := d.soapRequest("/upnp/control/rendercontrol1", "GetVolume", body)
	if err != nil {
		return err
	}
	volStr := xmlField(resp, "CurrentVolume")
	if vol, err := strconv.Atoi(volStr); err == nil {
		d.Volume = vol
	}
	return nil
}

func (d *Device) SetVolume(vol int) error {
	// Try httpapi.asp first (works for all devices including fixed volume mode)
	err := d.SetVolumeHTTPAPI(vol)
	if err == nil && d.Volume == vol {
		return nil
	}

	// Fallback to UPnP
	body := fmt.Sprintf(`<u:SetVolume xmlns:u="urn:schemas-upnp-org:service:RenderingControl:1"><InstanceID>0</InstanceID><Channel>Master</Channel><DesiredVolume>%d</DesiredVolume></u:SetVolume>`, vol)
	_, err = d.soapRequest("/upnp/control/rendercontrol1", "SetVolume", body)
	if err == nil {
		d.Volume = vol
	}
	return err
}

func (d *Device) SubscribeEventing(serverURL string) error {
	// Check current subscription first
	client := &http.Client{Timeout: 5 * time.Second}
	req, err := http.NewRequest("SUBSCRIBE", fmt.Sprintf("http://%s:%d%s", d.IP, d.Port, d.EventURL), nil)
	if err != nil {
		return err
	}
	req.Header.Set("HOST", fmt.Sprintf("%s:%d", d.IP, d.Port))
	req.Header.Set("NT", "upnp:event")
	req.Header.Set("TIMEOUT", "Second-3600")
	req.Header.Set("CALLBACK", fmt.Sprintf("<%s>", serverURL))

	resp, err := client.Do(req)
	if err != nil {
		// Try without NT (renewal)
		req2, _ := http.NewRequest("SUBSCRIBE", fmt.Sprintf("http://%s:%d%s", d.IP, d.Port, d.EventURL), nil)
		req2.Header.Set("HOST", fmt.Sprintf("%s:%d", d.IP, d.Port))
		req2.Header.Set("TIMEOUT", "Second-3600")
		req2.Header.Set("CALLBACK", fmt.Sprintf("<%s>", serverURL))
		resp, err = client.Do(req2)
		if err != nil {
			return fmt.Errorf("subscribe failed: %v", err)
		}
	}
	defer resp.Body.Close()

	sid := resp.Header.Get("SID")
	if sid != "" {
		d.SID = sid
	}
	return nil
}

func (d *Device) UnsubscribeEventing() error {
	if d.SID == "" {
		return nil
	}
	client := &http.Client{Timeout: 5 * time.Second}
	req, err := http.NewRequest("UNSUBSCRIBE", fmt.Sprintf("http://%s:%d%s", d.IP, d.Port, d.EventURL), nil)
	if err != nil {
		return err
	}
	req.Header.Set("HOST", fmt.Sprintf("%s:%d", d.IP, d.Port))
	req.Header.Set("SID", d.SID)

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("unsubscribe failed: %v", err)
	}
	defer resp.Body.Close()
	d.SID = ""
	return nil
}
func (d *Device) SetMute(mute bool) error {
	m := 0
	if mute {
		m = 1
	}
	body := fmt.Sprintf(`<u:SetMute xmlns:u="urn:schemas-upnp-org:service:RenderingControl:1"><InstanceID>0</InstanceID><Channel>Master</Channel><DesiredMute>%d</DesiredMute></u:SetMute>`, m)
	_, err := d.soapRequest("/upnp/control/rendercontrol1", "SetMute", body)
	if err == nil {
		d.Mute = mute
	}
	return err
}

func (d *Device) httpapiRequest(command string) (string, error) {
	url := fmt.Sprintf("https://%s/httpapi.asp?command=%s", d.IP, command)
	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
	resp, err := client.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return string(body), nil
}

func (d *Device) SetVolumeHTTPAPI(vol int) error {
	resp, err := d.httpapiRequest(fmt.Sprintf("setPlayerCmd:vol:%d", vol))
	if err != nil {
		return err
	}
	if strings.TrimSpace(resp) == "OK" {
		d.Volume = vol
	}
	return nil
}

func (d *Device) GetPlayerStatus() (map[string]interface{}, error) {
	resp, err := d.httpapiRequest("getPlayerStatus")
	if err != nil {
		return nil, err
	}
	var status map[string]interface{}
	if err := json.Unmarshal([]byte(resp), &status); err != nil {
		return nil, err
	}
	return status, nil
}

func (d *Device) Play() error {
	body := `<u:Play xmlns:u="urn:schemas-upnp-org:service:AVTransport:1"><InstanceID>0</InstanceID><Speed>1</Speed></u:Play>`
	_, err := d.soapRequest(d.ControlURL, "Play", body)
	return err
}

func (d *Device) Pause() error {
	body := `<u:Pause xmlns:u="urn:schemas-upnp-org:service:AVTransport:1"><InstanceID>0</InstanceID></u:Pause>`
	_, err := d.soapRequest(d.ControlURL, "Pause", body)
	return err
}

func (d *Device) Next() error {
	body := `<u:Next xmlns:u="urn:schemas-upnp-org:service:AVTransport:1"><InstanceID>0</InstanceID></u:Next>`
	_, err := d.soapRequest(d.ControlURL, "Next", body)
	return err
}

func (d *Device) Previous() error {
	body := `<u:Previous xmlns:u="urn:schemas-upnp-org:service:AVTransport:1"><InstanceID>0</InstanceID></u:Previous>`
	_, err := d.soapRequest(d.ControlURL, "Previous", body)
	return err
}

func (d *Device) SwitchSource(mode string) error {
	_, err := d.httpapiRequest(fmt.Sprintf("setPlayerCmd:switchmode:%s", mode))
	return err
}

func (d *Device) Seek(seconds int) error {
	_, err := d.httpapiRequest(fmt.Sprintf("setPlayerCmd:seek:%d", seconds))
	return err
}

func (d *Device) SetEQ(eq int) error {
	_, err := d.httpapiRequest(fmt.Sprintf("setPlayerCmd:eq:%d", eq))
	return err
}

func (d *Device) JoinGroup(masterIP string) error {
	_, err := d.httpapiRequest(fmt.Sprintf("setPlayerCmd:slave_mode:open:%s", masterIP))
	return err
}

func (d *Device) LeaveGroup() error {
	_, err := d.httpapiRequest("setPlayerCmd:slave_mode:close")
	return err
}

func (d *Device) GetGroupList() (string, error) {
	return d.httpapiRequest("setPlayerCmd:group_list")
}

func xmlField(xml, tag string) string {
	re := regexp.MustCompile(fmt.Sprintf(`<%s[^>]*>([^<]*)</%s>`, tag, tag))
	matches := re.FindStringSubmatch(xml)
	if len(matches) > 1 {
		return strings.TrimSpace(matches[1])
	}
	return ""
}

// ==================== Device Discovery ====================

func discoverDevices() []Device {
	conn, err := net.ListenPacket("udp4", ":0")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Discovery listen error: %v\n", err)
		return nil
	}
	defer conn.Close()

	addr, err := net.ResolveUDPAddr("udp4", "239.255.255.250:1900")
	if err != nil {
		return nil
	}

	msg := "M-SEARCH * HTTP/1.1\r\n" +
		"HOST: 239.255.255.250:1900\r\n" +
		"MAN: \"ssdp:discover\"\r\n" +
		"MX: 2\r\n" +
		"ST: ssdp:all\r\n" +
		"\r\n"

	conn.SetWriteDeadline(time.Now().Add(1 * time.Second))
	conn.WriteTo([]byte(msg), addr)

	var devices []Device
	found := make(map[string]bool)
	buf := make([]byte, 4096)

	for {
		conn.SetReadDeadline(time.Now().Add(3 * time.Second))
		n, _, err := conn.ReadFrom(buf)
		if err != nil {
			break
		}

		resp := string(buf[:n])
		location := extractHeader(resp, "LOCATION")
		server := extractHeader(resp, "SERVER")

		if location == "" || !strings.Contains(strings.ToLower(server), "linux") {
			continue
		}

		parsed, err := url.Parse(location)
		if err != nil || parsed == nil || found[parsed.Host] {
			continue
		}
		found[parsed.Host] = true

		ip := strings.Split(parsed.Host, ":")[0]
		port := 49152
		if p := strings.Split(parsed.Host, ":"); len(p) > 1 {
			port, _ = strconv.Atoi(p[1])
		}

		fmt.Printf("Discovered: %s (%s) at %s\n", server, location, parsed.Host)

		dev := fetchDescription(location, ip, port)
		if dev != nil {
			fmt.Printf("  -> %s (%s)\n", dev.Name, dev.Model)
			devices = append(devices, *dev)
		}
	}

	return devices
}

func extractHeader(resp, header string) string {
	lines := strings.Split(resp, "\r\n")
	for _, line := range lines {
		if len(line) == 0 {
			continue
		}
		// Case-insensitive prefix match
		if len(line) >= len(header)+1 {
			prefix := line[:len(header)]
			if strings.EqualFold(prefix, header) && line[len(header)] == ':' {
				return strings.TrimSpace(line[len(header)+1:])
			}
		}
	}
	return ""
}

func fetchDescription(location, ip string, port int) *Device {
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get(location)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	xml := string(body)

	dev := &Device{
		IP:         ip,
		Port:       port,
		UPnPURL:    location,
		ControlURL: "/upnp/control/rendertransport1",
		EventURL:   "/upnp/event/rendertransport1",
	}

	dev.Name = xmlField(xml, "friendlyName")
	dev.Model = xmlField(xml, "modelName")
	uuid := xmlField(xml, "UDN")
	if strings.HasPrefix(uuid, "uuid:") {
		dev.UUID = uuid[5:]
	} else {
		dev.UUID = uuid
	}
	dev.SSID = xmlField(xml, "ssidName")

	// Parse service URLs
	if ctrl := xmlField(xml, "controlURL"); ctrl != "" {
		if strings.Contains(ctrl, "rendertransport") {
			dev.ControlURL = ctrl
		}
	}

	return dev
}

// ==================== Album Art Proxy ====================

func proxyAlbumArt(w http.ResponseWriter, r *http.Request) {
	imgURL := r.URL.Query().Get("url")
	if imgURL == "" {
		http.Error(w, "missing url", http.StatusBadRequest)
		return
	}

	resp, err := http.Get(imgURL)
	if err != nil {
		http.Error(w, "failed to fetch image", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	w.Header().Set("Content-Type", resp.Header.Get("Content-Type"))
	w.Header().Set("Cache-Control", "public, max-age=3600")
	io.Copy(w, resp.Body)
}

// ==================== GENA Event Handler ====================

func handleGenaEvent(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	xml := string(body)

	devicesMu.RLock()
	var dev *Device
	for _, d := range devices {
		if d.SID != "" && r.Header.Get("SID") == d.SID {
			dev = d
			break
		}
	}
	devicesMu.RUnlock()

	if dev == nil {
		w.WriteHeader(200)
		return
	}

	// Parse state change
	if state := xmlField(xml, "LastChange"); state != "" {
		// WiiM sends state in LastChange property
		devicesMu.Lock()
		dev.State = xmlField(state, "TransportState")
		if vol := xmlField(state, "Volume"); vol != "" {
			if v, _ := strconv.Atoi(vol); v >= 0 {
				dev.Volume = v
			}
		}
		devicesMu.Unlock()
	}

	// Fallback: poll for full metadata on any event
	if err := dev.GetInfoEx(); err == nil {
		broadcast(map[string]interface{}{
			"type": "state",
			"data": dev,
		})
	}

	w.WriteHeader(200)
}

// ==================== Server ====================

var (
	devices   = make(map[string]*Device)
	clients   = make(map[*websocketconn]bool)
	clientsMu sync.RWMutex
	devicesMu sync.RWMutex
	selected  string
)

func broadcast(msg map[string]interface{}) {
	data, _ := json.Marshal(msg)
	clientsMu.RLock()
	for ws := range clients {
		if err := ws.WriteMessage(data); err != nil {
			ws.Close()
			delete(clients, ws)
		}
	}
	clientsMu.RUnlock()
}

func subscribeToDevice(dev *Device, serverURL string) {
	if err := dev.SubscribeEventing(serverURL); err != nil {
		fmt.Printf("  Eventing failed for %s: %v\n", dev.Name, err)
		return
	}
	fmt.Printf("  Subscribed to %s events (SID: %s)\n", dev.Name, dev.SID[:min(20, len(dev.SID))]+"...")
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func pollDevice() {
	for {
		devicesMu.RLock()
		dev, ok := devices[selected]
		devicesMu.RUnlock()

		if ok {
			if err := dev.GetInfoEx(); err == nil {
				broadcast(map[string]interface{}{
					"type": "state",
					"data": dev,
				})
			}
		}

		time.Sleep(2 * time.Second)
	}
}

func handleWS(w http.ResponseWriter, r *http.Request) {
	fmt.Printf("[ws] Upgrade request from %s\n", r.RemoteAddr)
	ws, err := upgradeWS(w, r)
	if err != nil {
		fmt.Printf("[ws] Upgrade failed: %v\n", err)
		http.Error(w, "upgrade failed", http.StatusBadRequest)
		return
	}

	clientsMu.Lock()
	clients[ws] = true
	clientsMu.Unlock()

	defer func() {
		clientsMu.Lock()
		delete(clients, ws)
		clientsMu.Unlock()
		ws.Close()
		fmt.Printf("[ws] Connection closed\n")
	}()

	// Send initial state
	devicesMu.RLock()
	devList := make([]Device, 0, len(devices))
	for _, d := range devices {
		devList = append(devList, *d)
	}
	devicesMu.RUnlock()

	broadcast(map[string]interface{}{
		"type":    "devices",
		"devices": devList,
		"selected": selected,
	})

	if dev, ok := devices[selected]; ok {
		broadcast(map[string]interface{}{
			"type": "state",
			"data": dev,
		})
	}

	// Read loop
	for {
		msg, err := ws.ReadMessage()
		if err != nil {
			fmt.Printf("[ws] Read error: %v\n", err)
			return
		}

		var cmd map[string]interface{}
		if err := json.Unmarshal(msg, &cmd); err != nil {
			continue
		}

		action, _ := cmd["action"].(string)
		devicesMu.RLock()
		dev, ok := devices[selected]
		devicesMu.RUnlock()

		if !ok {
			continue
		}

		switch action {
		case "select":
			if ip, ok := cmd["ip"].(string); ok && ip != "" {
				devicesMu.Lock()
				selected = ip
				devicesMu.Unlock()
				broadcast(map[string]interface{}{
					"type":     "selected",
					"selected": selected,
				})
				go func() {
					devicesMu.RLock()
					d := devices[selected]
					devicesMu.RUnlock()
					if d != nil {
						d.GetInfoEx()
						broadcast(map[string]interface{}{
							"type": "state",
							"data": d,
						})
					}
				}()
			}
		case "play":
			dev.Play()
		case "pause":
			dev.Pause()
		case "next":
			dev.Next()
		case "prev":
			dev.Previous()
		case "volume":
			if v, ok := cmd["value"].(float64); ok && v >= 0 {
				dev.SetVolume(int(v))
			}
		case "mute":
			if m, ok := cmd["value"].(bool); ok {
				dev.SetMute(m)
			}
		case "switch":
			if mode, ok := cmd["mode"].(string); ok && mode != "" {
				dev.SwitchSource(mode)
			}
		case "seek":
			if secs, ok := cmd["seconds"].(float64); ok {
				dev.Seek(int(secs))
			}
		case "eq":
			if eq, ok := cmd["value"].(float64); ok {
				dev.SetEQ(int(eq))
			}
		case "group_join":
			if masterIP, ok := cmd["masterIP"].(string); ok && masterIP != "" {
				dev.JoinGroup(masterIP)
			}
		case "group_leave":
			dev.LeaveGroup()
		case "group_list":
			if resp, err := dev.GetGroupList(); err == nil {
				broadcast(map[string]interface{}{
					"type": "group_list",
					"data": resp,
				})
			}
		case "refresh":
			dev.GetInfoEx()
			broadcast(map[string]interface{}{
				"type": "state",
				"data": dev,
			})
		}
	}
}

func handleDiscover(w http.ResponseWriter, r *http.Request) {
	found := discoverDevices()

	devicesMu.Lock()
	for _, d := range found {
		devices[d.IP] = &d
		if selected == "" {
			selected = d.IP
		}
	}
	devicesMu.Unlock()

	devicesMu.RLock()
	devList := make([]Device, 0, len(devices))
	for _, d := range devices {
		devList = append(devList, *d)
	}
	devicesMu.RUnlock()

	broadcast(map[string]interface{}{
		"type":     "devices",
		"devices":  devList,
		"selected": selected,
	})

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(devList)
}

func main() {
	port := 8080
	if len(os.Args) > 1 {
		if p, err := strconv.Atoi(os.Args[1]); err == nil {
			port = p
		}
	}

	fmt.Printf("WiiM Media Mirror starting on :%d\n", port)
	fmt.Println("Press Enter to discover devices, or visit /discover")

	// Initial discovery
	go func() {
		time.Sleep(500 * time.Millisecond)
		found := discoverDevices()
		devicesMu.Lock()
		for _, d := range found {
			devices[d.IP] = &d
			if selected == "" {
				selected = d.IP
			}
		}
		devicesMu.Unlock()

		// Broadcast devices to connected clients
		devicesMu.RLock()
		devList := make([]Device, 0, len(devices))
		for _, d := range devices {
			devList = append(devList, *d)
		}
		devicesMu.RUnlock()
		broadcast(map[string]interface{}{
			"type":     "devices",
			"devices":  devList,
			"selected": selected,
		})

		// Subscribe to events for all devices
		serverURL := fmt.Sprintf("http://10.1.1.20:%d/event", port)
		for _, d := range found {
			devicesMu.RLock()
			dev := devices[d.IP]
			devicesMu.RUnlock()
			if dev != nil {
				go subscribeToDevice(dev, serverURL)
			}
		}
	}()

	// Poll selected device
	go pollDevice()

	// Discovery goroutine (read from stdin)
	go func() {
		scanner := bufio.NewScanner(os.Stdin)
		for scanner.Scan() {
			fmt.Println("Discovering devices...")
			found := discoverDevices()
			devicesMu.Lock()
			for _, d := range found {
				devices[d.IP] = &d
				if selected == "" {
					selected = d.IP
				}
			}
			devicesMu.Unlock()
			devicesMu.RLock()
			devList := make([]Device, 0, len(devices))
			for _, d := range devices {
				devList = append(devList, *d)
			}
		devicesMu.RUnlock()
			broadcast(map[string]interface{}{
				"type":     "devices",
				"devices":  devList,
				"selected": selected,
			})
			fmt.Printf("Found %d devices\n", len(found))
		}
	}()

	http.HandleFunc("/ws", handleWS)
	http.HandleFunc("/discover", handleDiscover)
	http.HandleFunc("/albumart", proxyAlbumArt)
	http.HandleFunc("/event", handleGenaEvent)

	// Serve embedded static files
	staticSubFS, err := fs.Sub(staticFS, "static")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create static sub-FS: %v\n", err)
		os.Exit(1)
	}
	staticHandler := http.StripPrefix("/static/", http.FileServer(http.FS(staticSubFS)))
	http.Handle("/static/", staticHandler)

	// Serve embedded index.html at root
	indexHTML, err := staticFS.ReadFile("static/index.html")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to read embedded index.html: %v\n", err)
		os.Exit(1)
	}
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Write(indexHTML)
		}
	})

	// Cleanup dead clients periodically
	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		for range ticker.C {
			found := discoverDevices()
			devicesMu.Lock()
			for _, d := range found {
				devices[d.IP] = &d
				if selected == "" {
					selected = d.IP
				}
			}
			devicesMu.Unlock()

			devicesMu.RLock()
			devList := make([]Device, 0, len(devices))
			for _, d := range devices {
				devList = append(devList, *d)
			}
			devicesMu.RUnlock()
			broadcast(map[string]interface{}{
				"type":     "devices",
				"devices":  devList,
				"selected": selected,
			})
		}
	}()

	// Renew GENA subscriptions every 30 minutes
	go func() {
		ticker := time.NewTicker(30 * time.Minute)
		for range ticker.C {
			devicesMu.RLock()
			serverURL := fmt.Sprintf("http://10.1.1.20:%d/event", port)
			for _, dev := range devices {
				if dev.SID != "" {
					dev.UnsubscribeEventing()
					if err := dev.SubscribeEventing(serverURL); err == nil {
						fmt.Printf("  Renewed subscription for %s\n", dev.Name)
					}
				}
			}
			devicesMu.RUnlock()
		}
	}()
	addr := fmt.Sprintf(":%d", port)
	if err := http.ListenAndServe(addr, nil); err != nil {
		fmt.Fprintf(os.Stderr, "Server failed: %v\n", err)
		os.Exit(1)
	}
}

// Suppress unused import warnings
var _ = rand.Int
var _ = math.MaxFloat64
var _ = hex.EncodeToString
