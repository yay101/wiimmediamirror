package main

import (
	"bufio"
	"crypto/sha1"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
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

// ==================== WebSocket ====================

type WSConn struct {
	conn   net.Conn
	reader *bufio.ReadWriter
	mu     sync.Mutex
}

func upgradeWS(w http.ResponseWriter, r *http.Request) (*WSConn, error) {
	hj, ok := w.(http.Hijacker)
	if !ok {
		return nil, fmt.Errorf("server does not support hijacking")
	}

	key := r.Header.Get("Sec-WebSocket-Key")
	if key == "" {
		return nil, fmt.Errorf("not a websocket handshake")
	}

	h := sha1.New()
	h.Write([]byte(key + "258EAFA5-E914-47DA-95CA-5AB5AC782D0B"))
	accept := base64.StdEncoding.EncodeToString(h.Sum(nil))

	conn, bufrw, err := hj.Hijack()
	if err != nil {
		return nil, err
	}

	resp := "HTTP/1.1 101 Switching Protocols\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Accept: " + accept + "\r\n" +
		"\r\n"

	if _, err := conn.Write([]byte(resp)); err != nil {
		conn.Close()
		return nil, err
	}

	return &WSConn{conn: conn, reader: bufrw}, nil
}

func (ws *WSConn) ReadMessage() ([]byte, error) {
	// Read first 2 bytes
	header := make([]byte, 2)
	if _, err := io.ReadFull(ws.reader, header); err != nil {
		return nil, err
	}

	payloadLen := int(header[1] & 0x7F)
	masked := (header[1] & 0x80) != 0
	offset := 2

	if payloadLen == 126 {
		ext := make([]byte, 2)
		if _, err := io.ReadFull(ws.reader, ext); err != nil {
			return nil, err
		}
		payloadLen = int(binary.BigEndian.Uint16(ext))
		offset += 2
	} else if payloadLen == 127 {
		ext := make([]byte, 8)
		if _, err := io.ReadFull(ws.reader, ext); err != nil {
			return nil, err
		}
		payloadLen = int(binary.BigEndian.Uint64(ext))
		offset += 8
	}

	var maskKey []byte
	if masked {
		maskKey = make([]byte, 4)
		if _, err := io.ReadFull(ws.reader, maskKey); err != nil {
			return nil, err
		}
		offset += 4
	}

	payload := make([]byte, payloadLen)
	if _, err := io.ReadFull(ws.reader, payload); err != nil {
		return nil, err
	}

	if masked {
		for i := range payload {
			payload[i] ^= maskKey[i%4]
		}
	}

	return payload, nil
}

func (ws *WSConn) WriteMessage(data []byte) error {
	ws.mu.Lock()
	defer ws.mu.Unlock()

	header := []byte{0x81} // fin=1, text frame

	payloadLen := len(data)
	if payloadLen < 126 {
		header = append(header, byte(payloadLen))
	} else if payloadLen < 65536 {
		header = append(header, 126)
		ext := make([]byte, 2)
		binary.BigEndian.PutUint16(ext, uint16(payloadLen))
		header = append(header, ext...)
	} else {
		header = append(header, 127)
		ext := make([]byte, 8)
		binary.BigEndian.PutUint64(ext, uint64(payloadLen))
		header = append(header, ext...)
	}

	if _, err := ws.conn.Write(header); err != nil {
		return err
	}
	_, err := ws.conn.Write(data)
	return err
}

func (ws *WSConn) Close() error {
	return ws.conn.Close()
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
	d.Title = xmlField(resp, "dc:title")
	d.Artist = xmlField(resp, "dc:creator")
	d.Album = xmlField(resp, "upnp:album")
	d.Duration = xmlField(resp, "TrackDuration")
	d.RelTime = xmlField(resp, "RelTime")

	// Extract metadata
	meta := xmlField(resp, "TrackMetaData")
	if meta != "" {
		// Unescape XML
		meta = strings.ReplaceAll(meta, "&lt;", "<")
		meta = strings.ReplaceAll(meta, "&gt;", ">")
		meta = strings.ReplaceAll(meta, "&amp;", "&")
		meta = strings.ReplaceAll(meta, "&quot;", "\"")

		d.Title = xmlField(meta, "dc:title")
		d.Artist = xmlField(meta, "dc:creator")
		d.Album = xmlField(meta, "upnp:album")
		d.AlbumArtURL = xmlField(meta, "upnp:albumArtURI")
		d.TrackSource = xmlField(meta, "song:source")
		d.Quality = xmlField(meta, "song:actualQuality")
		d.Format = xmlField(meta, "song:format_s")
		d.Bitrate = xmlField(meta, "song:bitrate")
	}

	// Get volume
	d.GetVolume()

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
	body := fmt.Sprintf(`<u:SetVolume xmlns:u="urn:schemas-upnp-org:service:RenderingControl:1"><InstanceID>0</InstanceID><Channel>Master</Channel><DesiredVolume>%d</DesiredVolume></u:SetVolume>`, vol)
	_, err := d.soapRequest("/upnp/control/rendercontrol1", "SetVolume", body)
	if err == nil {
		d.Volume = vol
	}
	return err
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
	client := &http.Client{
		Timeout:   5 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
	}
	url := fmt.Sprintf("https://%s:443/httpapi.asp?command=setPlayerCmd:switchmode:%s", d.IP, mode)
	_, err := client.Get(url)
	return err
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
	conn, err := net.DialUDP("udp4", nil, &net.UDPAddr{
		IP:   net.ParseIP("239.255.255.250"),
		Port: 1900,
	})
	if err != nil {
		return nil
	}
	defer conn.Close()

	msg := "M-SEARCH * HTTP/1.1\r\n" +
		"HOST: 239.255.255.250:1900\r\n" +
		"MAN: \"ssdp:discover\"\r\n" +
		"MX: 3\r\n" +
		"ST: ssdp:all\r\n" +
		"\r\n"

	conn.SetDeadline(time.Now().Add(100 * time.Millisecond))
	conn.Write([]byte(msg))

	var devices []Device
	found := make(map[string]bool)
	buf := make([]byte, 4096)

	for i := 0; i < 10; i++ {
		conn.SetReadDeadline(time.Now().Add(3 * time.Second))
		n, _, err := conn.ReadFromUDP(buf)
		if err != nil {
			break
		}

		resp := string(buf[:n])
		location := extractHeader(resp, "LOCATION")
		server := extractHeader(resp, "SERVER")

		if location == "" || !strings.Contains(strings.ToLower(server), "linux") {
			continue
		}

		parsed, _ := url.Parse(location)
		if parsed == nil || found[parsed.Host] {
			continue
		}
		found[parsed.Host] = true

		ip := strings.Split(parsed.Host, ":")[0]
		port := 49152
		if p := strings.Split(parsed.Host, ":"); len(p) > 1 {
			port, _ = strconv.Atoi(p[1])
		}

		// Fetch description
		dev := fetchDescription(location, ip, port)
		if dev != nil {
			devices = append(devices, *dev)
		}
	}

	return devices
}

func extractHeader(resp, header string) string {
	re := regexp.MustCompile(`(?i)^` + regexp.QuoteMeta(header) + `:\s*(.+)$`)
	for _, line := range strings.Split(resp, "\r\n") {
		matches := re.FindStringSubmatch(line)
		if len(matches) > 1 {
			return strings.TrimSpace(matches[1])
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

// ==================== Server ====================

var (
	devices   = make(map[string]*Device)
	clients   = make(map[*WSConn]bool)
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
	ws, err := upgradeWS(w, r)
	if err != nil {
		http.Error(w, "upgrade failed", http.StatusBadRequest)
		return
	}

	clientsMu.Lock()
	clients[ws] = true
	clientsMu.Unlock()

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
			clientsMu.Lock()
			delete(clients, ws)
			clientsMu.Unlock()
			ws.Close()
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
	http.HandleFunc("/static/", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "."+r.URL.Path)
	})
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			http.ServeFile(w, r, "./static/index.html")
		}
	})

	// Cleanup dead clients periodically
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		for range ticker.C {
			// Discover every 5 minutes
			found := discoverDevices()
			devicesMu.Lock()
			for _, d := range found {
				devices[d.IP] = &d
				if selected == "" {
					selected = d.IP
				}
			}
			devicesMu.Unlock()
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
