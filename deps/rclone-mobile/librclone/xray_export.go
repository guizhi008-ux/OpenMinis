package main

/*
#include <stdlib.h>
*/
import "C"

import (
	"os"
	"strings"
	"sync"

	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/infra/conf/serial"
	_ "github.com/xtls/xray-core/main/distro/all"
)

// Xray core, embedded in the SAME c-archive (and therefore the same Go
// runtime) as rclone + Tailscale above. One process can only ever link one
// Go runtime, so the proxy core must live here rather than in a second
// framework — see the warning in build_rclone_ios.sh and XTLS/libXray#116.
//
// The Swift side (ProxyCore.swift) builds a plain Xray JSON config with a
// loopback HTTP/SOCKS inbound and one SS or VLESS outbound, hands it over,
// and points the app's URLSessions at the loopback port. No TUN, no
// NetworkExtension: only this app's own traffic is proxied.

var (
	minisXrayMu       sync.Mutex
	minisXrayInstance *core.Instance
)

// MinisXrayStart starts (or replaces) the embedded Xray instance with the
// given JSON config. Returns "" on success, otherwise a malloc'd error
// string. Caller releases non-nil results with MinisRcloneFreeString.
//
//export MinisXrayStart
func MinisXrayStart(configJSON *C.char) *C.char {
	minisXrayMu.Lock()
	defer minisXrayMu.Unlock()
	if minisXrayInstance != nil {
		_ = minisXrayInstance.Close()
		minisXrayInstance = nil
	}
	confCfg, err := serial.DecodeJSONConfig(strings.NewReader(C.GoString(configJSON)))
	if err != nil {
		return C.CString("config: " + err.Error())
	}
	cfg, err := confCfg.Build()
	if err != nil {
		return C.CString("build: " + err.Error())
	}
	inst, err := core.New(cfg)
	if err != nil {
		return C.CString("init: " + err.Error())
	}
	if err := inst.Start(); err != nil {
		return C.CString("start: " + err.Error())
	}
	minisXrayInstance = inst
	return C.CString("")
}

// MinisXraySetAssetDir points Xray's geo-data loader (geoip.dat /
// geosite.dat, bundled as app resources) at the given directory. Must be
// called before MinisXrayStart for rule modes that reference geo data.
//
//export MinisXraySetAssetDir
func MinisXraySetAssetDir(dir *C.char) {
	if dir != nil {
		_ = os.Setenv("XRAY_LOCATION_ASSET", C.GoString(dir))
	}
}

//export MinisXrayStop
func MinisXrayStop() {
	minisXrayMu.Lock()
	defer minisXrayMu.Unlock()
	if minisXrayInstance != nil {
		_ = minisXrayInstance.Close()
		minisXrayInstance = nil
	}
}

//export MinisXrayRunning
func MinisXrayRunning() C.int {
	minisXrayMu.Lock()
	defer minisXrayMu.Unlock()
	if minisXrayInstance != nil && minisXrayInstance.IsRunning() {
		return 1
	}
	return 0
}
