package main

/*
#include <stdlib.h>
static int minis_appproxy_length(const char *s) {
    if (!s) return 0;
    int n = 0;
    while (n <= 1048576 && s[n]) n++;
    return n;
}
*/
import "C"
import (
	"encoding/json"
	"errors"
	"unsafe"

	"github.com/OpenMinis/minis-rclone/appproxy"
	"github.com/OpenMinis/minis-rclone/routepolicy"
)

var appProxy = appproxy.NewManager()

func appProxyResult(data any, err error) *C.char {
	result := map[string]any{"ok": err == nil, "data": data}
	if err != nil {
		result["error"] = err.Error()
	}
	b, _ := json.Marshal(result)
	return C.CString(string(b))
}

//export MinisAppProxyConfigure
func MinisAppProxyConfigure(config *C.char) *C.char {
	input := []byte(C.GoStringN(config, C.minis_appproxy_length(config)))
	if !routepolicy.Installed() {
		var requested struct {
			Mode string `json:"mode"`
		}
		if json.Unmarshal(input, &requested) != nil || requested.Mode != "off" {
			return appProxyResult(appProxy.Stop(), errors.New("strict network hook missing: rebuild the native library with the documented script"))
		}
	}
	s, e := appProxy.Configure(input)
	return appProxyResult(s, e)
}

//export MinisAppProxyImport
func MinisAppProxyImport(text *C.char) *C.char {
	r, e := appproxy.Import(C.GoStringN(text, C.minis_appproxy_length(text)))
	return appProxyResult(r, e)
}

//export MinisAppProxyStop
func MinisAppProxyStop() *C.char { return appProxyResult(appProxy.Stop(), nil) }

//export MinisAppProxyStatus
func MinisAppProxyStatus() *C.char { return appProxyResult(appProxy.Status(), nil) }

// MinisAppProxyStrictEnabled lets Objective-C native offloads refuse
// OS-hosted network services that cannot use the app's proxy session.
//
//export MinisAppProxyStrictEnabled
func MinisAppProxyStrictEnabled() C.int {
	if appProxy.Status().Mode == "off" {
		return 0
	}
	return 1
}

//export MinisAppProxyFreeString
func MinisAppProxyFreeString(s *C.char) { C.free(unsafe.Pointer(s)) }
