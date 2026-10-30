//
//  PacketTunnel-Bridging-Header.h
//  MinisPacketTunnel
//
//  Exposes the Go c-archive's exported functions (MinisTun*, MinisXray*,
//  MinisRcloneFreeString) to the extension's Swift code. The generated
//  librclone.h lives in the Rclone.xcframework Headers directory, which is
//  on this target's HEADER_SEARCH_PATHS.
//

#ifndef PacketTunnel_Bridging_Header_h
#define PacketTunnel_Bridging_Header_h

#include "librclone.h"

#endif
