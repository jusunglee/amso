// Package auth implements KakaoTalk HTTP authentication and device registration.
package auth

import (
	"crypto/sha512"
	"fmt"
)

// XVC seed pairs per agent type.
const (
	xvcPatternWin32   = "ARTHUR|%s|RUZ|%s|%s"   // UA, email, UUID
	xvcPatternMac     = "PITT|%s|%s|%s|INORAN"   // UA, email, UUID
	xvcPatternAndroid = "KOLD|%s|BRAN|%s|BRAD"   // UA, email
)

// ComputeXVC computes the XVC header value used in KakaoTalk auth requests.
// SHA512(pattern)[:16] where pattern depends on the agent type.
func ComputeXVC(agent, userAgent, email, deviceUUID string) string {
	var input string
	switch agent {
	case "android":
		input = fmt.Sprintf(xvcPatternAndroid, userAgent, email)
	case "mac":
		input = fmt.Sprintf(xvcPatternMac, userAgent, email, deviceUUID)
	default: // win32
		input = fmt.Sprintf(xvcPatternWin32, userAgent, email, deviceUUID)
	}
	hash := sha512.Sum512([]byte(input))
	return fmt.Sprintf("%x", hash)[:16]
}
