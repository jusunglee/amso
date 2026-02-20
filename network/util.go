package network

import "strconv"

// itoa converts an int to a string. Used for net.JoinHostPort.
func itoa(i int) string {
	return strconv.Itoa(i)
}
