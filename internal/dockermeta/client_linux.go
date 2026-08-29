//go:build linux

package dockermeta

import (
	"context"
	"net"
	"net/http"
	"os"
	"time"
)

// DefaultSocket is the standard Docker Engine socket path.
const DefaultSocket = "/var/run/docker.sock"

// NewUnixClient returns a Client speaking the Docker API over the unix
// socket, or nil when the socket does not exist.
func NewUnixClient(socketPath string) *Client {
	if socketPath == "" {
		socketPath = DefaultSocket
	}
	if _, err := os.Stat(socketPath); err != nil {
		return nil
	}
	httpClient := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "unix", socketPath)
			},
		},
	}
	// Host part of the URL is ignored by the unix transport but must
	// parse; "docker" is the conventional placeholder.
	return NewClient(httpClient, "http://docker")
}
