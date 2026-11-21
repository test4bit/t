// File: internal/config/constants.go
package config

const (
	NSName        = "amnezia"
	VPNIface      = "wg0"
	WARPIface     = "wg1"
	VethHost      = "v-host"
	VethNS        = "v-ns"
	ClientIPWG    = "192.168.166.2"
	ServerIPWG    = "192.168.166.1"
	ServerLPort   = 443
	MinClientPort = 20000
	MaxClientPort = 30000
	TUNMTU        = 1280

	VethHostIP = "192.168.15.1/24"
	VethNSIP   = "192.168.15.2/24"

	KeepaliveTarget = "1.1.1.1:53"
	HealthTarget    = "1.1.1.1:53"

	StatusServerReady = "server_ready"
	StatusClientReady = "client_ready"
)

var STUNServers = []string{
	"stun.cloudflare.com:3478",
	"stun.miwifi.com:3478",
	"stun.l.google.com:19302",
}

type AWGParams struct {
	JC                     int
	JMin                   int
	JMax                   int
	S1                     int
	S2                     int
	S3                     int
	S4                     int
	H1                     string
	H2                     string
	H3                     string
	H4                     string
	ContentPaddingAddition string
	RekeyAfterTime         string
	RekeyTimeout           string
	RejectAfterTime        string
	KeepaliveTimeout       string
	MaxHandshakeAttempts   string
	I1                     string
	I2                     string
	I3                     string
	I4                     string
	I5                     string
	RandomTrailers         bool
	DisableCookies         bool
}

// DefaultAWGParams - параметры обфускации AWG 3.1 для связи Клиент <-> Сервер
func DefaultAWGParams() AWGParams {
	return AWGParams{
		JC: 7, JMin: 8, JMax: 80,
		S1: 40, S2: 40, S3: 40, S4: 40,
		H1: "70-100", H2: "110-140",
		H3: "150-180", H4: "190-220",
		RandomTrailers:       true,
		RekeyAfterTime:       "120-130",
		RekeyTimeout:         "5-7",
		RejectAfterTime:      "180-200",
		KeepaliveTimeout:     "10-15",
		MaxHandshakeAttempts: "5-10",
	}
}

// ClientAWGParams disables cookie responses only on the client. This removes
// under-load protection on that side; the server keeps it enabled.
func ClientAWGParams() AWGParams {
	p := DefaultAWGParams()
	p.DisableCookies = true
	return p
}

// StandardWGParams - "чистый" WireGuard для связи Сервер <-> Cloudflare WARP
func StandardWGParams() AWGParams {
	return AWGParams{
		JC: 0, JMin: 0, JMax: 0,
		S1: 0, S2: 0, S3: 0, S4: 0,
		H1: "1", H2: "2", H3: "3", H4: "4",
		// Все остальные параметры остаются пустыми, отключая фичи AWG
	}
}
