package config

type Config struct {
	BoundaryAddr string
	LoginName    string
	AuthMethodID string
	Password     string
}

type SessionData struct {
	Port        int `json:"port"`
	Credentials []struct {
		CredentialSource struct {
			Name string `json:"name"`
		} `json:"credential_source"`
		Secret struct {
			Decoded struct {
				ServiceAccountToken string `json:"service_account_token"`
				Data                struct {
					CaCrt string `json:"ca_crt"`
				} `json:"data"`
			} `json:"decoded"`
		} `json:"secret"`
	} `json:"credentials"`
}
