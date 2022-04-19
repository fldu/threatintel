package ghsa

type GHSADataRaw struct {
	Data struct {
		SecurityAdvisories struct {
			Nodes []struct {
				Summary     string `json:"summary"`
				Description string `json:"description"`
				GhsaID      string `json:"ghsaId"`
				PublishedAt string `json:"publishedAt"`
				Cvss        struct {
					Score        float64 `json:"score"`
					VectorString string  `json:"vectorString"`
				} `json:"cvss"`
				Severity  string `json:"severity"`
				Permalink string `json:"permalink"`
			} `json:"nodes"`
		} `json:"securityAdvisories"`
	} `json:"data"`
}

type GHSAData struct {
	Summary     string
	Description string
	GHSAID      string
	PublishedAt string
	Score       float64
	CVSSScore   string
	Severity    string
	Permalink   string
}
