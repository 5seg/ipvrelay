package vpnapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
)

// GeoLocation is the caller's own location as seen by the API. It is used to
// pick a sensible first server for the user instead of the least loaded one
// anywhere on the planet.
type GeoLocation struct {
	IP       string `json:"ip"`
	Location struct {
		Country     string `json:"country"`
		CountryCode string `json:"country_code"`
		City        string `json:"city"`
		Region      string `json:"region"`
	} `json:"location"`
}

// GeoLocation asks the API where this client is.
func (c *Client) GeoLocation(ctx context.Context) (GeoLocation, error) {
	req, err := c.newRequest(ctx, http.MethodGet, "/ipgeo", apiVersionLogin, nil)
	if err != nil {
		return GeoLocation{}, err
	}
	body, err := c.do(req)
	if err != nil {
		return GeoLocation{}, err
	}
	var g GeoLocation
	if err := json.Unmarshal(body, &g); err != nil {
		return GeoLocation{}, fmt.Errorf("vpnapi: parse ipgeo: %w", err)
	}
	return g, nil
}
