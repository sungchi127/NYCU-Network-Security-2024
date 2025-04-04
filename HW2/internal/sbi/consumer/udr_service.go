package consumer

import (
	"io/ioutil"
	"sync"

	"github.com/free5gc/openapi"
	"github.com/free5gc/openapi/Nudr_DataRepository"
	"github.com/free5gc/openapi/models"
	"github.com/free5gc/scp/internal/logger"
)

type nudrService struct {
	consumer *Consumer

	mu      sync.RWMutex
	clients map[string]*Nudr_DataRepository.APIClient
}

func (s *nudrService) getClient(uri string) *Nudr_DataRepository.APIClient {
	s.mu.RLock()
	if client, ok := s.clients[uri]; ok {
		defer s.mu.RUnlock()
		return client
	} else {
		configuration := Nudr_DataRepository.NewConfiguration()
		configuration.SetBasePath(uri)
		cli := Nudr_DataRepository.NewAPIClient(configuration)

		s.mu.RUnlock()
		s.mu.Lock()
		defer s.mu.Unlock()
		s.clients[uri] = cli
		return cli
	}
}

func (s *nudrService) SendAuthSubsDataGet(uri string,
	supi string) (*models.AuthenticationSubscription, *models.ProblemDetails, error) {

	client := s.getClient(uri)
	if client == nil {
		return nil, nil, openapi.ReportError("udr not found")
	}

	// TODO: OAuth UDR Auth Subs Data Get
	// get /subscription-data/{ueId}/authentication-data/authentication-subscription
	// ref: https://github.com/free5gc/openapi/blob/main/Nudr_DataRepository/api/openapi.yaml#L20
	scpCtx := s.consumer.scp.Context()
	tokenCtx, problemDetails, err := scpCtx.GetTokenCtx(models.ServiceName_NAUSF_AUTH, models.NfType_AUSF)
	if err != nil || problemDetails != nil {
		logger.ProxyLog.Errorf("GetTokenCtx failed: %s, %#v", err, problemDetails)
		return nil, nil, err
	}
	var authSubs models.AuthenticationSubscription
	authSubs, httpResp, err := client.AuthenticationDataDocumentApi.QueryAuthSubsData(tokenCtx, supi, nil)
	if err != nil {
		if httpResp != nil && httpResp.StatusCode == 400 {
			var problemDetails models.ProblemDetails
			bodyBytes, err := ioutil.ReadAll(httpResp.Body)
			if err != nil {
				return nil, nil, err
			}
			if err := openapi.Deserialize(&problemDetails, bodyBytes, httpResp.Header.Get("Content-Type")); err != nil {
				return nil, nil, err
			}
			return nil, &problemDetails, nil
		}
		return nil, nil, err
	}
	return &authSubs, nil, nil
}
