package consumer

import (
	"io/ioutil"
	"sync"

	"github.com/free5gc/openapi"
	Nudm_UEAU "github.com/free5gc/openapi/Nudm_UEAuthentication"
	"github.com/free5gc/openapi/models"
	"github.com/free5gc/scp/internal/logger"
)

type nudmService struct {
	consumer *Consumer

	ueauMu sync.RWMutex

	ueauClients map[string]*Nudm_UEAU.APIClient
}

func (s *nudmService) getUdmUeauClient(uri string) *Nudm_UEAU.APIClient {
	if uri == "" {
		return nil
	}
	s.ueauMu.RLock()
	client, ok := s.ueauClients[uri]
	if ok {
		s.ueauMu.RUnlock()
		return client
	}

	configuration := Nudm_UEAU.NewConfiguration()
	configuration.SetBasePath(uri)
	client = Nudm_UEAU.NewAPIClient(configuration)

	s.ueauMu.RUnlock()
	s.ueauMu.Lock()
	defer s.ueauMu.Unlock()
	s.ueauClients[uri] = client
	return client
}

func (s *nudmService) SendGenerateAuthDataRequest(uri string,
	supiOrSuci string, authInfoReq *models.AuthenticationInfoRequest) (*models.AuthenticationInfoResult, *models.ProblemDetails, error) {

	client := s.getUdmUeauClient(uri)
	if client == nil {
		return nil, nil, openapi.ReportError("udm not found")
	}

	// TODO: OAuth UDM Generate Auth Data Post
	// ref: https://github.com/free5gc/openapi/blob/main/Nausf_UEAuthentication/api_default.go#L248
	scpCtx := s.consumer.scp.Context()
	tokenCtx, problemDetails, err := scpCtx.GetTokenCtx(models.ServiceName_NAUSF_AUTH, models.NfType_AUSF)
	if err != nil || problemDetails != nil {
		logger.ProxyLog.Errorf("GetTokenCtx failed: %s, %#v", err, problemDetails)
		return nil, nil, err
	}
	var authInfoResult models.AuthenticationInfoResult
	authInfoResult, httpResp, err := client.GenerateAuthDataApi.GenerateAuthData(tokenCtx, supiOrSuci, *authInfoReq)
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
	return &authInfoResult, nil, nil
}
