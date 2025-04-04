package consumer

import (
	"io/ioutil"
	"sync"

	"github.com/antihax/optional"
	"github.com/free5gc/openapi"
	"github.com/free5gc/openapi/Nausf_UEAuthentication"
	"github.com/free5gc/openapi/models"
	"github.com/free5gc/scp/internal/logger"
)

type nausfService struct {
	consumer *Consumer

	UEAuthenticationMu sync.RWMutex

	UEAuthenticationClients map[string]*Nausf_UEAuthentication.APIClient
}

func (s *nausfService) getUEAuthenticationClient(uri string) *Nausf_UEAuthentication.APIClient {
	if uri == "" {
		return nil
	}
	s.UEAuthenticationMu.RLock()
	client, ok := s.UEAuthenticationClients[uri]
	if ok {
		s.UEAuthenticationMu.RUnlock()
		return client
	}

	configuration := Nausf_UEAuthentication.NewConfiguration()
	configuration.SetBasePath(uri)
	client = Nausf_UEAuthentication.NewAPIClient(configuration)

	s.UEAuthenticationMu.RUnlock()
	s.UEAuthenticationMu.Lock()
	defer s.UEAuthenticationMu.Unlock()
	s.UEAuthenticationClients[uri] = client
	return client
}

func (s *nausfService) SendUeAuthPostRequest(uri string,
	authInfo *models.AuthenticationInfo) (*models.UeAuthenticationCtx, *models.ProblemDetails, error) {

	client := s.getUEAuthenticationClient(uri)
	if client == nil {
		return nil, nil, openapi.ReportError("ausf not found")
	}
	// logger.ProxyLog.Debugf("[AMF->AUSF] SendUeAuthPostRequest@ausf_service, authInfo: %#v, client: %#v", authInfo, client)

	// TODO: OAuth AUSF Ue Auth Post
	// ref: https://github.com/free5gc/openapi/blob/main/Nausf_UEAuthentication/api_default.go#L248
	scpCtx := s.consumer.scp.Context()
	tokenCtx, problemDetails, err := scpCtx.GetTokenCtx(models.ServiceName_NAUSF_AUTH, models.NfType_AUSF)
	if err != nil || problemDetails != nil {
		logger.ProxyLog.Errorf("GetTokenCtx failed: %s, %#v", err, problemDetails)
		return nil, nil, err
	}
	ueAuthenticationCtx, httpResp, err := client.DefaultApi.UeAuthenticationsPost(tokenCtx, *authInfo)
	// logger.ProxyLog.Debugf("client: %#v", client)
	// logger.ProxyLog.Debugf("ueAuthenticationCtx: %#v, httpResp: %#v, err: %s", ueAuthenticationCtx, httpResp, err)
	// logger.ProxyLog.Debugf("response.body: %#v", httpResp.Body)
	// logger.ProxyLog.Debugf("request: %#v", httpResp.Request)
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
	return &ueAuthenticationCtx, nil, nil
}

func (s *nausfService) SendAuth5gAkaConfirmRequest(uri string,
	authCtxId string, confirmationData *models.ConfirmationData) (*models.ConfirmationDataResponse, *models.ProblemDetails, error) {

	client := s.getUEAuthenticationClient(uri)
	if client == nil {
		return nil, nil, openapi.ReportError("ausf not found")
	}

	// TODO: OAuth AUSF Auth 5gAka Confirm Put
	scpCtx := s.consumer.scp.Context()
	tokenCtx, problemDetails, err := scpCtx.GetTokenCtx(models.ServiceName_NAUSF_AUTH, models.NfType_AUSF)
	if err != nil || problemDetails != nil {
		logger.ProxyLog.Errorf("GetTokenCtx failed: %s, %#v", err, problemDetails)
		return nil, nil, err
	}
	// logger.ProxyLog.Debugf("confirmationData: %#v", confirmationData)
	localVarOptionals := &Nausf_UEAuthentication.UeAuthenticationsAuthCtxId5gAkaConfirmationPutParamOpts{
    ConfirmationData: optional.NewInterface(*confirmationData),
	}
	var confirmResult models.ConfirmationDataResponse
	confirmResult, httpResp, err := client.DefaultApi.UeAuthenticationsAuthCtxId5gAkaConfirmationPut(tokenCtx, authCtxId, localVarOptionals)
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
	return &confirmResult, nil, nil
}
