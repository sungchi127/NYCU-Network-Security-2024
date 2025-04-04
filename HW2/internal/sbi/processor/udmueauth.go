package processor

import (
	"net/http"
	"regexp"
    "encoding/hex"

	"github.com/free5gc/openapi/models"
	"github.com/free5gc/scp/internal/logger"
    "github.com/free5gc/util/ueauth"
)

// NOTE: Assume Rand from UDM and ausfInstanceId from AUSF is correct
func (p *Processor) PostGenerateAuthData(
	supiOrSuci string,
	authInfo models.AuthenticationInfoRequest,
) *HandlerResponse {
	logger.ProxyLog.Debugln("[AUSF->UDM] Forward AUSF UE Authentication Request")


    // // 驗證 supiOrSuci
    // if supiOrSuci == "" {
    //     logger.DetectorLog.Errorln("models.AuthenticationInfoRequest.SupiOrSuci: Mandatory type is absent")
    //     problemDetails := &models.ProblemDetails{
    //         Status: http.StatusBadRequest,
    //         Cause:  "INVALID_REQUEST",
    //         Detail: "missing supiOrSuci",
    //     }
    //     return &HandlerResponse{http.StatusBadRequest, nil, problemDetails}
    // }

    validateAuthenticationInfoRequest(authInfo)
    authInfo.ServingNetworkName = UeAuthProcedure.ServingNetworkName
    logger.ProxyLog.Debugf("[Recovery] AuthenticationInfoRequest: %#v", authInfo)

	// TODO: Send request to target NF by setting correct uri
	var targetNfUri string
	targetNfUri = "http://10.100.200.3:8000"

	
	// TODO: Verify that the Information Elements (IEs) in the request or response body are correct
	//       Recover and handle errors if the IEs are incorrect
	response, problemDetails, err := p.Consumer().SendGenerateAuthDataRequest(targetNfUri, supiOrSuci, &authInfo)

    validateAuthenticationInfoResult(*response)
    response.Supi, err = extractSupi(UeAuthProcedure.Suci)
    if err != nil {
        logger.ProxyLog.Errorln("Error extracting SUPI from SUCI: ", err)
    }
    authSubs := UeAuthProcedure.authSubs
    randHex := response.AuthenticationVector.Rand
    _, SQNxorAK, _, _, autn := retrieveBasicDeriveFactor(authSubs, randHex)
    key := append(UeAuthProcedure.CK, UeAuthProcedure.IK...)
    P0 := []byte(UeAuthProcedure.ServingNetworkName)
    response.AuthenticationVector.Autn = hex.EncodeToString(autn)
    response.AuthenticationVector.XresStar = hex.EncodeToString(
        retrieveXresStar(
            key,
            ueauth.FC_FOR_RES_STAR_XRES_STAR_DERIVATION,
            P0,
            UeAuthProcedure.Rand,
            UeAuthProcedure.XRES,
        ),
    )
    response.AuthenticationVector.Kausf = hex.EncodeToString(
        retrieve5GAkaKausf(
            key,
            ueauth.FC_FOR_KAUSF_DERIVATION,
            P0,
            SQNxorAK,
        ),
    )

    logger.ProxyLog.Debugf("[Recovery] AuthenticationInfoResult: %#v", response)
    logger.ProxyLog.Debugf("[Recovery] AuthenticationInfoResult.AuthenticationVector: %#v", response.AuthenticationVector)
	
    if response != nil {
		return &HandlerResponse{http.StatusOK, nil, response}
	} else if problemDetails != nil {
		return &HandlerResponse{int(problemDetails.Status), nil, problemDetails}
	}
	logger.ProxyLog.Errorln(err)
	problemDetails = &models.ProblemDetails{
		Status: http.StatusForbidden,
		Cause:  "UNSPECIFIED",
	}

	return &HandlerResponse{http.StatusForbidden, nil, problemDetails}
}

func validateAuthenticationInfoResult(data models.AuthenticationInfoResult) {
    // &models.AuthenticationInfoResult{
    //   AuthType:"5G_AKA", 
    //   SupportedFeatures:"", 
    //   AuthenticationVector:(*models.AuthenticationVector)(0xc00008de80), 
    //   Supi:"imsi-208930000000001"
    // }
    // authenticationVector: &models.AuthenticationVector{
    //   AvType:"5G_HE_AKA", 
    //   Rand:"15d82d61793daad23c865e9467fdc5f2", 
    //   Xres:"", 
    //   Autn:"357553be08998000cf4a96a07a74f54a", 
    //   CkPrime:"", 
    //   IkPrime:"", 
    //   XresStar:"03402f98596e13c390fd1194b84a1384", 
    //   Kausf:"32e67725fb1271c1b95b18c5f60a2852bcb764cfdce7fea4982510e1fee47a68"
    // }
    // AuthenticationInfoRessult shall contain the authType, an authentication vector (conditional, if 5GAKA or EAP-AKA's is selected)
    // (conditional)SUPI shall be present if the request contained the SUCI within the request URI 

    // ref: https://www.etsi.org/deliver/etsi_ts/129500_129599/129503/17.07.00_60/ts_129503v170700p.pdf p.289
    // Type: AuthenticationInfoResult
    //   authType: AuthType Mandatory
    //   authenticationVector: AuthenticationVector Conditional (if 5G AKA or EAP-AKA's is selected)
    //     fields: presented above, everyting is mandatory
    //   supi: Supi Conditional (if request contained the SUCI within the request URI)

    logger.ProxyLog.Debugf("authenticationInfoResult: %#v", data)
    if data.Supi == "" {
        logger.DetectorLog.Errorln("AuthenticationInfoResult.Supi: Miss Condition")
    }
    if data.AuthType == "" {
        logger.DetectorLog.Errorln("AuthenticationInfoResult.AuthType: Mandatory type is absent")
    } else {
        if data.AuthType != models.AuthType__5_G_AKA {
            logger.DetectorLog.Errorln("AuthenticationInfoResult.AuthType: Unexpected value is received")
        }
    }
    if data.AuthenticationVector == nil {
        logger.DetectorLog.Errorln("AuthenticationInfoResult.AuthenticationVector: Miss Condition")
    } else {
        logger.ProxyLog.Debugf("authenticationVector: %#v", data.AuthenticationVector)
        if data.AuthenticationVector.AvType == "" {
            logger.DetectorLog.Errorln("AuthenticationInfoResult.AuthenticationVector.AvType: Mandatory type is absent")
        } else if (data.AuthenticationVector.AvType != models.AvType__5_G_HE_AKA) {
            logger.DetectorLog.Errorln("AuthenticationInfoResult.AuthenticationVector.AvType: Unexpected value is received")
        }
        if data.AuthenticationVector.Rand == "" {
            logger.DetectorLog.Errorln("AuthenticationInfoResult.AuthenticationVector.Rand: Mandatory type is absent")
        }
        if data.AuthenticationVector.Autn == "" {
            logger.DetectorLog.Errorln("AuthenticationInfoResult.AuthenticationVector.Autn: Mandatory type is absent")
        }
        if data.AuthenticationVector.XresStar == "" {
            logger.DetectorLog.Errorln("AuthenticationInfoResult.AuthenticationVector.XresStar: Mandatory type is absent")
        }
        if data.AuthenticationVector.Kausf == "" {
            logger.DetectorLog.Errorln("AuthenticationInfoResult.AuthenticationVector.Kausf: Mandatory type is absent")
        }
    }
}

func validateAuthenticationInfoRequest(data models.AuthenticationInfoRequest) {
    // authenticationInfoRequest shall contain servingNetworkName and ausfInstanceId

    // ref: https://www.etsi.org/deliver/etsi_ts/129500_129599/129503/17.07.00_60/ts_129503v170700p.pdf p.289
    // Type: AuthenticationInfoRequest
    //   servingNetworkName: ServingNetworkName Mandatory
    //   ausfInstanceId: NfInstanceId Mandatory
    //     RFC UUID format

    logger.ProxyLog.Debugf("authenticationInfoRequest: %#v", data)
    if data.ServingNetworkName == "" {
        logger.DetectorLog.Errorln("AuthenticationInfoRequest.ServingNetworkName: Mandatory type is absent")
    } else {
        matched, err := regexp.MatchString("^(5G:mnc[0-9]{3}[.]mcc[0-9]{3}[.]3gppnetwork[.]org(:[AF0-9]{11})?)|5G:NSWO$", data.ServingNetworkName)
        if err != nil {
            logger.ProxyLog.Errorln("Error compiling regex: ", err)
        } else if !matched {
            logger.DetectorLog.Errorln("AuthenticationInfoRequest.ServingNetworkName: Unexpected value is received")
        }
    }
    if data.AusfInstanceId == "" {
        logger.DetectorLog.Errorln("AuthenticationInfoRequest.AusfInstanceId: Mandatory type is absent")
    } else {
        matched, err := regexp.MatchString("^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", data.AusfInstanceId)
        if err != nil {
            logger.ProxyLog.Errorln("Error compiling regex: ", err)
        } else if !matched {
            logger.DetectorLog.Errorln("AuthenticationInfoRequest.AusfInstanceId: Unexpected value is received")
        }
    }
}
