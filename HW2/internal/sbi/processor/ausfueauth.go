package processor

import (
	"net/http"
	"regexp"
    "encoding/hex"

	"github.com/free5gc/openapi/models"
	"github.com/free5gc/scp/internal/logger"
)

// NOTE: The response from AMF is guaranteed to be correct
func (p *Processor) PostUeAutentications(
	authInfo models.AuthenticationInfo,
) *HandlerResponse {
	logger.ProxyLog.Debugln("[AMF->AUSF] Forward AMF UE Authentication Request")

    // 驗證 Information Elements
    validateAuthInfo(authInfo)
    UeAuthProcedure.ServingNetworkName = authInfo.ServingNetworkName
    UeAuthProcedure.Suci = authInfo.SupiOrSuci

	// TODO: Send request to target NF by setting correct uri
	var targetNfUri string
    targetNfUri = "http://10.100.200.9:8000"

	// TODO: Verify that the Information Elements (IEs) in the response body are correct
	//       Recover and handle errors if the IEs are incorrect
	response, problemDetails, err := p.Consumer().SendUeAuthPostRequest(targetNfUri, &authInfo)

    validateUeAuthenticationCtx(*response)
    response.AuthType = models.AuthType__5_G_AKA
    if var5gAuthData, ok := response.Var5gAuthData.(map[string]interface{}); ok {
        var5gAuthData["autn"] = hex.EncodeToString(UeAuthProcedure.Autn)
        var5gAuthData["rand"] = hex.EncodeToString(UeAuthProcedure.Rand)
        tmp := hex.EncodeToString(UeAuthProcedure.Rand) + hex.EncodeToString(UeAuthProcedure.XresStar)
        bytes, err := hex.DecodeString(tmp)
        if err != nil {
            logger.ProxyLog.Errorln("Error decoding hex: ", err)
        }
        var5gAuthData["hxresStar"] = hex.EncodeToString(retrieveHxresStar(bytes))
    } else {
        logger.ProxyLog.Errorln("response.Var5gAuthData: Invalid type")
    }
    logger.ProxyLog.Debugf("[Recovery] UeAuthenticationCtx: %#v", response)

	if response != nil {
		return &HandlerResponse{http.StatusCreated, nil, response}
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

func (p *Processor) PutUeAutenticationsConfirmation(
	authCtxId string,
	confirmationData models.ConfirmationData,
) *HandlerResponse {
	logger.ProxyLog.Debugln("[AMF->AUSF] Forward AMF UE Authentication Response")

    // 驗證 authCtxId
    // if authCtxId == "" {
    //     logger.DetectorLog.Errorln("models.ConfirmationData.AuthCtxId: Mandatory type is absent")
    //     problemDetails := &models.ProblemDetails{
    //         Status: http.StatusBadRequest,
    //         Cause:  "INVALID_REQUEST",
    //         Detail: "missing authCtxId",
    //     }
    //     return &HandlerResponse{http.StatusBadRequest, nil, problemDetails}
    // }

    validateConfirmationData(confirmationData)

	// TODO: Send request to target NF by setting correct uri
	var targetNfUri string
	targetNfUri = "http://10.100.200.9:8000"

	// TODO: Verify that the Information Elements (IEs) in the response body are correct
	//       Recover and handle errors if the IEs are incorrect
	
    response, problemDetails, err := p.Consumer().SendAuth5gAkaConfirmRequest(targetNfUri, authCtxId, &confirmationData)

    validateConfirmationDataResponse(*response)
    response.Supi, err = extractSupi(UeAuthProcedure.Suci)
    if err != nil {
        logger.ProxyLog.Errorln("Error extracting SUPI from SUCI: ", err)
    }
    response.Kseaf = hex.EncodeToString(
        retrieveKseaf(
            UeAuthProcedure.Kausf,
            "",
            []byte(UeAuthProcedure.ServingNetworkName),
        ),
    )

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

func validateUeAuthenticationCtx(data models.UeAuthenticationCtx) {
    // &models.UeAuthenticationCtx{
    //    AuthType:"5G_AKA", 
    //    Var5gAuthData:map[string]interface {}{
    //       "autn":"bce592312b3780000e11153191dfbf9a", 
    //       "hxresStar":"c52a08a92367846acedf58e9b6faaa10", 
    //       "rand":"e89e4c73a6d57ab72d8345b20874e22c"
    //   }, 
    //   Links:map[string]models.LinksValueSchema{"5g-aka":models.LinksValueSchema{Href:"http://ausf.free5gc.org:8000/nausf-auth/v1/ue-authentications/suci-0-208-93-0000-0-0-0000000001/5g-aka-confirmation"}}, 
    //   ServingNetworkName:"5G:mnc093.mcc208.3gppnetwork.org"
    // }

    // ref: https://www.etsi.org/deliver/etsi_ts/129500_129599/129509/16.04.00_60/ts_129509v160400p.pdf p.25
    // Upon success, if 5G AKA is selected, the response body will contain one AV and "link" for the AMF to PUT the confirmation.
    // The HTTP response shall include a "Location" header that contains the resource URI of the created resource.
    // Contains the information related to the resource generated to handle the UE authentication. It contains at least the UE id, Serving Network, the Authentication Method and related EAP information or related 5G-AKA information. 

    // ref: https://www.etsi.org/deliver/etsi_ts/129500_129599/129509/16.04.00_60/ts_129509v160400p.pdf p.32
    // ref: common type https://www.etsi.org/deliver/etsi_ts/129500_129599/129503/17.07.00_60/ts_129503v170700p.pdf p.294
    // ref: link https://www.etsi.org/deliver/etsi_ts/129500_129599/129571/16.06.00_60/ts_129571v160600p.pdf p.21
    // Type: UeAuthenticationCtx
    // authType: AuthType Mandatory (expected to be exactly "5G_AKA")
    // _links: map[string]LinksValueSchema Mandatory, this IE shall contain a member whose name is set to "5g-aka" and the URI to perform the confirmation
    //   LinkValueSchema
    //     Href: Uri(string) Mandatory 
    // 5gAuthData: 5gAuthData -> Av5gAka
    //   rand: Rand Mandatory pattern: "^[A-Fa-f0-9]{32}$"
    //   autn: Autn Mandatory pattern: "^[A-Fa-f0-9]{32}$" 
    //   hxresStar: HxresStar Mandatory pattern: "^[A-Fa-f0-9]{32}$" 
    // servingNetworkName: ServingNetworkName Optional pattern: "^(5G:mnc[0-9]{3}[.]mcc[0-9]{3}[.]3gppnetwork[.]org(:[AF0-9]{11})?)|5G:NSWO$" 

    logger.ProxyLog.Debugf("UeAuthenticationCtx: %#v", data)

    if data.AuthType == "" {
        logger.DetectorLog.Errorln("UeAuthenticationCtx.AuthType: Mandatory type is absent")
    } else if data.AuthType != models.AuthType__5_G_AKA {
        logger.DetectorLog.Errorln("UeAuthenticationCtx.AuthType: Unexpected value is received")
    }

    if data.Var5gAuthData == nil {
        logger.DetectorLog.Errorln("UeAuthenticationCtx.Var5gAuthData: Mandatory type is absent")
        data.Var5gAuthData = map[string]interface{}{}
    } else {
        var5gAuthData, ok := data.Var5gAuthData.(map[string]interface{})
        logger.ProxyLog.Debugf("UeAuthenticationCtx.Var5gAuthData: %#v", var5gAuthData)
        if !ok {
            logger.ProxyLog.Errorln("UeAuthenticationCtx.Var5gAuthData: Invalid type")
        }

        if rand, ok := var5gAuthData["rand"].(string); !ok || rand == "" {
            logger.DetectorLog.Errorln("UeAuthenticationCtx.Av5gAka.Rand: Mandatory type is absent")
        } else {
            matched, err := regexp.MatchString("^[A-Fa-f0-9]{32}$", rand)
            if err != nil {
                logger.ProxyLog.Errorln("Error compiling regex: ", err)
            } else if !matched {
                logger.DetectorLog.Errorln("UeAuthenticationCtx.Av5gAka.Rand: Unexpected value is received")
            }
        }

        if autn, ok := var5gAuthData["autn"].(string); !ok || autn == "" {
            logger.DetectorLog.Errorln("UeAuthenticationCtx.Av5gAka.Autn: Mandatory type is absent")
        } else {
            matched, err := regexp.MatchString("^[A-Fa-f0-9]{32}$", autn)
            if err != nil {
                logger.ProxyLog.Errorln("Error compiling regex: ", err)
            } else if !matched {
                logger.DetectorLog.Errorln("UeAuthenticationCtx.Av5gAka.Autn: Unexpected value is received")
            }
        }

        if hxresStar, ok := var5gAuthData["hxresStar"].(string); !ok || hxresStar == "" {
            logger.DetectorLog.Errorln("UeAuthenticationCtx.Av5gAka.HxresStar: Mandatory type is absent")
        } else {
            matched, err := regexp.MatchString("^[A-Fa-f0-9]{32}$", hxresStar)
            if err != nil {
                logger.ProxyLog.Errorln("Error compiling regex: ", err)
            } else if !matched {
                logger.DetectorLog.Errorln("UeAuthenticationCtx.Av5gAka.HxresStar: Unexpected value is received")
            }
        }
    }

    if data.Links == nil {
        logger.DetectorLog.Errorln("UeAuthenticationCtx.Links: Mandatory type is absent")
    } else {
        if link, ok := data.Links["5g-aka"]; !ok {
            logger.DetectorLog.Errorln("UeAuthenticationCtx.Links: Mandatory type is absent")
        } else if link.Href == "" {
            logger.DetectorLog.Errorln("UeAuthenticationCtx.Links.5g-aka: Mandatory type is absent")
        }
    }

    if data.ServingNetworkName != "" {
        matched, err := regexp.MatchString("^(5G:mnc[0-9]{3}[.]mcc[0-9]{3}[.]3gppnetwork[.]org(:[AF0-9]{11})?)|5G:NSWO$", data.ServingNetworkName)
        if err != nil {
            logger.ProxyLog.Errorln("Error compiling regex: ", err)
        } else if !matched {
            logger.DetectorLog.Errorln("UeAuthenticationCtx.ServingNetworkName: Unexpected value is received")
        }
    }
}

// 驗證 AuthenticationInfo
func validateAuthInfo(authInfo models.AuthenticationInfo) {
    // ref: https://www.etsi.org/deliver/etsi_ts/129500_129599/129509/16.04.00_60/ts_129509v160400p.pdf p.32
    // Type: AuthenticationInfo
    // supiOrSuci: SupiOrSuci Mandatory
    // servingNetworkName: ServingNetworkName Mandatory pattern: "^(5G:mnc[0-9]{3}[.]mcc[0-9]{3}[.]3gppnetwork[.]org(:[AF0-9]{11})?)|5G:NSWO$" 

    logger.ProxyLog.Debugf("AuthenticationInfo: %#v", authInfo)
    if authInfo.SupiOrSuci == "" {
        logger.DetectorLog.Errorln("AuthenticationInfo.SupiOrSuci: Mandatory type is absent")
    } else {
        // Validate supiOrSuci format
        matched, err := regexp.MatchString(`^(imsi-[0-9]{5,15}|nai-.+|gci-.+|gli-.+|.+)$`, authInfo.SupiOrSuci)
        if err != nil {
            logger.ProxyLog.Errorln("Error compiling regex: ", err)
        } else if !matched {
            logger.DetectorLog.Errorln("AuthenticationInfo.SupiOrSuci: Unexpected value is received")
        }
    }

    if authInfo.ServingNetworkName == "" {
        logger.DetectorLog.Errorln("AuthenticationInfo.ServingNetworkName: Mandatory type is absent")
    } else {
        // Validate ServingNetworkName format
        matched, err := regexp.MatchString(`^(5G:mnc[0-9]{3}[.]mcc[0-9]{3}[.]3gppnetwork[.]org(:[AF0-9]{11})?)|5G:NSWO$`, authInfo.ServingNetworkName)
        if err != nil {
            logger.ProxyLog.Errorln("Error compiling regex: ", err)
        } else if !matched {
            logger.DetectorLog.Errorln("AuthenticationInfo.ServingNetworkName: Unexpected value is received")
        }
    }
}

// 驗證 ConfirmationData
func validateConfirmationData(data models.ConfirmationData) {
    // ref: https://www.etsi.org/deliver/etsi_ts/129500_129599/129509/16.04.00_60/ts_129509v160400p.pdf p.33
    // Type: ConfirmationData
    //   resStar: ResStar Mandatory
    //     Contains the "RES*" provided by the UE to the AMF. If no RES* has been provided by the UE the null value is conveyed to the AUSF.

    logger.ProxyLog.Debugf("ConfirmationData: %#v", data)
    if data.ResStar == "" { // Hm but the spec says it can be null
        logger.DetectorLog.Errorln("ConfirmationData.ResStar: Mandatory type is absent")
    }
}

func validateConfirmationDataResponse(data models.ConfirmationDataResponse) {
    // The response body shall contain the result of the authentication and the Kseaf if the authentication is successful.
    // ref: https://www.etsi.org/deliver/etsi_ts/129500_129599/129509/16.04.00_60/ts_129509v160400p.pdf p.33
    // Type: ConfirmationDataResponse
    //   authResult: AuthResult Mandatory
    //      enum: "AUTHENTICATION_SUCCESS", "AUTHENTICATION_FAILURE", "AUTHENTICATION_ONGOING"
    //   supi: Supi Conditional (if authentication succcessful)
    //   kseaf: Kseaf Conditional (if authentication succcessful) pattern: "^[A-Fa-f0-9]{64}$" 

    // &models.ConfirmationDataResponse{
    //   AuthResult:"AUTHENTICATION_SUCCESS", 
    //   Supi:"imsi-208930000000001", 
    //   Kseaf:"9c92cefd26ce397f138947e0931528bd6b3104cdb9c55cfe57078d7e1e7fe4b5"
    // }

    logger.ProxyLog.Debugf("ConfirmationDataResponse: %#v", data)
    
    if data.AuthResult == "" {
        logger.DetectorLog.Errorln("ConfirmationDataResponse.AuthResult: Mandatory type is absent")
    }

    if data.AuthResult == models.AuthResult_SUCCESS {
        if data.Supi == "" {
            logger.DetectorLog.Errorln("ConfirmationDataResponse.Supi: Miss Condition")
        } else {
            matched, err := regexp.MatchString(`^(imsi-[0-9]{5,15}|nai-.+|gci-.+|gli-.+|.+)$`, data.Supi)
            if err != nil {
                logger.ProxyLog.Errorln("Error compiling regex: ", err)
            } else if !matched {
                logger.DetectorLog.Errorln("ConfirmationResponse.SupiOrSuci: Unexpected value is received")
            }
        }

        if data.Kseaf == "" {
            logger.DetectorLog.Errorln("ConfirmationDataResponse.Kseaf: Miss Condition")
        } else {
            // Validate Kseaf format
            matched, err := regexp.MatchString(`^[A-Fa-f0-9]{64}$`, data.Kseaf)
            if err != nil {
                logger.ProxyLog.Errorln("Error compiling regex: ", err)
            } else if !matched {
                logger.DetectorLog.Errorln("ConfirmationDataResponse.Kseaf: Unexpected value is received")
            }
        }
    }
}
