package processor

import (
	"fmt"
	"net/http"

	"github.com/free5gc/openapi/models"
	"github.com/free5gc/scp/internal/logger"
)

// NOTE: The response from UDR is guaranteed to be correct
func (p *Processor) GetAuthSubsData(
	ueId string,
) *HandlerResponse {
	logger.DetectorLog.Debugln("[UDM->UDR] Forward UDM Authentication Data Query Request")

    // if err := validateUeId(ueId); err != nil {
    //     problemDetails := &models.ProblemDetails{
    //         Status: http.StatusBadRequest,
    //         Cause:  "INVALID_REQUEST",
    //         Detail: err.Error(),
    //     }
    //     return &HandlerResponse{http.StatusBadRequest, nil, problemDetails}
    // }

	// TODO: Send request to correct NF by setting correct uri
	var targetNfUri string
    targetNfUri = "http://10.100.200.4:8000"

	// TODO: Store UE auth subscription data
	response, problemDetails, err := p.Consumer().SendAuthSubsDataGet(targetNfUri, ueId)

    logger.ProxyLog.Debugf("AuthenticationSubscription: %#v", response)
    UeAuthProcedure.authSubs = response
    // &models.AuthenticationSubscription{
    //     AuthenticationMethod:"5G_AKA", 
    //     PermanentKey:(*models.PermanentKey)(0xc0005414d0), 
    //     SequenceNumber:"00000000012c", 
    //     AuthenticationManagementField:"8000", 
    //     VectorAlgorithm:"", 
    //     Milenage:(*models.Milenage)(0xc000541488), 
    //     Tuak:(*models.Tuak)(nil), 
    //     Opc:(*models.Opc)(0xc0005414b8), 
    //     Topc:(*models.Topc)(nil), 
    //     SharedAuthenticationSubscriptionId:(*models.SharedData)(nil)
    // }

    // no need validation?

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

// 驗證 UeId
func validateUeId(ueId string) error {
    // 檢查必要欄位
    if ueId == "" {
        logger.DetectorLog.Errorln("models.AuthenticationSubscription.UeId: Mandatory type is absent")
        return fmt.Errorf("missing mandatory field: ueId")
    }

    // 驗證欄位值格式
    /*if !strings.HasPrefix(ueId, "imsi-") {
        logger.DetectorLog.Errorln("models.AuthenticationSubscription.UeId: Unexpected value is received")
        return fmt.Errorf("invalid ueId format: must start with 'imsi-'")
    }*/

    // 驗證 IMSI 長度 (應為 15 位數字)
    /*imsi := strings.TrimPrefix(ueId, "imsi-")
    if len(imsi) != 15 || !isNumeric(imsi) {
        logger.DetectorLog.Errorln("models.AuthenticationSubscription.UeId: Unexpected value is received")
        return fmt.Errorf("invalid IMSI format: must be 15 digits")
    }*/

    return nil
}

// 檢查字串是否都是數字
func isNumeric(s string) bool {
    for _, c := range s {
        if c < '0' || c > '9' {
            return false
        }
    }
    return true
}
