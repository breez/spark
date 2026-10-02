package rpcpolicy

import (
	pbssp "github.com/lightsparkdev/spark/proto/spark_ssp_internal"
)

func init() {
	register(sparkSspInternalServicePolicies())
}

// sparkSspInternalServicePolicies requires a session for every call, and a caller
// on the service authz allowlist when authz is enforced.
func sparkSspInternalServicePolicies() map[string]Policy {
	sessionInternal := Policy{AuthMode: AuthSession, InternalOnly: true}
	return map[string]Policy{
		pbssp.SparkSspInternalService_PrepareTreeAddress_FullMethodName:                  sessionInternal,
		pbssp.SparkSspInternalService_CreateTree_FullMethodName:                          sessionInternal,
		pbssp.SparkSspInternalService_InitiateCounterTransfer_FullMethodName:             sessionInternal,
		pbssp.SparkSspInternalService_ReturnStuckTransfer_FullMethodName:                 sessionInternal,
		pbssp.SparkSspInternalService_InitiateStaticDepositUtxoSwap_FullMethodName:       sessionInternal,
		pbssp.SparkSspInternalService_ReserveInstantStaticDepositUtxoSwap_FullMethodName: sessionInternal,
		pbssp.SparkSspInternalService_ClaimInstantStaticDepositUtxoSwap_FullMethodName:   sessionInternal,
		pbssp.SparkSspInternalService_SignStaticDepositSweepTx_FullMethodName:            sessionInternal,
	}
}
