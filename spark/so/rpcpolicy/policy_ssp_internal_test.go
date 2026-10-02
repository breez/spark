package rpcpolicy

import (
	pbssp "github.com/lightsparkdev/spark/proto/spark_ssp_internal"
)

func init() {
	baseRegisteredServiceDescs = append(baseRegisteredServiceDescs, &pbssp.SparkSspInternalService_ServiceDesc)
}
