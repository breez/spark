package grpc

import (
	"context"

	pb "github.com/lightsparkdev/spark/proto/spark"
	pbssp "github.com/lightsparkdev/spark/proto/spark_ssp_internal"
	"github.com/lightsparkdev/spark/so"
	"github.com/lightsparkdev/spark/so/handler"
)

// SparkSspInternalServer implements SparkSspInternalService, the calls a service
// provider makes that a wallet never does.
type SparkSspInternalServer struct {
	pbssp.UnimplementedSparkSspInternalServiceServer
	handler *handler.SspRequestHandler
}

func NewSparkSspInternalServer(config *so.Config) *SparkSspInternalServer {
	return &SparkSspInternalServer{handler: handler.NewSspRequestHandler(config)}
}

func (s *SparkSspInternalServer) PrepareTreeAddress(ctx context.Context, req *pb.PrepareTreeAddressRequest) (*pb.PrepareTreeAddressResponse, error) {
	return s.handler.PrepareTreeAddress(ctx, req)
}

func (s *SparkSspInternalServer) CreateTree(ctx context.Context, req *pb.CreateTreeRequest) (*pb.CreateTreeResponse, error) {
	return s.handler.CreateTree(ctx, req)
}

func (s *SparkSspInternalServer) InitiateCounterTransfer(ctx context.Context, req *pbssp.CounterTransferRequest) (*pb.StartTransferResponse, error) {
	return s.handler.InitiateCounterTransfer(ctx, req)
}

func (s *SparkSspInternalServer) ReturnStuckTransfer(ctx context.Context, req *pbssp.ReturnStuckTransferRequest) (*pbssp.ReturnStuckTransferResponse, error) {
	return s.handler.ReturnStuckTransfer(ctx, req)
}

func (s *SparkSspInternalServer) InitiateStaticDepositUtxoSwap(ctx context.Context, req *pbssp.InitiateStaticDepositUtxoSwapRequest) (*pbssp.InitiateStaticDepositUtxoSwapResponse, error) {
	return s.handler.InitiateStaticDepositUtxoSwap(ctx, req)
}

func (s *SparkSspInternalServer) ReserveInstantStaticDepositUtxoSwap(ctx context.Context, req *pbssp.ReserveInstantStaticDepositUtxoSwapRequest) (*pbssp.ReserveInstantStaticDepositUtxoSwapResponse, error) {
	return s.handler.ReserveInstantStaticDepositUtxoSwap(ctx, req)
}

func (s *SparkSspInternalServer) ClaimInstantStaticDepositUtxoSwap(ctx context.Context, req *pbssp.ClaimInstantStaticDepositUtxoSwapRequest) (*pbssp.ClaimInstantStaticDepositUtxoSwapResponse, error) {
	return s.handler.ClaimInstantStaticDepositUtxoSwap(ctx, req)
}

func (s *SparkSspInternalServer) SignStaticDepositSweepTx(ctx context.Context, req *pbssp.SignStaticDepositSweepTxRequest) (*pbssp.SignStaticDepositSweepTxResponse, error) {
	return s.handler.SignStaticDepositSweepTx(ctx, req)
}
