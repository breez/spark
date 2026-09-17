package handler

import (
	"context"
	"testing"

	"github.com/lightsparkdev/spark/common/keys"
	pbspark "github.com/lightsparkdev/spark/proto/spark"
	pbssp "github.com/lightsparkdev/spark/proto/spark_ssp_internal"
	"github.com/lightsparkdev/spark/so"
	"github.com/lightsparkdev/spark/so/authn"
	"github.com/lightsparkdev/spark/so/db"
	"github.com/lightsparkdev/spark/so/ent"
	st "github.com/lightsparkdev/spark/so/ent/schema/schematype"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// createTestCommittedInstantReservation is a reservation the SO running config
// committed as the coordinator, with authz enforced for its SSP's session.
func createTestCommittedInstantReservation(t *testing.T) (context.Context, *so.Config, *ent.UtxoSwap, *ent.Transfer) {
	t.Helper()
	ctx, _ := db.ConnectToTestPostgres(t)
	config := setUpTestConfigWithRegtestNoAuthz(t)
	config.AuthzEnforced = true
	swap, transfer, _ := createTestInstantReserveSwap(t, ctx, st.TransferStatusSenderKeyTweaked)
	swap, err := swap.Update().SetCoordinatorIdentityPublicKey(config.IdentityPublicKey()).Save(ctx)
	require.NoError(t, err)
	return authn.InjectSessionForTests(ctx, swap.SspIdentityPublicKey, 0), config, swap, transfer
}

// instantReserveRetryFor resends the request that made swap, carrying the
// fields a retry is checked on.
func instantReserveRetryFor(swap *ent.UtxoSwap) *pbssp.ReserveInstantStaticDepositUtxoSwapRequest {
	return &pbssp.ReserveInstantStaticDepositUtxoSwapRequest{
		OnChainUtxo:   &pbspark.UTXO{Network: pbspark.Network_REGTEST},
		SspSignature:  swap.SspSignature,
		UserSignature: swap.UserSignature,
		Transfer: &pbspark.StartTransferRequest{
			TransferId:             swap.RequestedTransferID.String(),
			OwnerIdentityPublicKey: swap.SspIdentityPublicKey.Serialize(),
			TransferPackage:        &pbspark.TransferPackage{},
		},
	}
}

func TestSspReserveInstantStaticDepositUtxoSwap_RetryReturnsTheCommittedReservation(t *testing.T) {
	t.Parallel()
	ctx, config, swap, transfer := createTestCommittedInstantReservation(t)

	resp, err := NewSspRequestHandler(config).ReserveInstantStaticDepositUtxoSwap(ctx, instantReserveRetryFor(swap))

	require.NoError(t, err)
	assert.Equal(t, swap.ID.String(), resp.GetUtxoSwapId())
	assert.Equal(t, transfer.ID.String(), resp.GetTransfer().GetId())
}

func TestSspReserveInstantStaticDepositUtxoSwap_RetryFromAnotherIdentityIsRefused(t *testing.T) {
	t.Parallel()
	ctx, config, swap, _ := createTestCommittedInstantReservation(t)
	ctx = authn.InjectSessionForTests(ctx, keys.GeneratePrivateKey().Public(), 0)

	resp, err := NewSspRequestHandler(config).ReserveInstantStaticDepositUtxoSwap(ctx, instantReserveRetryFor(swap))

	assert.Equal(t, codes.PermissionDenied, status.Code(err))
	assert.Nil(t, resp)
}

func TestSspReserveInstantStaticDepositUtxoSwap_DifferentRequestForAReservedTransferIsADuplicate(t *testing.T) {
	t.Parallel()
	for name, change := range map[string]func(*pbssp.ReserveInstantStaticDepositUtxoSwapRequest){
		"ssp signature":  func(req *pbssp.ReserveInstantStaticDepositUtxoSwapRequest) { req.SspSignature = []byte("other") },
		"user signature": func(req *pbssp.ReserveInstantStaticDepositUtxoSwapRequest) { req.UserSignature = []byte("other") },
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			ctx, config, swap, _ := createTestCommittedInstantReservation(t)
			req := instantReserveRetryFor(swap)
			change(req)

			resp, err := NewSspRequestHandler(config).ReserveInstantStaticDepositUtxoSwap(ctx, req)

			assert.Equal(t, codes.AlreadyExists, status.Code(err))
			assert.Nil(t, resp)
		})
	}
}

// A reservation this coordinator did not commit is not replayed: the request
// continues to the checks of a new reservation, the first of which refuses it
// here because the test SO has instant static deposits disabled.
func TestSspReserveInstantStaticDepositUtxoSwap_RetryOnlyReplaysReservationsThisCoordinatorCommitted(t *testing.T) {
	t.Parallel()
	for name, change := range map[string]func(*testing.T, context.Context, *ent.UtxoSwap){
		"cancelled": func(t *testing.T, ctx context.Context, swap *ent.UtxoSwap) {
			transfer, err := swap.QueryTransfer().Only(ctx)
			require.NoError(t, err)
			require.NoError(t, transfer.Update().SetStatus(st.TransferStatusReturned).Exec(ctx))
			require.NoError(t, CancelUtxoSwap(ctx, swap))
		},
		"coordinated by another operator": func(t *testing.T, ctx context.Context, swap *ent.UtxoSwap) {
			require.NoError(t, swap.Update().SetCoordinatorIdentityPublicKey(keys.GeneratePrivateKey().Public()).Exec(ctx))
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			ctx, config, swap, _ := createTestCommittedInstantReservation(t)
			change(t, ctx, swap)

			resp, err := NewSspRequestHandler(config).ReserveInstantStaticDepositUtxoSwap(ctx, instantReserveRetryFor(swap))

			require.ErrorContains(t, err, "instant static deposit is not enabled")
			assert.Nil(t, resp)
		})
	}
}
