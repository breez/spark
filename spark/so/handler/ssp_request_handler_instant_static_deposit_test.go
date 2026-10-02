package handler

import (
	"bytes"
	"testing"

	"github.com/lightsparkdev/spark/common/btcnetwork"
	pb "github.com/lightsparkdev/spark/proto/spark"
	pbssp "github.com/lightsparkdev/spark/proto/spark_ssp_internal"
	"github.com/lightsparkdev/spark/so/authn"
	"github.com/lightsparkdev/spark/so/db"
	"github.com/lightsparkdev/spark/so/ent"
	"github.com/lightsparkdev/spark/so/ent/depositaddress"
	st "github.com/lightsparkdev/spark/so/ent/schema/schematype"
	entutxoswap "github.com/lightsparkdev/spark/so/ent/utxoswap"
	"github.com/lightsparkdev/spark/so/knobs"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestSspClaimInstantStaticDepositUtxoSwapRefusesAClaimedReservation(t *testing.T) {
	ctx, _ := db.ConnectToTestPostgres(t)
	config := setUpTestConfigWithRegtestNoAuthz(t)
	client, err := ent.GetDbFromContext(ctx)
	require.NoError(t, err)
	swap, _, _ := createTestInstantReserveSwap(t, ctx, st.TransferStatusSenderKeyTweaked)
	depositAddress, err := client.DepositAddress.Query().Where(depositaddress.HasUtxoswapsWith(entutxoswap.ID(swap.ID))).Only(ctx)
	require.NoError(t, err)
	utxo := createTestInstantUtxo(t, ctx, client, depositAddress, bytes.Repeat([]byte{7}, 32))
	swap, err = swap.Update().SetUtxo(utxo).SetStatus(st.UtxoSwapStatusCompleted).Save(ctx)
	require.NoError(t, err)

	ctx = authn.InjectSessionForTests(ctx, swap.SspIdentityPublicKey, 0)
	ctx = knobs.InjectKnobsService(ctx, knobs.NewFixedKnobs(map[string]float64{
		knobs.KnobEnableInstantStaticDeposit + "@" + btcnetwork.Regtest.String(): 1,
	}))
	resp, err := NewSspRequestHandler(config).ClaimInstantStaticDepositUtxoSwap(ctx, &pbssp.ClaimInstantStaticDepositUtxoSwapRequest{
		OnChainUtxo: &pb.UTXO{Network: pb.Network_REGTEST},
		UtxoSwapId:  swap.ID.String(),
	})

	require.Nil(t, resp)
	require.Equal(t, codes.AlreadyExists, status.Code(err))
	require.ErrorContains(t, err, "is already claimed")
}
