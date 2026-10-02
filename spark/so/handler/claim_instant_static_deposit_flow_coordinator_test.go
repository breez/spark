package handler

import (
	"math/rand/v2"
	"testing"

	pbssp "github.com/lightsparkdev/spark/proto/spark_ssp_internal"
	"github.com/stretchr/testify/require"
)

func TestClaimInstantStaticDepositUtxoSwapRejectsASpendJobTheOperatorsCannotSign(t *testing.T) {
	rng := rand.NewChaCha8([32]byte{76})
	config := setUpTestConfigWithRegtestNoAuthz(t)

	for _, tt := range unsignableSpendJobs(config, rng) {
		t.Run(tt.name, func(t *testing.T) {
			resp, err := NewStaticDepositHandler(config).claimInstantStaticDepositUtxoSwapConsensus(t.Context(), config, &pbssp.ClaimInstantStaticDepositUtxoSwapRequest{
				SpendTxSigningJob: tt.job,
			}, nil)

			require.Nil(t, resp)
			require.ErrorContains(t, err, tt.expectedError)
		})
	}
}
