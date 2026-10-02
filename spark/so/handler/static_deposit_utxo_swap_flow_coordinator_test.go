package handler

import (
	"io"
	"maps"
	"math/rand/v2"
	"slices"
	"testing"

	pb "github.com/lightsparkdev/spark/proto/spark"
	pbssp "github.com/lightsparkdev/spark/proto/spark_ssp_internal"
	"github.com/lightsparkdev/spark/so"
	"github.com/stretchr/testify/require"
)

type unsignableSpendJob struct {
	name          string
	job           *pb.UserSignedTxSigningJob
	expectedError string
}

// unsignableSpendJobs returns spend jobs the operators cannot finish a signature of.
func unsignableSpendJobs(config *so.Config, rng io.Reader) []unsignableSpendJob {
	operatorIDs := slices.Sorted(maps.Keys(config.SigningOperatorMap))
	job := func(operatorIDs ...string) *pb.UserSignedTxSigningJob {
		return sspSignedJobFor(&pb.SigningJob{SigningNonceCommitment: createTestSigningCommitment(rng)}, testOperatorCommitments(rng, operatorIDs...))
	}
	withoutShare := job(operatorIDs...)
	withoutShare.UserSignature = nil

	jobs := []unsignableSpendJob{
		{"no job", nil, "spend_tx_signing_job is required"},
		{"no signature share", withoutShare, "spend_tx_signing_job.user_signature is required"},
		{"no operator commitments", job(), "spend_tx_signing_job.signing_commitments is required"},
		{"an unknown operator", job(append(slices.Clone(operatorIDs), "unknown")...), "not found in signing operator map"},
	}
	if config.Threshold > 1 {
		jobs = append(jobs, unsignableSpendJob{"fewer operators than the threshold", job(operatorIDs[0]), "fewer than the threshold"})
	}
	return jobs
}

func TestInitiateStaticDepositUtxoSwapRejectsASpendJobTheOperatorsCannotSign(t *testing.T) {
	rng := rand.NewChaCha8([32]byte{75})
	config := setUpTestConfigWithRegtestNoAuthz(t)

	for _, tt := range unsignableSpendJobs(config, rng) {
		t.Run(tt.name, func(t *testing.T) {
			resp, err := NewStaticDepositHandler(config).initiateStaticDepositUtxoSwapConsensus(t.Context(), config, &pbssp.InitiateStaticDepositUtxoSwapRequest{
				Transfer:          &pb.StartTransferRequest{TransferPackage: &pb.TransferPackage{}},
				SpendTxSigningJob: tt.job,
			})

			require.Nil(t, resp)
			require.ErrorContains(t, err, tt.expectedError)
		})
	}
}
