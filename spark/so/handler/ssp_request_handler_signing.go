package handler

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"strconv"

	"github.com/lightsparkdev/spark/common/keys"
	pbfrost "github.com/lightsparkdev/spark/proto/frost"
	"github.com/lightsparkdev/spark/so"
	sparkerrors "github.com/lightsparkdev/spark/so/errors"
	"github.com/lightsparkdev/spark/so/frost"
	"github.com/lightsparkdev/spark/so/helper"
)

// sspSignedJob is a transaction the service provider signed before the operators
// did, with what the operators need to finish its signature.
type sspSignedJob struct {
	userJob       userSignedSigningJob
	signingResult *helper.SigningResult
	verifyingKey  keys.Public
	userPublicKey keys.Public
}

// sspSigningCommitments returns the operator commitments the service provider
// signed job against. field names the job in errors.
func sspSigningCommitments(field string, job userSignedSigningJob) (map[string]frost.SigningCommitment, error) {
	if job.GetSigningNonceCommitment() == nil {
		return nil, sparkerrors.InvalidArgumentMissingField(fmt.Errorf("%s.signing_nonce_commitment is required", field))
	}
	if err := (&frost.SigningCommitment{}).UnmarshalProto(job.GetSigningNonceCommitment()); err != nil {
		return nil, sparkerrors.InvalidArgumentMalformedField(fmt.Errorf("invalid %s.signing_nonce_commitment: %w", field, err))
	}
	if len(job.GetUserSignature()) == 0 {
		return nil, sparkerrors.InvalidArgumentMissingField(fmt.Errorf("%s.user_signature is required", field))
	}
	protoCommitments := job.GetSigningCommitments().GetSigningCommitments()
	if len(protoCommitments) == 0 {
		return nil, sparkerrors.InvalidArgumentMissingField(fmt.Errorf("%s.signing_commitments is required", field))
	}
	commitments := make(map[string]frost.SigningCommitment, len(protoCommitments))
	for operatorID, protoCommitment := range protoCommitments {
		commitment := frost.SigningCommitment{}
		if err := commitment.UnmarshalProto(protoCommitment); err != nil {
			return nil, sparkerrors.InvalidArgumentMalformedField(fmt.Errorf("invalid %s.signing_commitments[%s]: %w", field, operatorID, err))
		}
		if commitment.IsZero() {
			return nil, sparkerrors.InvalidArgumentMalformedField(fmt.Errorf("%s.signing_commitments[%s] is empty", field, operatorID))
		}
		commitments[operatorID] = commitment
	}
	return commitments, nil
}

// validateSigningOperators rejects a set of operators that cannot produce a
// signature, before any operator spends a nonce on it.
func validateSigningOperators(config *so.Config, field string, commitments map[string]frost.SigningCommitment) error {
	if _, err := helper.NewPreSelectedOperatorSelection(config, slices.Collect(maps.Keys(commitments))); err != nil {
		return sparkerrors.InvalidArgumentMalformedField(fmt.Errorf("invalid %s.signing_commitments: %w", field, err))
	}
	if uint64(len(commitments)) < config.Threshold {
		return sparkerrors.InvalidArgumentMalformedField(fmt.Errorf("%s.signing_commitments names %d operators, fewer than the threshold of %d", field, len(commitments), config.Threshold))
	}
	return nil
}

func sameOperators(a, b map[string]frost.SigningCommitment) bool {
	if len(a) != len(b) {
		return false
	}
	for operatorID := range a {
		if _, ok := b[operatorID]; !ok {
			return false
		}
	}
	return true
}

// aggregateSspSignedJobs returns the finished signature of every job, in order.
func aggregateSspSignedJobs(ctx context.Context, config *so.Config, jobs []sspSignedJob) ([][]byte, error) {
	frostConn, err := config.NewFrostGRPCConnection()
	if err != nil {
		return nil, fmt.Errorf("unable to connect to the signer: %w", err)
	}
	defer frostConn.Close()

	batch := newFrostAggregationBatch(config)
	for i, job := range jobs {
		if err := batch.addSigningResultJob(strconv.Itoa(i), job.signingResult, job.userJob, job.verifyingKey, job.userPublicKey, keys.Public{}); err != nil {
			return nil, err
		}
	}
	aggregated, err := batch.aggregate(ctx, pbfrost.NewFrostServiceClient(frostConn))
	if err != nil {
		return nil, fmt.Errorf("unable to aggregate signatures: %w", err)
	}
	signatures := make([][]byte, len(jobs))
	for i := range jobs {
		signatures[i] = aggregated[strconv.Itoa(i)]
	}
	return signatures, nil
}
