package handler

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"strconv"

	"github.com/btcsuite/btcd/wire"
	"github.com/lightsparkdev/spark/common"
	"github.com/lightsparkdev/spark/common/keys"
	pbfrost "github.com/lightsparkdev/spark/proto/frost"
	pb "github.com/lightsparkdev/spark/proto/spark"
	"github.com/lightsparkdev/spark/so"
	"github.com/lightsparkdev/spark/so/ent"
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

// validateStaticDepositSpendShare checks the service provider's share of the
// signature of its spend of utxo. The claim entry points call it before any
// operator prepares: the coordinator aggregates only after the participants
// prepared, and a participant cannot undo every prepared claim.
func validateStaticDepositSpendShare(ctx context.Context, config *so.Config, job *pb.UserSignedTxSigningJob, utxo *ent.Utxo) error {
	depositAddress, err := utxo.QueryDepositAddress().Only(ctx)
	if err != nil {
		return fmt.Errorf("unable to get utxo deposit address: %w", err)
	}
	signingKeyshare, err := depositAddress.QuerySigningKeyshare().Only(ctx)
	if err != nil {
		return fmt.Errorf("failed to get signing keyshare: %w", err)
	}
	verifyingKey := signingKeyshare.PublicKey.Add(depositAddress.OwnerSigningPubkey)
	spendTxSighash, _, err := GetTxSigningInfo(ctx, utxo, job.GetRawTx())
	if err != nil {
		return fmt.Errorf("failed to get spend tx sighash: %w", err)
	}

	frostConn, err := config.NewFrostGRPCConnection()
	if err != nil {
		return fmt.Errorf("unable to connect to the signer: %w", err)
	}
	defer frostConn.Close()
	_, err = pbfrost.NewFrostServiceClient(frostConn).ValidateSignatureShare(ctx, &pbfrost.ValidateSignatureShareRequest{
		Message:         spendTxSighash.Serialize(),
		SignatureShare:  job.GetUserSignature(),
		Role:            pbfrost.SigningRole_USER,
		VerifyingKey:    verifyingKey.Serialize(),
		PublicShare:     depositAddress.OwnerSigningPubkey.Serialize(),
		Commitments:     job.GetSigningCommitments().GetSigningCommitments(),
		UserCommitments: job.GetSigningNonceCommitment(),
	})
	if err != nil {
		return sparkerrors.FailedPreconditionBadSignature(fmt.Errorf("unable to validate spend_tx_signing_job.user_signature: %w", err))
	}
	return nil
}

// finishStaticDepositSpendSignature returns the signature of the service
// provider's spend of utxo: the operators' shares aggregated with the service
// provider's. It fails when the signed transaction does not spend utxo.
func finishStaticDepositSpendSignature(ctx context.Context, config *so.Config, job *pb.UserSignedTxSigningJob, signingResult *helper.SigningResult, verifyingKey keys.Public, userPublicKey keys.Public, utxo *ent.Utxo) ([]byte, error) {
	signatures, err := aggregateSspSignedJobs(ctx, config, []sspSignedJob{{
		userJob:       job,
		signingResult: signingResult,
		verifyingKey:  verifyingKey,
		userPublicKey: userPublicKey,
	}})
	if err != nil {
		return nil, err
	}
	signedTxBytes, err := common.UpdateTxWithSignature(job.GetRawTx(), 0, signatures[0])
	if err != nil {
		return nil, fmt.Errorf("unable to apply the spend tx signature: %w", err)
	}
	signedTx, err := common.TxFromRawTxBytes(signedTxBytes)
	if err != nil {
		return nil, fmt.Errorf("unable to parse the signed spend tx: %w", err)
	}
	if err := common.VerifySignatureSingleInput(signedTx, 0, wire.NewTxOut(int64(utxo.Amount), utxo.PkScript)); err != nil {
		return nil, sparkerrors.FailedPreconditionBadSignature(fmt.Errorf("unable to verify the spend tx signature: %w", err))
	}
	return signatures[0], nil
}
