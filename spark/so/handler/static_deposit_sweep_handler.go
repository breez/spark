package handler

import (
	"context"
	"fmt"

	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightsparkdev/spark/common"
	"github.com/lightsparkdev/spark/common/btcnetwork"
	pbgossip "github.com/lightsparkdev/spark/proto/gossip"
	pb "github.com/lightsparkdev/spark/proto/spark"
	pbinternal "github.com/lightsparkdev/spark/proto/spark_internal"
	pbssp "github.com/lightsparkdev/spark/proto/spark_ssp_internal"
	"github.com/lightsparkdev/spark/so"
	"github.com/lightsparkdev/spark/so/authn"
	"github.com/lightsparkdev/spark/so/authz"
	"github.com/lightsparkdev/spark/so/consensus"
	sparkerrors "github.com/lightsparkdev/spark/so/errors"
	"github.com/lightsparkdev/spark/so/frost"
	"github.com/lightsparkdev/spark/so/helper"
)

// SignStaticDepositSweepTx co-signs every input of a transaction the SSP has
// built to sweep static deposit UTXOs it has already bought into its own wallet.
//
// Unlike per-claim spend signing, this signs whatever transaction the owning SSP
// presents, as many times as it asks. The eligibility check in resolveSweepInputs
// is the whole of what holds that line, and it runs on every operator: the signing
// goes through the 2PC engine, so a share is only ever produced by an SO that
// independently agrees the UTXO is the caller's to spend.
//
// This coordinator pass runs that check first so a caller holding stale inputs
// gets them named back and can rebuild, rather than burning a cluster-wide round
// trip on a sweep that was always going to abort.
//
// The SSP signs every input before this call, against operator commitments from
// get_signing_commitments. The operators sign with the nonces behind those
// commitments, and this handler finishes each signature with the SSP's share.
func (h *SspRequestHandler) SignStaticDepositSweepTx(ctx context.Context, req *pbssp.SignStaticDepositSweepTxRequest) (*pbssp.SignStaticDepositSweepTxResponse, error) {
	if req == nil {
		return nil, sparkerrors.InvalidArgumentMissingField(fmt.Errorf("request is required"))
	}
	network, err := btcnetwork.FromProtoNetwork(req.GetNetwork())
	if err != nil {
		return nil, sparkerrors.InvalidArgumentNetworkNotSupported(fmt.Errorf("invalid network: %w", err))
	}
	if len(req.GetInputs()) == 0 {
		return nil, sparkerrors.InvalidArgumentMissingField(fmt.Errorf("inputs are required"))
	}

	// The caller's identity is the sole authorization for spending someone else's
	// deposit address, so it comes from the session and not from anything the
	// request can assert.
	session, err := authn.GetSessionFromContext(ctx)
	if err != nil {
		return nil, err
	}
	sspIdentityPubKey := session.IdentityPublicKey()
	if err := authz.EnforceWalletNotKillSwitched(ctx, sspIdentityPubKey); err != nil {
		return nil, err
	}

	// Signing data the operators cannot finish a signature with is rejected here,
	// before an operator spends the nonce behind its commitment on it.
	inputs := make([]*pbinternal.StaticDepositSweepInput, 0, len(req.GetInputs()))
	signingData := make(map[uint32]*pb.InputSigningData, len(req.GetInputs()))
	commitments := make(map[uint32]map[string]frost.SigningCommitment, len(req.GetInputs()))
	var operators map[string]frost.SigningCommitment
	for i, in := range req.GetInputs() {
		if in == nil {
			return nil, sparkerrors.InvalidArgumentMissingField(fmt.Errorf("inputs[%d] is required", i))
		}
		field := fmt.Sprintf("inputs[%d].signing_data", i)
		if in.GetSigningData() == nil {
			return nil, sparkerrors.InvalidArgumentMissingField(fmt.Errorf("%s is required", field))
		}
		inputCommitments, err := sspSigningCommitments(field, in.GetSigningData())
		if err != nil {
			return nil, err
		}
		if operators == nil {
			if err := validateSigningOperators(h.config, field, inputCommitments); err != nil {
				return nil, err
			}
			operators = inputCommitments
		} else if !sameOperators(operators, inputCommitments) {
			return nil, sparkerrors.InvalidArgumentMalformedField(fmt.Errorf("every input must name the same operators"))
		}
		signingData[in.GetVin()] = in.GetSigningData()
		commitments[in.GetVin()] = inputCommitments
		inputs = append(inputs, &pbinternal.StaticDepositSweepInput{
			OnChainUtxo:           in.GetOnChainUtxo(),
			Vin:                   in.GetVin(),
			UserSigningCommitment: in.GetSigningData().GetSigningNonceCommitment(),
		})
	}

	prepared, refusals, err := PrepareSweep(ctx, network, req.GetRawTx(), inputs, sspIdentityPubKey, req.GetSspSignature())
	if err != nil {
		return nil, err
	}
	// A partially signed batch is useless, so refuse the whole set at once and let
	// the caller rebuild without the bad inputs.
	if len(refusals) > 0 {
		return &pbssp.SignStaticDepositSweepTxResponse{
			Result: &pbssp.SignStaticDepositSweepTxResponse_Ineligible{
				Ineligible: &pbssp.IneligibleSweepInputs{Inputs: ineligibleSweepInputProtos(refusals)},
			},
		}, nil
	}

	// Each operator's commitments, one per input, in the order of prepared.inputs
	// that buildStaticDepositSweepCoordinatorFlow pairs them with.
	round1 := make(map[string][]frost.SigningCommitment, len(operators))
	for _, in := range prepared.inputs {
		for operatorID, commitment := range commitments[in.vin] {
			round1[operatorID] = append(round1[operatorID], commitment)
		}
	}
	flow, err := buildStaticDepositSweepCoordinatorFlow(h.config, req.GetNetwork(), req.GetRawTx(), sspIdentityPubKey, req.GetSspSignature(), prepared, round1)
	if err != nil {
		return nil, fmt.Errorf("unable to build coordinator flow: %w", err)
	}
	engine, err := consensus.GetEngine(ctx)
	if err != nil {
		return nil, err
	}
	selection := helper.OperatorSelection{Option: helper.OperatorSelectionOptionAll}
	if _, err := engine.Execute(ctx, pbgossip.ConsensusOperationType_CONSENSUS_OPERATION_TYPE_STATIC_DEPOSIT_SWEEP, &selection, flow); err != nil {
		return nil, fmt.Errorf("consensus static deposit sweep failed: %w", err)
	}
	if len(flow.results) != len(prepared.inputs) {
		return nil, sparkerrors.InternalDataInconsistency(
			fmt.Errorf("static deposit sweep consensus produced %d of %d signing results", len(flow.results), len(prepared.inputs)),
		)
	}

	signatures, err := finishSweepSignatures(ctx, h.config, prepared, flow.results, signingData)
	if err != nil {
		return nil, err
	}
	return &pbssp.SignStaticDepositSweepTxResponse{
		Result: &pbssp.SignStaticDepositSweepTxResponse_Signed{
			Signed: &pbssp.SweptInputs{Signatures: signatures},
		},
	}, nil
}

// finishSweepSignatures returns the signature of every input: the operators'
// shares aggregated with the SSP's. It fails when the signed transaction does not
// spend the swept UTXOs.
func finishSweepSignatures(ctx context.Context, config *so.Config, prepared *preparedSweep, results []sweepSigningResult, signingData map[uint32]*pb.InputSigningData) ([]*pbssp.SweepInputSignature, error) {
	inputs := make(map[uint32]*sweepInput, len(prepared.inputs))
	prevOuts := make(map[wire.OutPoint]*wire.TxOut, len(prepared.inputs))
	for _, in := range prepared.inputs {
		inputs[in.vin] = in
		prevOuts[in.outpoint] = wire.NewTxOut(int64(in.utxo.Amount), in.utxo.PkScript)
	}

	jobs := make([]sspSignedJob, len(results))
	for i, result := range results {
		in, ok := inputs[result.Vin]
		if !ok {
			return nil, sparkerrors.InternalDataInconsistency(fmt.Errorf("signing result for unknown sweep input %d", result.Vin))
		}
		keyMaterial, err := sweepInputKeyMaterial(in)
		if err != nil {
			return nil, err
		}
		jobs[i] = sspSignedJob{
			userJob: signingData[result.Vin],
			signingResult: &helper.SigningResult{
				Message:         prepared.sighashes[in.jobID()],
				SignatureShares: result.SigningResult.GetSignatureShares(),
				PublicKeys:      result.SigningResult.GetPublicKeys(),
			},
			verifyingKey:  keyMaterial.verifyingKey,
			userPublicKey: in.utxo.Edges.DepositAddress.OwnerSigningPubkey,
		}
	}
	aggregated, err := aggregateSspSignedJobs(ctx, config, jobs)
	if err != nil {
		return nil, err
	}

	signedTx := prepared.tx.Copy()
	signatures := make([]*pbssp.SweepInputSignature, len(results))
	for i, result := range results {
		signedTx.TxIn[result.Vin].Witness = wire.TxWitness{aggregated[i]}
		signatures[i] = &pbssp.SweepInputSignature{Vin: result.Vin, Signature: aggregated[i]}
	}
	if err := common.VerifySignatureMultiInput(signedTx, txscript.NewMultiPrevOutFetcher(prevOuts)); err != nil {
		return nil, sparkerrors.FailedPreconditionBadSignature(fmt.Errorf("unable to verify the sweep tx signatures: %w", err))
	}
	return signatures, nil
}

func ineligibleSweepInputProtos(refusals []sweepRefusal) []*pbssp.IneligibleSweepInput {
	out := make([]*pbssp.IneligibleSweepInput, 0, len(refusals))
	for _, refusal := range refusals {
		out = append(out, &pbssp.IneligibleSweepInput{
			OnChainUtxo: refusal.utxo,
			Reason:      sweepIneligibleReasonProto(refusal.reason),
		})
	}
	return out
}

func sweepIneligibleReasonProto(reason sweepIneligibleReason) pbssp.SweepIneligibleReason {
	switch reason {
	case sweepUnknownUtxo:
		return pbssp.SweepIneligibleReason_SWEEP_INELIGIBLE_REASON_UNKNOWN_UTXO
	case sweepNoSwap:
		return pbssp.SweepIneligibleReason_SWEEP_INELIGIBLE_REASON_NO_SWAP
	case sweepSwapNotCompleted:
		return pbssp.SweepIneligibleReason_SWEEP_INELIGIBLE_REASON_SWAP_NOT_COMPLETED
	case sweepNotOwnedByCaller:
		return pbssp.SweepIneligibleReason_SWEEP_INELIGIBLE_REASON_NOT_OWNED_BY_CALLER
	case sweepRefundSwap:
		return pbssp.SweepIneligibleReason_SWEEP_INELIGIBLE_REASON_REFUND_SWAP
	default:
		return pbssp.SweepIneligibleReason_SWEEP_INELIGIBLE_REASON_UNSPECIFIED
	}
}
