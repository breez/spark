package handler

import (
	"bytes"
	"context"
	"fmt"

	"github.com/google/uuid"
	pbspark "github.com/lightsparkdev/spark/proto/spark"
	pbssp "github.com/lightsparkdev/spark/proto/spark_ssp_internal"
	"github.com/lightsparkdev/spark/so"
	"github.com/lightsparkdev/spark/so/authz"
	"github.com/lightsparkdev/spark/so/ent"
	st "github.com/lightsparkdev/spark/so/ent/schema/schematype"
	entutxoswap "github.com/lightsparkdev/spark/so/ent/utxoswap"
	sparkerrors "github.com/lightsparkdev/spark/so/errors"
	"google.golang.org/protobuf/proto"
)

// replayInstantReservation answers a retry of a reservation this coordinator has
// committed, so a service provider that lost the reply learns which reservation it
// holds. It returns nil when this coordinator committed no reservation for the
// request's transfer id. Only the coordinator's own row is used: a participant
// keeps a prepared reservation until a rollback reaches it.
func replayInstantReservation(ctx context.Context, config *so.Config, req *pbssp.ReserveInstantStaticDepositUtxoSwapRequest) (*pbssp.ReserveInstantStaticDepositUtxoSwapResponse, error) {
	transferID, err := uuid.Parse(req.GetTransfer().GetTransferId())
	if err != nil {
		return nil, sparkerrors.InvalidArgumentMalformedField(fmt.Errorf("invalid transfer id: %w", err))
	}
	db, err := ent.GetDbFromContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get db: %w", err)
	}
	swap, err := db.UtxoSwap.Query().
		Where(
			entutxoswap.RequestedTransferIDEQ(transferID),
			entutxoswap.RequestTypeEQ(st.UtxoSwapRequestTypeInstant),
			entutxoswap.StatusIn(st.UtxoSwapStatusCreated, st.UtxoSwapStatusCompleted),
			entutxoswap.CoordinatorIdentityPublicKeyEQ(config.IdentityPublicKey()),
		).
		WithTransfer(func(q *ent.TransferQuery) {
			q.WithTransferSenders().WithTransferReceivers()
		}).
		Only(ctx)
	if ent.IsNotFound(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("unable to load instant reservation for transfer %s: %w", transferID, err)
	}
	if err := authz.EnforceSessionIdentityPublicKeyMatches(ctx, config, swap.SspIdentityPublicKey); err != nil {
		return nil, err
	}
	if !bytes.Equal(req.GetSspSignature(), swap.SspSignature) || !bytes.Equal(req.GetUserSignature(), swap.UserSignature) {
		return nil, sparkerrors.AlreadyExistsDuplicateOperation(fmt.Errorf("transfer %s already reserves a different instant static deposit", transferID))
	}
	transfer, err := swap.Edges.TransferOrErr()
	if err != nil {
		return nil, fmt.Errorf("instant reservation %s has no transfer: %w", swap.ID, err)
	}
	transferProto, err := transfer.MarshalProto(ctx)
	if err != nil {
		return nil, fmt.Errorf("unable to marshal transfer %s: %w", transfer.ID, err)
	}
	return &pbssp.ReserveInstantStaticDepositUtxoSwapResponse{
		Transfer:   transferProto,
		UtxoSwapId: swap.ID.String(),
	}, nil
}

// completedInstantClaimResponse rebuilds a completed claim's response from what the
// claim stored, without running consensus or changing anything.
func completedInstantClaimResponse(ctx context.Context, swap *ent.UtxoSwap) (*pbssp.ClaimInstantStaticDepositUtxoSwapResponse, error) {
	if len(swap.SpendTxSigningResult) == 0 {
		return nil, sparkerrors.FailedPreconditionInvalidState(fmt.Errorf("instant reservation %s is completed but has no stored spend tx signing result", swap.ID))
	}
	signingResult := &pbspark.SigningResult{}
	if err := proto.Unmarshal(swap.SpendTxSigningResult, signingResult); err != nil {
		return nil, fmt.Errorf("unable to unmarshal stored spend tx signing result: %w", err)
	}
	targetUtxo, err := swap.QueryUtxo().Only(ctx)
	if err != nil {
		return nil, fmt.Errorf("unable to load utxo for completed swap %s: %w", swap.ID, err)
	}
	depositAddress, err := targetUtxo.QueryDepositAddress().Only(ctx)
	if err != nil {
		return nil, fmt.Errorf("unable to get utxo deposit address: %w", err)
	}
	signingKeyshare, err := depositAddress.QuerySigningKeyshare().Only(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get signing keyshare: %w", err)
	}
	verifyingKey := signingKeyshare.PublicKey.Add(depositAddress.OwnerSigningPubkey)

	var transferProto *pbspark.Transfer
	secondaryTransfer, err := swap.QuerySecondaryTransfer().Only(ctx)
	switch {
	case err == nil:
		transferProto, err = secondaryTransfer.MarshalProto(ctx)
		if err != nil {
			return nil, fmt.Errorf("unable to marshal secondary transfer: %w", err)
		}
	case ent.IsNotFound(err):
	default:
		return nil, fmt.Errorf("unable to load secondary transfer: %w", err)
	}

	return &pbssp.ClaimInstantStaticDepositUtxoSwapResponse{
		SpendTxSigningResult: signingResult,
		Transfer:             transferProto,
		DepositAddress: &pbspark.DepositAddressQueryResult{
			DepositAddress:       depositAddress.Address,
			UserSigningPublicKey: depositAddress.OwnerSigningPubkey.Serialize(),
			VerifyingPublicKey:   verifyingKey.Serialize(),
			LeafId:               new(depositAddress.NodeID.String()),
		},
	}, nil
}
