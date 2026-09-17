package handler

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/lightsparkdev/spark/common/btcnetwork"
	pbssp "github.com/lightsparkdev/spark/proto/spark_ssp_internal"
	"github.com/lightsparkdev/spark/so/authz"
	"github.com/lightsparkdev/spark/so/ent"
	st "github.com/lightsparkdev/spark/so/ent/schema/schematype"
	entutxoswap "github.com/lightsparkdev/spark/so/ent/utxoswap"
	sparkerrors "github.com/lightsparkdev/spark/so/errors"
	"github.com/lightsparkdev/spark/so/knobs"
)

// ReserveInstantStaticDepositUtxoSwap credits the user against a static deposit
// that may not have confirmed yet, holding the reservation open for the claim.
func (h *SspRequestHandler) ReserveInstantStaticDepositUtxoSwap(ctx context.Context, req *pbssp.ReserveInstantStaticDepositUtxoSwapRequest) (*pbssp.ReserveInstantStaticDepositUtxoSwapResponse, error) {
	if req == nil {
		return nil, sparkerrors.InvalidArgumentMissingField(fmt.Errorf("request is required"))
	}
	if err := h.enforceSspSendsTransfer(ctx, req.GetTransfer().GetOwnerIdentityPublicKey()); err != nil {
		return nil, err
	}
	return NewStaticDepositHandler(h.config).reserveInstantStaticDepositUtxoSwapConsensus(ctx, h.config, req)
}

// ClaimInstantStaticDepositUtxoSwap completes a reservation once its deposit has
// confirmed: the operators co-sign the service provider's spend of the deposit and
// send any secondary credit.
func (h *SspRequestHandler) ClaimInstantStaticDepositUtxoSwap(ctx context.Context, req *pbssp.ClaimInstantStaticDepositUtxoSwapRequest) (*pbssp.ClaimInstantStaticDepositUtxoSwapResponse, error) {
	if req == nil {
		return nil, sparkerrors.InvalidArgumentMissingField(fmt.Errorf("request is required"))
	}
	swapID, err := uuid.Parse(req.GetUtxoSwapId())
	if err != nil {
		return nil, sparkerrors.InvalidArgumentMalformedField(fmt.Errorf("invalid utxo_swap_id: %w", err))
	}
	network, err := btcnetwork.FromProtoNetwork(req.GetOnChainUtxo().GetNetwork())
	if err != nil {
		return nil, err
	}
	knobService := knobs.GetKnobsService(ctx)
	if knobService == nil || knobService.GetValueTarget(knobs.KnobEnableInstantStaticDeposit, new(network.String()), 0) == 0 {
		return nil, sparkerrors.FailedPreconditionInvalidState(fmt.Errorf("instant static deposit is not enabled"))
	}
	db, err := ent.GetDbFromContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get db: %w", err)
	}
	// utxo_swap_id names the coordinator's own reservation row, and the request type
	// keeps it from resolving a row another swap flow created.
	swap, err := db.UtxoSwap.Query().
		Where(
			entutxoswap.IDEQ(swapID),
			entutxoswap.RequestTypeEQ(st.UtxoSwapRequestTypeInstant),
			entutxoswap.StatusEQ(st.UtxoSwapStatusCreated),
		).
		ForUpdate().
		Only(ctx)
	if ent.IsNotFound(err) {
		return nil, sparkerrors.NotFoundMissingEntity(fmt.Errorf("instant reservation %s not found", swapID))
	}
	if err != nil {
		return nil, fmt.Errorf("unable to load instant reservation %s: %w", swapID, err)
	}
	if err := authz.EnforceSessionIdentityPublicKeyMatches(ctx, h.config, swap.SspIdentityPublicKey); err != nil {
		return nil, err
	}
	if err := authz.EnforceWalletNotKillSwitched(ctx, swap.SspIdentityPublicKey); err != nil {
		return nil, err
	}

	hasSecondaryCredit := swap.SecondaryCreditAmountSats != nil && *swap.SecondaryCreditAmountSats > 0
	if hasSecondaryCredit != (req.GetTransfer() != nil) {
		return nil, sparkerrors.InvalidArgumentMalformedField(fmt.Errorf("a secondary transfer is required exactly when the reservation has a secondary credit"))
	}
	return NewStaticDepositHandler(h.config).claimInstantStaticDepositUtxoSwapConsensus(ctx, h.config, req, swap)
}
