package handler

import (
	"context"
	"fmt"

	"github.com/lightsparkdev/spark/common/keys"
	pbssp "github.com/lightsparkdev/spark/proto/spark_ssp_internal"
	"github.com/lightsparkdev/spark/so/authz"
	sparkerrors "github.com/lightsparkdev/spark/so/errors"
)

// InitiateStaticDepositUtxoSwap claims a static deposit as a fixed-amount swap: the
// service provider transfers the user the credit, and the operators co-sign its
// spend of the deposit.
func (h *SspRequestHandler) InitiateStaticDepositUtxoSwap(ctx context.Context, req *pbssp.InitiateStaticDepositUtxoSwapRequest) (*pbssp.InitiateStaticDepositUtxoSwapResponse, error) {
	if req == nil {
		return nil, sparkerrors.InvalidArgumentMissingField(fmt.Errorf("request is required"))
	}
	if err := h.enforceSspSendsTransfer(ctx, req.GetTransfer().GetOwnerIdentityPublicKey()); err != nil {
		return nil, err
	}
	return NewStaticDepositHandler(h.config).initiateStaticDepositUtxoSwapConsensus(ctx, h.config, req)
}

// enforceSspSendsTransfer binds a transfer the service provider sends to the
// session's identity.
func (h *SspRequestHandler) enforceSspSendsTransfer(ctx context.Context, ownerIdentityPublicKey []byte) error {
	sspIdentityPubKey, err := keys.ParsePublicKey(ownerIdentityPublicKey)
	if err != nil {
		return sparkerrors.InvalidArgumentMalformedKey(fmt.Errorf("invalid transfer owner identity public key: %w", err))
	}
	if err := authz.EnforceSessionIdentityPublicKeyMatches(ctx, h.config, sspIdentityPubKey); err != nil {
		return err
	}
	return authz.EnforceWalletNotKillSwitched(ctx, sspIdentityPubKey)
}
