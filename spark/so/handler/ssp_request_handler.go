package handler

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/lightsparkdev/spark/common/logging"
	pb "github.com/lightsparkdev/spark/proto/spark"
	pbinternal "github.com/lightsparkdev/spark/proto/spark_internal"
	pbssp "github.com/lightsparkdev/spark/proto/spark_ssp_internal"
	"github.com/lightsparkdev/spark/so"
	"github.com/lightsparkdev/spark/so/authz"
	"github.com/lightsparkdev/spark/so/ent"
	"github.com/lightsparkdev/spark/so/ent/preimagerequest"
	st "github.com/lightsparkdev/spark/so/ent/schema/schematype"
	enttransfer "github.com/lightsparkdev/spark/so/ent/transfer"
	sparkerrors "github.com/lightsparkdev/spark/so/errors"
	"github.com/lightsparkdev/spark/so/knobs"
	"github.com/lightsparkdev/spark/so/mimo"
)

// SspRequestHandler serves the calls a service provider makes on the operators.
type SspRequestHandler struct {
	config *so.Config
}

func NewSspRequestHandler(config *so.Config) *SspRequestHandler {
	return &SspRequestHandler{config: config}
}

func (h *SspRequestHandler) PrepareTreeAddress(ctx context.Context, req *pb.PrepareTreeAddressRequest) (*pb.PrepareTreeAddressResponse, error) {
	return NewTreeCreationHandler(h.config).PrepareTreeAddress(ctx, req)
}

func (h *SspRequestHandler) CreateTree(ctx context.Context, req *pb.CreateTreeRequest) (*pb.CreateTreeResponse, error) {
	return NewTreeCreationHandler(h.config).CreateTree(ctx, req)
}

// InitiateCounterTransfer starts the counter leg of a swap, linked to the user's
// primary transfer so the operators commit both legs' sender key tweaks together.
func (h *SspRequestHandler) InitiateCounterTransfer(ctx context.Context, req *pbssp.CounterTransferRequest) (*pb.StartTransferResponse, error) {
	if req == nil {
		return nil, sparkerrors.InvalidArgumentMissingField(fmt.Errorf("request is required"))
	}
	if req.GetTransfer() == nil {
		return nil, sparkerrors.InvalidArgumentMissingField(fmt.Errorf("transfer is required"))
	}
	if req.GetAdaptorPublicKeys() == nil {
		return nil, sparkerrors.InvalidArgumentMissingField(fmt.Errorf("adaptor_public_keys is required"))
	}
	parsed, err := parseSwapTransferRequest(req.GetTransfer(), req.GetAdaptorPublicKeys())
	if err != nil {
		return nil, err
	}
	primaryTransferID, err := uuid.Parse(req.GetPrimaryTransferId())
	if err != nil {
		return nil, sparkerrors.InvalidArgumentMalformedField(fmt.Errorf("invalid primary_transfer_id: %w", err))
	}
	transferHandler := NewTransferHandler(h.config)
	primaryTransfer, err := transferHandler.loadTransferNoUpdate(ctx, primaryTransferID)
	if err != nil {
		return nil, fmt.Errorf("unable to load primary transfer %s: %w", primaryTransferID, err)
	}
	primarySender, err := mimo.GetSingleTransferSender(primaryTransfer)
	if err != nil {
		return nil, err
	}
	if err := authz.EnforceWalletNotKillSwitched(ctx, primarySender); err != nil {
		return nil, err
	}

	if knobs.GetKnobsService(ctx).GetValue(knobs.KnobUseConsensusInitiateCounterTransfer, 0) > 0 {
		return initiateCounterTransferConsensus(ctx, h.config, &pbinternal.InitiateCounterTransferRequest{
			Transfer:          req.GetTransfer(),
			AdaptorPublicKeys: req.GetAdaptorPublicKeys(),
			PrimaryTransferId: req.GetPrimaryTransferId(),
		})
	}

	directAdaptorPublicKey, err := parsePublicKeyIfPresent(req.GetAdaptorPublicKeys().GetDirectAdaptorPublicKey())
	if err != nil {
		return nil, fmt.Errorf("unable to parse direct adaptor public key: %w", err)
	}
	directFromCpfpAdaptorPublicKey, err := parsePublicKeyIfPresent(req.GetAdaptorPublicKeys().GetDirectFromCpfpAdaptorPublicKey())
	if err != nil {
		return nil, fmt.Errorf("unable to parse direct from cpfp adaptor public key: %w", err)
	}
	response, err := transferHandler.StartCounterTransferInternal(ctx, req.GetTransfer(), TransferAdaptorPublicKeys{
		cpfpAdaptorPubKey:           parsed.adaptorPubKey,
		directAdaptorPubKey:         directAdaptorPublicKey,
		directFromCpfpAdaptorPubKey: directFromCpfpAdaptorPublicKey,
	}, primaryTransferID)
	if err != nil {
		return nil, fmt.Errorf("failed to start counter transfer for request %s: %w", logging.FormatProto("counter_transfer_request", req), err)
	}
	return response, nil
}

// ReturnStuckTransfer returns a preimage swap transfer paying the caller for a
// Lightning invoice to its sender before the transfer expires. Only the receiver
// can return it, and only while no preimage has been shared.
func (h *SspRequestHandler) ReturnStuckTransfer(ctx context.Context, req *pbssp.ReturnStuckTransferRequest) (*pbssp.ReturnStuckTransferResponse, error) {
	transferID, err := uuid.Parse(req.GetTransferId())
	if err != nil {
		return nil, sparkerrors.InvalidArgumentMalformedField(fmt.Errorf("invalid transfer_id: %w", err))
	}
	transferHandler := NewBaseTransferHandler(h.config)
	transfer, err := transferHandler.loadTransferForUpdate(ctx, transferID)
	if err != nil {
		return nil, fmt.Errorf("unable to load transfer %s: %w", transferID, err)
	}
	if transfer.Type != st.TransferTypePreimageSwap {
		return nil, sparkerrors.FailedPreconditionInvalidState(fmt.Errorf("transfer %s is a %s transfer, not a preimage swap", transferID, transfer.Type))
	}
	_, receiver, err := mimo.GetSingleTransferSenderReceiver(transfer)
	if err != nil {
		return nil, err
	}
	if err := authz.EnforceSessionIdentityPublicKeyMatches(ctx, h.config, receiver); err != nil {
		return nil, err
	}
	if transfer.Status == st.TransferStatusReturned {
		return &pbssp.ReturnStuckTransferResponse{}, nil
	}

	db, err := ent.GetDbFromContext(ctx)
	if err != nil {
		return nil, err
	}
	preimageRequest, err := db.PreimageRequest.Query().Where(preimagerequest.HasTransfersWith(enttransfer.ID(transfer.ID))).Only(ctx)
	if err != nil && !ent.IsNotFound(err) {
		return nil, fmt.Errorf("unable to fetch the preimage request of transfer %s: %w", transferID, err)
	}
	if preimageRequest != nil && preimageRequest.Status == st.PreimageRequestStatusPreimageShared {
		return nil, sparkerrors.FailedPreconditionInvalidState(fmt.Errorf("cannot return a transfer whose preimage has already been revealed"))
	}

	if err := transferHandler.executeCancelTransfer(ctx, transfer); err != nil {
		return nil, sparkerrors.FailedPreconditionInvalidState(fmt.Errorf("unable to return transfer %s: %w", transferID, err))
	}
	if err := transferHandler.CreateCancelTransferGossipMessage(ctx, transferID); err != nil {
		return nil, fmt.Errorf("unable to create and send gossip message: %w", err)
	}
	return &pbssp.ReturnStuckTransferResponse{}, nil
}
