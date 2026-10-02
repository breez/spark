package handler

import (
	"context"
	"fmt"

	"github.com/lightsparkdev/spark/common/keys"
	"github.com/lightsparkdev/spark/common/logging"
	pbcommon "github.com/lightsparkdev/spark/proto/common"
	pb "github.com/lightsparkdev/spark/proto/spark"
	pbssp "github.com/lightsparkdev/spark/proto/spark_ssp_internal"
	"github.com/lightsparkdev/spark/so/authz"
	sparkerrors "github.com/lightsparkdev/spark/so/errors"
	"github.com/lightsparkdev/spark/so/frost"
	"github.com/lightsparkdev/spark/so/helper"
	"go.uber.org/zap"
	"google.golang.org/grpc/status"
)

// treeNodeJobs holds, for one node, the position of each of its transactions in
// the list of signing jobs. A node without such a transaction has -1.
type treeNodeJobs struct {
	nodeTx                 int
	directNodeTx           int
	refundTx               int
	directRefundTx         int
	directFromCpfpRefundTx int
}

// CreateTree creates a tree from transactions the service provider has already
// signed and returns the finished nodes. It is TreeCreationHandler.CreateTree
// followed by the finalize step for a created tree, except that the operators
// sign with the nonces behind the commitments in the request.
func (h *SspRequestHandler) CreateTree(ctx context.Context, req *pbssp.CreateTreeRequest) (*pb.FinalizeNodeSignaturesResponse, error) {
	if req == nil {
		return nil, sparkerrors.InvalidArgumentMissingField(fmt.Errorf("request is required"))
	}
	userIDPubKey, err := keys.ParsePublicKey(req.GetUserIdentityPublicKey())
	if err != nil {
		return nil, fmt.Errorf("invalid identity public key: %w", err)
	}
	if err := authz.EnforceSessionIdentityPublicKeyMatches(ctx, h.config, userIDPubKey); err != nil {
		return nil, err
	}
	if err := authz.EnforceWalletNotKillSwitched(ctx, userIDPubKey); err != nil {
		return nil, err
	}

	unsignedNode, userJobs, nodeJobs, err := splitSignedCreationTree(req.GetNode())
	if err != nil {
		return nil, err
	}
	commitments := make([]map[string]frost.SigningCommitment, len(userJobs))
	for i, userJob := range userJobs {
		commitments[i], err = sspSigningCommitments("signing job", userJob)
		if err != nil {
			return nil, err
		}
		if !sameOperators(commitments[0], commitments[i]) {
			return nil, sparkerrors.InvalidArgumentMalformedField(fmt.Errorf("every signing job must name the same operators"))
		}
	}
	if err := validateSigningOperators(h.config, "signing job", commitments[0]); err != nil {
		return nil, err
	}

	treeReq := &pb.CreateTreeRequest{
		Node:                  unsignedNode,
		UserIdentityPublicKey: req.GetUserIdentityPublicKey(),
	}
	switch source := req.GetSource().(type) {
	case *pbssp.CreateTreeRequest_ParentNodeOutput:
		treeReq.Source = &pb.CreateTreeRequest_ParentNodeOutput{ParentNodeOutput: source.ParentNodeOutput}
	case *pbssp.CreateTreeRequest_OnChainUtxo:
		treeReq.Source = &pb.CreateTreeRequest_OnChainUtxo{OnChainUtxo: source.OnChainUtxo}
	}

	treeHandler := NewTreeCreationHandler(h.config)
	signingJobs, nodes, err := treeHandler.prepareSigningJobs(ctx, treeReq, false)
	if err != nil {
		return nil, err
	}
	if len(signingJobs) != len(userJobs) || len(nodes) != len(nodeJobs) {
		return nil, sparkerrors.InternalDataInconsistency(fmt.Errorf("prepared %d signing jobs for %d nodes, the request has %d for %d", len(signingJobs), len(nodes), len(userJobs), len(nodeJobs)))
	}

	jobs := make([]*helper.SigningJobWithPregeneratedNonce, len(signingJobs))
	for i, signingJob := range signingJobs {
		jobs[i] = &helper.SigningJobWithPregeneratedNonce{SigningJob: *signingJob, Round1Packages: commitments[i]}
	}
	signingResults, err := helper.SignFrostWithPregeneratedNonce(ctx, h.config, jobs)
	if err != nil {
		return nil, err
	}

	signedJobs := make([]sspSignedJob, len(signingResults))
	for i, signingResult := range signingResults {
		userPublicKey, err := keys.ParsePublicKey(userJobs[i].GetSigningPublicKey())
		if err != nil {
			return nil, fmt.Errorf("failed to parse signing public key: %w", err)
		}
		signedJobs[i] = sspSignedJob{
			userJob:       userJobs[i],
			signingResult: signingResult,
			verifyingKey:  *signingJobs[i].VerifyingKey,
			userPublicKey: userPublicKey,
		}
	}
	signatures, err := aggregateSspSignedJobs(ctx, h.config, signedJobs)
	if err != nil {
		return nil, err
	}
	signature := func(job int) []byte {
		if job < 0 {
			return nil
		}
		return signatures[job]
	}
	nodeSignatures := make([]*pb.NodeSignatures, len(nodes))
	for i, node := range nodes {
		nodeSignatures[i] = &pb.NodeSignatures{
			NodeId:                          node.ID.String(),
			NodeTxSignature:                 signature(nodeJobs[i].nodeTx),
			RefundTxSignature:               signature(nodeJobs[i].refundTx),
			DirectNodeTxSignature:           signature(nodeJobs[i].directNodeTx),
			DirectRefundTxSignature:         signature(nodeJobs[i].directRefundTx),
			DirectFromCpfpRefundTxSignature: signature(nodeJobs[i].directFromCpfpRefundTx),
		}
	}

	if err := treeHandler.updateParentNodeStatus(ctx, treeReq.GetParentNodeOutput()); err != nil {
		return nil, err
	}
	finalized, err := NewFinalizeSignatureHandler(h.config).FinalizeNodeSignaturesV2(ctx, &pb.FinalizeNodeSignaturesRequest{
		Intent:         pbcommon.SignatureIntent_CREATION,
		NodeSignatures: nodeSignatures,
	})
	if err != nil {
		// The finalize handler puts its request in the error, and with it the
		// finished signatures. The service provider must not get those for a tree
		// the coordinator rolls back, so it gets the error's code alone.
		logging.GetLoggerFromContext(ctx).Error("failed to finalize a tree the operators signed", zap.Error(err))
		code, _ := sparkerrors.CodeAndReasonFrom(err)
		return nil, status.Error(code, "failed to finalize the created tree")
	}
	return finalized, nil
}

// splitSignedCreationTree returns the tree without the service provider's
// signatures, the jobs the operators sign, and where each node's transactions
// sit among those jobs. Jobs and nodes are in the order prepareSigningJobs
// produces them.
func splitSignedCreationTree(root *pbssp.CreationNode) (*pb.CreationNode, []*pb.UserSignedTxSigningJob, []treeNodeJobs, error) {
	type element struct {
		signed   *pbssp.CreationNode
		unsigned *pb.CreationNode
	}
	if root == nil {
		return nil, nil, nil, sparkerrors.InvalidArgumentMissingField(fmt.Errorf("node is required"))
	}
	unsignedRoot := &pb.CreationNode{}
	queue := []element{{signed: root, unsigned: unsignedRoot}}

	var jobs []*pb.UserSignedTxSigningJob
	var nodes []treeNodeJobs
	addJob := func(job *pb.UserSignedTxSigningJob) int {
		jobs = append(jobs, job)
		return len(jobs) - 1
	}
	for len(queue) > 0 {
		signed, unsigned := queue[0].signed, queue[0].unsigned
		queue = queue[1:]
		if signed.GetNodeTxSigningJob() == nil {
			return nil, nil, nil, sparkerrors.InvalidArgumentMissingField(fmt.Errorf("node_tx_signing_job is required"))
		}
		unsigned.NodeTxSigningJob = unsignedSigningJob(signed.GetNodeTxSigningJob())
		unsigned.RefundTxSigningJob = unsignedSigningJob(signed.GetRefundTxSigningJob())
		unsigned.DirectNodeTxSigningJob = unsignedSigningJob(signed.GetDirectNodeTxSigningJob())
		unsigned.DirectRefundTxSigningJob = unsignedSigningJob(signed.GetDirectRefundTxSigningJob())
		unsigned.DirectFromCpfpRefundTxSigningJob = unsignedSigningJob(signed.GetDirectFromCpfpRefundTxSigningJob())

		node := treeNodeJobs{nodeTx: addJob(signed.GetNodeTxSigningJob()), directNodeTx: -1, refundTx: -1, directRefundTx: -1, directFromCpfpRefundTx: -1}
		if signed.GetDirectNodeTxSigningJob() != nil {
			node.directNodeTx = addJob(signed.GetDirectNodeTxSigningJob())
		}
		if signed.GetRefundTxSigningJob() != nil {
			node.refundTx = addJob(signed.GetRefundTxSigningJob())
			if signed.GetDirectRefundTxSigningJob() != nil && signed.GetDirectFromCpfpRefundTxSigningJob() != nil {
				node.directRefundTx = addJob(signed.GetDirectRefundTxSigningJob())
				node.directFromCpfpRefundTx = addJob(signed.GetDirectFromCpfpRefundTxSigningJob())
			}
		}
		nodes = append(nodes, node)

		unsigned.Children = make([]*pb.CreationNode, len(signed.GetChildren()))
		for i, child := range signed.GetChildren() {
			if child == nil {
				return nil, nil, nil, sparkerrors.InvalidArgumentMissingField(fmt.Errorf("children[%d] is required", i))
			}
			unsigned.Children[i] = &pb.CreationNode{}
			queue = append(queue, element{signed: child, unsigned: unsigned.GetChildren()[i]})
		}
	}
	return unsignedRoot, jobs, nodes, nil
}

func unsignedSigningJob(job *pb.UserSignedTxSigningJob) *pb.SigningJob {
	if job == nil {
		return nil
	}
	return &pb.SigningJob{
		SigningPublicKey:       job.GetSigningPublicKey(),
		RawTx:                  job.GetRawTx(),
		SigningNonceCommitment: job.GetSigningNonceCommitment(),
	}
}
