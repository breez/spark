package handler

import (
	"io"
	"math/rand/v2"
	"testing"

	"github.com/btcsuite/btcd/wire"
	"github.com/lightsparkdev/spark/common"
	"github.com/lightsparkdev/spark/common/keys"
	pbcommon "github.com/lightsparkdev/spark/proto/common"
	pb "github.com/lightsparkdev/spark/proto/spark"
	pbssp "github.com/lightsparkdev/spark/proto/spark_ssp_internal"
	"github.com/lightsparkdev/spark/so"
	"github.com/lightsparkdev/spark/so/db"
	"github.com/lightsparkdev/spark/so/ent"
	"github.com/lightsparkdev/spark/so/frost"
	"github.com/lightsparkdev/spark/so/helper"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func testOperatorCommitments(rng io.Reader, operatorIDs ...string) *pb.SigningCommitments {
	commitments := make(map[string]*pbcommon.SigningCommitment, len(operatorIDs))
	for _, operatorID := range operatorIDs {
		commitments[operatorID] = createTestSigningCommitment(rng)
	}
	return &pb.SigningCommitments{SigningCommitments: commitments}
}

func sspSignedJobFor(job *pb.SigningJob, operatorCommitments *pb.SigningCommitments) *pb.UserSignedTxSigningJob {
	if job == nil {
		return nil
	}
	return &pb.UserSignedTxSigningJob{
		SigningPublicKey:       job.GetSigningPublicKey(),
		RawTx:                  job.GetRawTx(),
		SigningNonceCommitment: job.GetSigningNonceCommitment(),
		UserSignature:          []byte{1},
		SigningCommitments:     operatorCommitments,
	}
}

// sspSignedCreationNode is node as the service provider sends it.
func sspSignedCreationNode(node *pb.CreationNode, operatorCommitments *pb.SigningCommitments) *pbssp.CreationNode {
	children := make([]*pbssp.CreationNode, len(node.GetChildren()))
	for i, child := range node.GetChildren() {
		children[i] = sspSignedCreationNode(child, operatorCommitments)
	}
	return &pbssp.CreationNode{
		NodeTxSigningJob:                 sspSignedJobFor(node.GetNodeTxSigningJob(), operatorCommitments),
		RefundTxSigningJob:               sspSignedJobFor(node.GetRefundTxSigningJob(), operatorCommitments),
		Children:                         children,
		DirectNodeTxSigningJob:           sspSignedJobFor(node.GetDirectNodeTxSigningJob(), operatorCommitments),
		DirectRefundTxSigningJob:         sspSignedJobFor(node.GetDirectRefundTxSigningJob(), operatorCommitments),
		DirectFromCpfpRefundTxSigningJob: sspSignedJobFor(node.GetDirectFromCpfpRefundTxSigningJob(), operatorCommitments),
	}
}

// requireJobsAligned checks that every job the operators would sign is the one
// the service provider signed at the same position. Every test job has its own
// nonce commitment.
func requireJobsAligned(t *testing.T, signingJobs []*helper.SigningJob, userJobs []*pb.UserSignedTxSigningJob) {
	t.Helper()

	require.Len(t, signingJobs, len(userJobs))
	for i, signingJob := range signingJobs {
		require.True(t, proto.Equal(userJobs[i].GetSigningNonceCommitment(), signingJob.UserCommitment.MarshalProto()), "job %d", i)
	}
}

func TestSplitSignedCreationTreeOrdersALeafsJobsLikePrepareSigningJobs(t *testing.T) {
	rng := rand.NewChaCha8([32]byte{71})
	ctx, _ := db.ConnectToTestPostgres(t)
	fixture := createTreeCreationRefundValidationFixture(t, ctx, rng)

	unsigned, userJobs, nodeJobs, err := splitSignedCreationTree(sspSignedCreationNode(fixture.req.GetNode(), testOperatorCommitments(rng, "1", "2")))
	require.NoError(t, err)
	require.True(t, proto.Equal(fixture.req.GetNode(), unsigned))
	require.Equal(t, []treeNodeJobs{{nodeTx: 0, directNodeTx: 1, refundTx: 2, directRefundTx: 3, directFromCpfpRefundTx: 4}}, nodeJobs)

	signingJobs, nodes, err := createTestHandler().prepareSigningJobs(ctx, fixture.req, true)
	require.NoError(t, err)
	require.Len(t, nodes, len(nodeJobs))
	requireJobsAligned(t, signingJobs, userJobs)
}

func TestSplitSignedCreationTreeOrdersASplitsJobsLikePrepareSigningJobs(t *testing.T) {
	rng := rand.NewChaCha8([32]byte{72})
	ctx, _ := db.ConnectToTestPostgres(t)
	dbTX, err := ent.GetDbFromContext(ctx)
	require.NoError(t, err)

	fixture := setUpTreeCreationPreparedSplit(t, ctx, dbTX, rng, 0x72)
	parentTxid := fixture.parentTx.TxHash()
	splitTx, splitRawTx := createTreeCreationSplitTx(t, wire.OutPoint{Hash: parentTxid, Index: 0}, fixture.leftOutput, fixture.rightOutput, common.EphemeralAnchorOutput())
	splitTxid := splitTx.TxHash()
	_, directSplitRawTx := createTreeCreationSplitTx(
		t,
		wire.OutPoint{Hash: parentTxid, Index: 0},
		feeAdjustedTreeCreationSplitOutput(fixture.leftOutput),
		feeAdjustedTreeCreationSplitOutput(fixture.rightOutput),
	)
	children := make([]*pb.CreationNode, 0, 2)
	for i, childFields := range []struct {
		output     *wire.TxOut
		userPubkey keys.Public
	}{
		{fixture.leftOutput, fixture.leftUserPubkey},
		{fixture.rightOutput, fixture.rightUserPubkey},
	} {
		_, childRawTx := createTreeCreationSplitTx(t, wire.OutPoint{Hash: splitTxid, Index: uint32(i)}, childFields.output, common.EphemeralAnchorOutput())
		children = append(children, &pb.CreationNode{
			NodeTxSigningJob: &pb.SigningJob{
				RawTx:                  childRawTx,
				SigningPublicKey:       childFields.userPubkey.Serialize(),
				SigningNonceCommitment: createTestSigningCommitment(rng),
			},
		})
	}
	req := fixture.createTreeRequest(rng, splitRawTx, directSplitRawTx, children)

	unsigned, userJobs, nodeJobs, err := splitSignedCreationTree(sspSignedCreationNode(req.GetNode(), testOperatorCommitments(rng, "1", "2")))
	require.NoError(t, err)
	require.True(t, proto.Equal(req.GetNode(), unsigned))
	require.Equal(t, []treeNodeJobs{
		{nodeTx: 0, directNodeTx: 1, refundTx: -1, directRefundTx: -1, directFromCpfpRefundTx: -1},
		{nodeTx: 2, directNodeTx: -1, refundTx: -1, directRefundTx: -1, directFromCpfpRefundTx: -1},
		{nodeTx: 3, directNodeTx: -1, refundTx: -1, directRefundTx: -1, directFromCpfpRefundTx: -1},
	}, nodeJobs)

	signingJobs, nodes, err := createTestHandler().prepareSigningJobs(ctx, req, false)
	require.NoError(t, err)
	require.Len(t, nodes, len(nodeJobs))
	requireJobsAligned(t, signingJobs, userJobs)
}

func TestSplitSignedCreationTreeLeavesADirectRefundWithoutItsPairUnsigned(t *testing.T) {
	rng := rand.NewChaCha8([32]byte{73})
	operatorCommitments := testOperatorCommitments(rng, "1", "2")
	job := func(rawTx byte) *pb.UserSignedTxSigningJob {
		return sspSignedJobFor(&pb.SigningJob{RawTx: []byte{rawTx}, SigningNonceCommitment: createTestSigningCommitment(rng)}, operatorCommitments)
	}

	unsigned, userJobs, nodeJobs, err := splitSignedCreationTree(&pbssp.CreationNode{
		NodeTxSigningJob:                 job(1),
		RefundTxSigningJob:               job(2),
		DirectFromCpfpRefundTxSigningJob: job(3),
	})
	require.NoError(t, err)
	require.Len(t, userJobs, 2)
	require.Equal(t, []treeNodeJobs{{nodeTx: 0, directNodeTx: -1, refundTx: 1, directRefundTx: -1, directFromCpfpRefundTx: -1}}, nodeJobs)
	require.Equal(t, []byte{3}, unsigned.GetDirectFromCpfpRefundTxSigningJob().GetRawTx())
}

func TestSplitSignedCreationTreeRejectsANodeWithoutANodeTransaction(t *testing.T) {
	_, _, _, err := splitSignedCreationTree(&pbssp.CreationNode{Children: []*pbssp.CreationNode{{}}})
	require.ErrorContains(t, err, "node_tx_signing_job is required")

	_, _, _, err = splitSignedCreationTree(nil)
	require.ErrorContains(t, err, "node is required")
}

func TestSspSigningCommitments(t *testing.T) {
	rng := rand.NewChaCha8([32]byte{74})
	validJob := func() *pb.UserSignedTxSigningJob {
		return sspSignedJobFor(&pb.SigningJob{SigningNonceCommitment: createTestSigningCommitment(rng)}, testOperatorCommitments(rng, "1", "2"))
	}

	commitments, err := sspSigningCommitments("job", validJob())
	require.NoError(t, err)
	require.Len(t, commitments, 2)

	tests := []struct {
		name          string
		mutate        func(job *pb.UserSignedTxSigningJob)
		expectedError string
	}{
		{"no nonce commitment", func(job *pb.UserSignedTxSigningJob) { job.SigningNonceCommitment = nil }, "job.signing_nonce_commitment is required"},
		{"no signature share", func(job *pb.UserSignedTxSigningJob) { job.UserSignature = nil }, "job.user_signature is required"},
		{"no operator commitments", func(job *pb.UserSignedTxSigningJob) { job.SigningCommitments = nil }, "job.signing_commitments is required"},
		{"malformed operator commitment", func(job *pb.UserSignedTxSigningJob) {
			job.SigningCommitments.SigningCommitments["1"] = &pbcommon.SigningCommitment{Hiding: []byte{1}, Binding: []byte{2}}
		}, "invalid job.signing_commitments[1]"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			job := validJob()
			tt.mutate(job)
			_, err := sspSigningCommitments("job", job)
			require.ErrorContains(t, err, tt.expectedError)
		})
	}
}

func TestValidateSigningOperators(t *testing.T) {
	config := &so.Config{
		SigningOperatorMap: map[string]*so.SigningOperator{"1": {}, "2": {}, "3": {}},
		Threshold:          2,
	}
	commitments := func(operatorIDs ...string) map[string]frost.SigningCommitment {
		result := make(map[string]frost.SigningCommitment, len(operatorIDs))
		for _, operatorID := range operatorIDs {
			result[operatorID] = frost.SigningCommitment{}
		}
		return result
	}

	require.NoError(t, validateSigningOperators(config, "job", commitments("1", "3")))
	require.ErrorContains(t, validateSigningOperators(config, "job", commitments("1")), "fewer than the threshold of 2")
	require.ErrorContains(t, validateSigningOperators(config, "job", commitments("1", "4")), "operator ID 4 not found")

	require.True(t, sameOperators(commitments("1", "2"), commitments("2", "1")))
	require.False(t, sameOperators(commitments("1", "2"), commitments("1", "3")))
	require.False(t, sameOperators(commitments("1", "2"), commitments("1")))
}
