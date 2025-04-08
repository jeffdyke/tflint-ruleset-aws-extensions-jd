package rules

import (
	"fmt"

	"github.com/terraform-linters/tflint-plugin-sdk/hclext"
	"github.com/terraform-linters/tflint-plugin-sdk/logger"
	"github.com/terraform-linters/tflint-plugin-sdk/tflint"
)

// AwsInstanceEgressRule checks whether ...
type AwsInstanceEgressRule struct {
	tflint.DefaultRule
}

// NewAwsInstanceEgressRule returns a new rule
func NewAwsInstanceEgressRule() *AwsInstanceEgressRule {
	return &AwsInstanceEgressRule{}
}

// Name returns the rule name
func (r *AwsInstanceEgressRule) Name() string {
	return "aws_extension_egress_no_shared_sg"
}

// Enabled returns whether the rule is enabled by default
func (r *AwsInstanceEgressRule) Enabled() bool {
	return true
}

// Severity returns the rule severity
func (r *AwsInstanceEgressRule) Severity() tflint.Severity {
	return tflint.ERROR
}

// Link returns the rule reference link
func (r *AwsInstanceEgressRule) Link() string {
	return ""
}

// Check checks whether ...
func (r *AwsInstanceEgressRule) Check(runner tflint.Runner) error {
	// This rule is an example to get a top-level resource attribute.
	resources, err := runner.GetResourceContent("aws_security_group", &hclext.BodySchema{
		Attributes: []hclext.AttributeSchema{
			{Name: "egress"},
		},
	}, nil)
	if err != nil {
		return err
	}

	// Put a log that can be output with `TFLINT_LOG=debug`
	logger.Debug(fmt.Sprintf("Get %d egress rules", len(resources.Blocks)))

	for _, resource := range resources.Blocks {
		attribute, exists := resource.Body.Attributes["cidr_blocks"]
		if !exists {
			continue
		}

		err := runner.EvaluateExpr(attribute.Expr, func(egressCidrBlock string) error {
			return runner.EmitIssue(
				r,
				fmt.Sprintf("egress.cidr_blocks is %s", egressCidrBlock),
				attribute.Expr.Range(),
			)
		}, nil)
		if err != nil {
			return err
		}
	}

	return nil
}
