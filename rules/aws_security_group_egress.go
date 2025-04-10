package rules

import (
	"fmt"

	"github.com/terraform-linters/tflint-plugin-sdk/hclext"
	"github.com/terraform-linters/tflint-plugin-sdk/tflint"
	"github.com/terraform-linters/tflint-ruleset-terraform/project"
)

// AwsSecurityGroupEgressRule checks whether ...
type AwsSecurityGroupEgressRule struct {
	tflint.DefaultRule
	resourceType    string
	subResourceType string
	attributeName   string
}

// NewAwsSecurityGroupEgressRule returns a new rule
func NewAwsSecurityGroupEgressTypeRule() *AwsSecurityGroupEgressRule {
	return &AwsSecurityGroupEgressRule{
		resourceType:    "aws_security_group",
		subResourceType: "egress",
		attributeName:   "cidr_blocks",
	}
}

// Name returns the rule name
func (r *AwsSecurityGroupEgressRule) Name() string {
	return "aws_security_group_egress"
}

// Enabled returns whether the rule is enabled by default
func (r *AwsSecurityGroupEgressRule) Enabled() bool {
	return true
}

// Severity returns the rule severity
func (r *AwsSecurityGroupEgressRule) Severity() tflint.Severity {
	return tflint.ERROR
}

// Link returns the rule reference link
func (r *AwsSecurityGroupEgressRule) Link() string {
	return project.ReferenceLink(r.Name())
}

// Check checks whether ...
func (r *AwsSecurityGroupEgressRule) Check(runner tflint.Runner) error {

	resources, err := runner.GetResourceContent(r.resourceType, &hclext.BodySchema{
		Blocks: []hclext.BlockSchema{
			{
				Type: r.subResourceType,
				Body: &hclext.BodySchema{
					Attributes: []hclext.AttributeSchema{
						{Name: r.attributeName},
					},
				},
			},
		},
	}, nil)

	if err != nil {
		return err
	}
	fmt.Printf("\n RESOURCES: %+v\n\n", resources.Blocks)
	for _, resource := range resources.Blocks {
		fmt.Printf("Block: %+v\n\n", resource.Body)
		for _, block := range resource.Body.Blocks {
			fmt.Printf("\n.......Block: %+v\n\n", block.Body.Attributes[r.attributeName])
			value, ok := block.Body.Attributes[r.attributeName]
			if ok && value.Expr.Variables() != nil {
				fmt.Printf("Value %s\n\n\n", value.Expr.Variables())
			} else {
				runner.EmitIssue(
					r,
					fmt.Sprintf("\"%s\" can't be empty", r.attributeName),
					block.DefRange,
				)
			}

		}
	}

	return nil
}
