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
	// This rule is an example to get a top-level resource attribute.
	resources, err := runner.GetResourceContent(r.resourceType, &hclext.BodySchema{
		Blocks: []hclext.BlockSchema{
			{Type: r.subResourceType},
		},
		Attributes: []hclext.AttributeSchema{
			{Name: r.attributeName},
		},
	}, nil)
	if err != nil {
		return err
	}

	for _, resource := range resources.Blocks {
		attribute, exists := resource.Body.Attributes[r.attributeName]
		if !exists {
			continue
		}

		err := runner.EvaluateExpr(attribute.Expr, func(cidr string) error {
			if cidr != "[0.0.0.0/0]" {
				runner.EmitIssue(
					r,
					fmt.Sprintf("\"%s\" is an invalid cidr block.", cidr),
					attribute.Expr.Range(),
				)
			}
			return nil
		}, nil)
		if err != nil {
			return err
		}
	}

	return nil

	// resources, err := runner.GetResourceContent(r.resourceType, &hclext.BodySchema{
	// 	Blocks: []hclext.BlockSchema{
	// 		{
	// 			Type: r.subResourceType,
	// 			Body: &hclext.BodySchema{
	// 				Attributes: []hclext.AttributeSchema{
	// 					{Name: r.attributeName},
	// 				},
	// 			},
	// 		},
	// 	},
	// }, nil)

	// if err != nil {
	// 	return err
	// }

	// for _, resource := range resources.Blocks {
	// 	for _, rule := range resource.Body.Blocks {
	// 		attribute, exists := rule.Body.Attributes["egress"]
	// 		if !exists {
	// 			continue
	// 		}

	// 		err := runner.EvaluateExpr(attribute.Expr, func(cidr string) error {
	// 			if cidr != "0.0.0.0/0" {
	// 				runner.EmitIssue(
	// 					r,
	// 					fmt.Sprintf("\"%s\" is an invalid cidr block.", cidr),
	// 					attribute.Expr.Range(),
	// 				)
	// 			}
	// 			return nil
	// 		}, nil)
	// 		if err != nil {
	// 			return err
	// 		}
	// 	}
	// }

	// return nil
}
