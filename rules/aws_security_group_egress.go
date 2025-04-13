package rules

import (
	"strings"

	"github.com/hashicorp/hcl/v2"
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
func (r *AwsSecurityGroupEgressRule) ExpressionAttributes(attrs *hclext.Attribute) []hcl.TraverseAttr {
	var res []hcl.TraverseAttr
	rt, _ := hcl.RelTraversalForExpr(attrs.Expr)

	for _, t := range rt {
		res = append(res, t.(hcl.TraverseAttr))
	}
	return res
}
func (r *AwsSecurityGroupEgressRule) ConcatName(lt []hcl.TraverseAttr, separator string) string {
	if separator == "" {
		separator = "."
	}
	var res []string
	for _, t := range lt {
		res = append(res, t.Name)
	}
	return strings.Join(res, separator)
}
func (r *AwsSecurityGroupEgressRule) PathChecker(runner tflint.Runner, attrs *hclext.Attribute) error {
	// log.Printf("Path is %s", path)
	parsedAttrs := r.ExpressionAttributes(attrs)
	path := r.ConcatName(parsedAttrs, ".")
	if path == "" {
		runner.EmitIssue(
			r,
			"egress can not be empty",
			attrs.Range,
		)
	} else if strings.HasPrefix(path, "module.common") {
		runner.EmitIssue(
			r,
			"Do not share egress with common",
			attrs.Range,
		)
	}
	return nil
}

// Check evaluates the content of the egress value and applies rules
func (r *AwsSecurityGroupEgressRule) Check(runner tflint.Runner) error {
	// resourceFile := "resource.tf"

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

	for _, block := range resources.Blocks {
		for _, attrs := range block.Body.Blocks.OfType(r.subResourceType)[0].Body.Attributes {
			r.PathChecker(runner, attrs)
		}
	}
	return nil
}
