package rules

import (
	"log"

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

// Check checks whether ...
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
	// got := []string{}

	// diag := resources.WalkAttributes(func(a *Attribute) &hcl.Diagnostics {

	// 	got = append(got, a.Name)
	// 	return nil
	// })
	type TraverseLocal struct {
		isTraverser struct{}
		Name        string
		SrcRange    string
	}

	// var l []TraverseLocal

	for _, block := range resources.Blocks {
		for _, attrs := range block.Body.Blocks.OfType("egress")[0].Body.Attributes {
			log.Printf("CIDR: %+v\n\n", attrs.Expr.Variables()[0])
			rt, d := hcl.RelTraversalForExpr(attrs.Expr)
			for _, t := range rt {
				root := t.(hcl.TraverseAttr)
				log.Printf("RT BITCH: %+v\n", root.Name)
			}

			log.Printf("Item: %+v\n", d)
			// for _, item := range attrs.Expr.Variables()[0] {
			// 	get, _ := item.TraversalStep(cty.Value{})
			// 	log.Printf("Item: %+v\n", get)
			// }

		}
	}
	// got := []string{}
	// diag := resources.WalkAttributes(func(a *Attribute) hcl.Diagnostics {
	// 	got = append(got, a.Name)
	// 	return nil
	// })
	// log.Printf("walked attrs %+v", got)
	// log.Printf("walked attrs %+v", diag)

	return nil
}
