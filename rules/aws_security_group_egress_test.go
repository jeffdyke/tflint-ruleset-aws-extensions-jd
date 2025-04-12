package rules

import (
	"testing"

	hcl "github.com/hashicorp/hcl/v2"
	"github.com/terraform-linters/tflint-plugin-sdk/helper"
)

func Test_AwsSecurityGroupEgress(t *testing.T) {
	tests := []struct {
		Name     string
		Content  string
		Expected helper.Issues
	}{
		{
			Name: "valid cidr",
			Content: `
resource "aws_security_group_rule" "this" {
	egress {
	  cidr_blocks = "0.0.0.0/0"
	}
}
`,
			Expected: helper.Issues{},
		},
		{
			Name: "Do not share egress with common",
			Content: `
locals {
			common = {
				public_cidr = "foo"
			}
}
resource "aws_security_group" "this" {
	egress {
	  cidr_blocks = local.common.public_cidr
	}
}`,
			Expected: helper.Issues{
				{
					Rule:    NewAwsSecurityGroupEgressTypeRule(),
					Message: "Do not share egress with common",
					Range: hcl.Range{
						Filename: "resource.tf",
						Start:    hcl.Pos{Line: 3, Column: 2},
						End:      hcl.Pos{Line: 3, Column: 8},
					},
				},
			},
		},
	}

	rule := NewAwsSecurityGroupEgressTypeRule()

	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			runner := helper.TestRunner(t, map[string]string{"resource.tf": test.Content})
			if err := rule.Check(runner); err != nil {
				t.Fatalf("Unexpected error occurred: %s", err)
			}
			helper.AssertIssues(t, test.Expected, runner.Issues)
		})
	}
}
