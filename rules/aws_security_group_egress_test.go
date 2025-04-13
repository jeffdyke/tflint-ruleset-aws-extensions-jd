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
			Name: "egress can not be empty",
			Content: `
resource "aws_security_group" "this" {
	egress {
	  cidr_blocks = ""
	}
}`,
			Expected: helper.Issues{
				{
					Rule:    NewAwsSecurityGroupEgressTypeRule(),
					Message: "egress can not be empty",
					Range: hcl.Range{
						Filename: "resource.tf",
						Start:    hcl.Pos{Line: 4, Column: 4},
						End:      hcl.Pos{Line: 4, Column: 20},
					},
				},
			},
		},
		{
			Name: "Do not share egress with common",
			Content: `
module {
			common = {
				public_cidr = "foo"
			}
}
resource "aws_security_group" "this" {
	egress {
	  cidr_blocks = module.common.public_cidr
	}
}`,
			Expected: helper.Issues{
				{
					Rule:    NewAwsSecurityGroupEgressTypeRule(),
					Message: "Do not share egress with common",
					Range: hcl.Range{
						Filename: "resource.tf",
						Start:    hcl.Pos{Line: 9, Column: 4},
						End:      hcl.Pos{Line: 9, Column: 43},
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
