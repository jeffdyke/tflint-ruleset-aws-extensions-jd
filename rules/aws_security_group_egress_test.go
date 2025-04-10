package rules

import (
	"fmt"
	"testing"

	hcl "github.com/hashicorp/hcl/v2"
	"github.com/terraform-linters/tflint-plugin-sdk/helper"
)

// t.Helper()
//
//	switch expected.(type) {
//	case string:
//	    if expected != actual {
//	        t.Errorf("Error:\nexpected: %s\nactual: %s", expected, actual)
//	    }
//	default:
//	    t.Errorf("Unsupported type")
//	}
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
			Name: "No variables for cidr",
			Content: `
resource "aws_security_group" "this" {
	egress {
	  cidr_blocks = ""
	}
}`,
			Expected: helper.Issues{
				{
					Rule:    NewAwsSecurityGroupEgressTypeRule(),
					Message: "\"cidr_blocks\" can't be empty",
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
			fmt.Printf("%s", test.Content)
			runner := helper.TestRunner(t, map[string]string{"resource.tf": test.Content})

			if err := rule.Check(runner); err != nil {
				t.Fatalf("Unexpected error occurred: %s", err)
			}

			helper.AssertIssues(t, test.Expected, runner.Issues)
		})
	}
}
