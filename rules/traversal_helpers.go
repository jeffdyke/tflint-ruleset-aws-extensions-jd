package rules

import (
	"log"
	"strings"

	"github.com/hashicorp/hcl/v2"
	"github.com/terraform-linters/tflint-plugin-sdk/hclext"
)

func ExpressionAttributes(attrs *hclext.Attribute) (error, []hcl.TraverseAttr) {

	rt, rtd := hcl.RelTraversalForExpr(attrs.Expr)
	if rt != nil && rtd.HasErrors() {
		log.Printf("Failed to parse Expression into attributes %s, with result %s", rtd.Error(), rt)
		return rtd, []hcl.TraverseAttr{}
	} else {
		var res []hcl.TraverseAttr
		for _, t := range rt {
			res = append(res, t.(hcl.TraverseAttr))
		}
		return nil, res
	}

}

func ConcatName(lt []hcl.TraverseAttr, separator string) string {
	if separator == "" {
		separator = "."
	}
	var res []string
	for _, t := range lt {
		res = append(res, t.Name)
	}
	return strings.Join(res, separator)
}
