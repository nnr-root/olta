package models

import "github.com/s4l1hs/olta/pkg/campaign/personalizer"

func personalizerContext(context PhishingTemplateContext) personalizer.Context {
	return personalizer.Context{
		FirstName:   context.FirstName,
		LastName:    context.LastName,
		Position:    context.Position,
		Department:  context.Department,
		Role:        context.Role,
		Company:     context.Company,
		ManagerName: context.ManagerName,
		PhishingURL: context.PhishingURL,
	}
}
