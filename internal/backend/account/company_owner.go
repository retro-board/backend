package account

type CompanyOwner struct {
	SprintLeader

	CreateCompany func(company *Company) error
	UpdateCompany func(company *Company) error
}
