package models

type ScopeOut struct {
	Id          string `json:"id"`
	Value       string `json:"value"`
	Description string `json:"description"`
}

type Scope struct {
	Id          string
	Value       string
	Description string
}

func (scope Scope) ToOutput() ScopeOut {
	return ScopeOut{}
}

type ScopeIn struct {
	Value       string `json:"value"`
	Description string `json:"description"`
}

func (scope ScopeIn) ToInternal() Scope {
	return Scope{}
}
