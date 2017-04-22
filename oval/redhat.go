package oval

type redhat struct{}

func NewRedhat() redhat {
	return redhat{}
}

func (o redhat) FillCveInfoFromOvalDB() {

}
