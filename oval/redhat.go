package oval

type redhatOvalClient struct{}

func NewRedhatOvalClient() redhatOvalClient {
	return redhatOvalClient{}
}

func (o redhatOvalClient) FillCveInfoFromOvalDB() {

}
