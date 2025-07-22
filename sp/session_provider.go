package sp

import (
	"errors"
	"net"
	"net/http"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/samlsp"
)

type mySessionProvider struct {
	domain string
}

func (p *mySessionProvider) CreateSession(w http.ResponseWriter, r *http.Request, assertion *saml.Assertion) error {
	email := ""
	for _, attributeStatement := range assertion.AttributeStatements {
		for _, attribute := range attributeStatement.Attributes {
			if attribute.FriendlyName == "mail" {
				email = attribute.Values[0].Value
			}
		}
	}
	if email == "" {
		return errors.New("email not found")
	}
	user := GetUserByEmail(email)
	if user == nil {
		return errors.New("user not found")
	}
	host, _, _ := net.SplitHostPort(p.domain)
	http.SetCookie(w, &http.Cookie{
		Name:   TOKEN_HEADER_KEY,
		Domain: host,
		Value:  user.SignJWT(),
		Path:   "/",
	})
	return nil
}

func (*mySessionProvider) DeleteSession(w http.ResponseWriter, r *http.Request) error {
	return nil
}

func (*mySessionProvider) GetSession(r *http.Request) (samlsp.Session, error) {
	return "", nil
}
