package idp

import (
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/url"
	"os"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/logger"
	"github.com/crewjam/saml/samlidp"
	"golang.org/x/crypto/bcrypt"
)

var (
	key  crypto.PrivateKey
	cert *x509.Certificate
)

func init() {
	keyData, err := os.ReadFile("idp/idp.key")
	if err != nil {
		panic(err)
	}
	block, _ := pem.Decode(keyData)
	key, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		panic(err)
	}
	certData, err := os.ReadFile("idp/idp.cert")
	if err != nil {
		panic(err)
	}
	block, _ = pem.Decode(certData)
	cert, err = x509.ParseCertificate(block.Bytes)
	if err != nil {
		panic(err)
	}
}

type IdentityProvider struct {
	idp     *samlidp.Server
	baseUrl *url.URL
	store   *samlidp.MemoryStore
}

func NewIdp(baseUrlStr string) (*IdentityProvider, error) {
	baseUrl, err := url.Parse(baseUrlStr)
	if err != nil {
		return nil, err
	}
	store := &samlidp.MemoryStore{}
	return &IdentityProvider{baseUrl: baseUrl, store: store}, err
}

func (idp *IdentityProvider) Start() error {
	idpServer, err := samlidp.New(samlidp.Options{
		URL:         *idp.baseUrl,
		Key:         key,
		Certificate: cert,
		Logger:      logger.DefaultLogger,
		Store:       idp.store,
	})
	if err != nil {
		return err
	}
	idp.idp = idpServer
	mux := http.NewServeMux()
	mux.HandleFunc("/sso", idp.idp.IDP.ServeSSO)
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}
		session := idp.idp.GetSession(w, r, &saml.IdpAuthnRequest{IDP: &idp.idp.IDP})
		if session == nil {
			return
		}
		// after get session, make assertion
		req, err := saml.NewIdpAuthnRequest(&idp.idp.IDP, r)
		if err != nil {
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}
		err = req.Validate()
		if err != nil {
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}
		maker := saml.DefaultAssertionMaker{}
		err = maker.MakeAssertion(req, session)
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		req.WriteResponse(w)
	})

	http.ListenAndServe(fmt.Sprintf(":%s", idp.baseUrl.Port()), mux)
	return nil
}

func (idp *IdentityProvider) CreateDefaultUser() {
	password := "123456"
	passwordHash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		panic(err)
	}
	idp.store.Put("/users/PPG007", samlidp.User{
		Name:           "PPG007",
		Groups:         []string{"admin"},
		Email:          "1658292229@qq.com",
		CommonName:     "PPG007",
		Surname:        "PPG007",
		GivenName:      "PPG007",
		HashedPassword: passwordHash,
	})
}

func (idp *IdentityProvider) AddSP(name string, metadata saml.EntityDescriptor) {
	idp.store.Put(fmt.Sprintf("/services/%s", name), samlidp.Service{
		Name:     name,
		Metadata: metadata,
	})
}

func (idp *IdentityProvider) GetMetadata() *saml.EntityDescriptor {
	return idp.idp.IDP.Metadata()
}
