package sp

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/samlsp"
	"github.com/golang-jwt/jwt/v4"
	"github.com/spf13/cast"
	"golang.org/x/crypto/bcrypt"
)

var (
	key  crypto.PrivateKey
	cert *x509.Certificate
)

func init() {
	keyData, err := os.ReadFile("sp/sp.key")
	if err != nil {
		panic(err)
	}
	block, _ := pem.Decode(keyData)
	key, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		panic(err)
	}
	certData, err := os.ReadFile("sp/sp.cert")
	if err != nil {
		panic(err)
	}
	block, _ = pem.Decode(certData)
	cert, err = x509.ParseCertificate(block.Bytes)
	if err != nil {
		panic(err)
	}
}

type ServiceProvider struct {
	sp      *samlsp.Middleware
	baseUrl *url.URL
}

func NewSP(baseUrlStr, entityID string) (*ServiceProvider, error) {
	baseUrl, err := url.Parse(baseUrlStr)
	if err != nil {
		return nil, err
	}
	sp, err := samlsp.New(samlsp.Options{
		Key:         key.(*rsa.PrivateKey),
		Certificate: cert,
		URL:         *baseUrl,
		EntityID:    entityID,
		CookieName:  TOKEN_HEADER_KEY,
	})
	if err != nil {
		return nil, err
	}
	sp.Session = &mySessionProvider{domain: baseUrl.Host}
	return &ServiceProvider{sp: sp, baseUrl: baseUrl}, nil
}

func (sp *ServiceProvider) SetIdpMetadata(metadata *saml.EntityDescriptor) {
	sp.sp.ServiceProvider.IDPMetadata = metadata
}

func (sp *ServiceProvider) GetSPMetadata() *saml.EntityDescriptor {
	return sp.sp.ServiceProvider.Metadata()
}

func (*ServiceProvider) readBodyToJson(body io.ReadCloser) map[string]any {
	var data map[string]any
	json.NewDecoder(body).Decode(&data)
	return data
}

type SPUser struct {
	Name     string `json:"name"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

func (user *SPUser) SignJWT() string {
	tokenStr, _ := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"name":  user.Name,
		"email": user.Email,
	}).SignedString([]byte(JWT_KEY))
	return tokenStr
}

func GetUserByEmail(email string) *SPUser {
	passwordHash, _ := bcrypt.GenerateFromPassword([]byte("123456"), bcrypt.DefaultCost)
	users := []SPUser{
		{
			Name:     "PPG007",
			Email:    "1658292229@qq.com",
			Password: string(passwordHash),
		},
		{
			Name:     "User no sso",
			Email:    "user_no_sso@example.com",
			Password: string(passwordHash),
		},
	}
	for _, user := range users {
		if user.Email == email {
			return &user
		}
	}
	return nil
}

const (
	JWT_KEY           = "ssodemospkey"
	TOKEN_HEADER_KEY  = "X-Access-Token"
	EMAIL_CONTEXT_KEY = "X-Authorized-Email"
)

func responseJson(w http.ResponseWriter, data map[string]any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(data)
}

func (sp *ServiceProvider) parseJWT(r *http.Request) *jwt.Token {
	tokenStr := r.Header.Get(TOKEN_HEADER_KEY)
	if tokenStr == "" {
		cookie, err := r.Cookie(TOKEN_HEADER_KEY)
		if err != nil {
			return nil
		}
		tokenStr = cookie.Value
	}
	if tokenStr == "" {
		return nil
	}
	token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
		return []byte(JWT_KEY), nil
	})
	if err != nil || !token.Valid {
		return nil
	}
	return token
}

func (sp *ServiceProvider) login(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	params := sp.readBodyToJson(r.Body)
	email := cast.ToString(params["email"])
	password := cast.ToString(params["password"])
	user := GetUserByEmail(email)
	if bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password)) != nil {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	responseJson(w, map[string]any{
		"token": user.SignJWT(),
	})
}

func (sp *ServiceProvider) loginWithSSO(w http.ResponseWriter, r *http.Request) {
	if sp.parseJWT(r) != nil {
		w.Header().Set("Location", "/hello")
		w.WriteHeader(http.StatusFound)
		return
	}
	idpUrl := sp.sp.ServiceProvider.GetSSOBindingLocation(saml.HTTPRedirectBinding)
	req, err := sp.sp.ServiceProvider.MakeAuthenticationRequest(idpUrl, saml.HTTPRedirectBinding, saml.HTTPArtifactBinding)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	relayState, err := sp.sp.RequestTracker.TrackRequest(w, r, req.ID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	redirectUrl, err := req.Redirect(relayState, &sp.sp.ServiceProvider)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Location", redirectUrl.String())
	w.WriteHeader(http.StatusFound)
}

func (sp *ServiceProvider) authWrapper(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := sp.parseJWT(r)
		if token == nil {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		claim := token.Claims.(jwt.MapClaims)
		next.ServeHTTP(
			w,
			r.WithContext(context.WithValue(r.Context(), EMAIL_CONTEXT_KEY, claim["email"])),
		)
	})
}

func (sp *ServiceProvider) hello(w http.ResponseWriter, r *http.Request) {
	email := r.Context().Value(EMAIL_CONTEXT_KEY)
	responseJson(w, map[string]any{
		"email": email,
	})
}

func (sp *ServiceProvider) Start() {
	mux := http.NewServeMux()
	mux.Handle("POST /login", http.HandlerFunc(sp.login))
	mux.Handle("GET /loginWithSSO", http.HandlerFunc(sp.loginWithSSO))
	mux.Handle("/hello", sp.authWrapper(http.HandlerFunc(sp.hello)))
	mux.HandleFunc("/saml/acs", sp.sp.ServeACS)
	http.ListenAndServe(fmt.Sprintf(":%s", sp.baseUrl.Port()), mux)
}
