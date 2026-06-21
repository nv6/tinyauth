package controller

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/tinyauthapp/tinyauth/internal/model"
	"github.com/tinyauthapp/tinyauth/internal/repository"
	"github.com/tinyauthapp/tinyauth/internal/service"
	"github.com/tinyauthapp/tinyauth/internal/utils"
	"github.com/tinyauthapp/tinyauth/internal/utils/logger"
	"github.com/weppos/publicsuffix-go/publicsuffix"
	"go.uber.org/dig"

	"github.com/gin-gonic/gin"
	"github.com/google/go-querystring/query"
)

type OAuthRequest struct {
	Provider string `uri:"provider" binding:"required"`
}

type OAuthController struct {
	log     *logger.Logger
	config  *model.Config
	runtime *model.RuntimeConfig
	auth    *service.AuthService
}

type OAuthControllerInput struct {
	dig.In

	Log           *logger.Logger
	Config        *model.Config
	RuntimeConfig *model.RuntimeConfig
	RouterGroup   *gin.RouterGroup `name:"apiRouterGroup"`
	AuthService   *service.AuthService
}

func NewOAuthController(i OAuthControllerInput) *OAuthController {
	controller := &OAuthController{
		log:     i.Log,
		config:  i.Config,
		runtime: i.RuntimeConfig,
		auth:    i.AuthService,
	}

	oauthGroup := i.RouterGroup.Group("/oauth")
	oauthGroup.GET("/url/:provider", controller.oauthURLHandler)
	oauthGroup.GET("/callback/:provider", controller.oauthCallbackHandler)

	return controller
}

func (controller *OAuthController) oauthURLHandler(c *gin.Context) {
	var req OAuthRequest

	err := c.BindUri(&req)
	if err != nil {
		controller.log.App.Error().Err(err).Msg("Failed to bind URI")
		c.JSON(400, gin.H{
			"status":  400,
			"message": "Bad Request",
		})
		return
	}

	var reqParams service.OAuthCallbackParams

	err = c.BindQuery(&reqParams)

	if err != nil {
		controller.log.App.Error().Err(err).Msg("Failed to bind query parameters")
		c.JSON(400, gin.H{
			"status":  400,
			"message": "Bad Request",
		})
		return
	}

	if !controller.isOidcRequest(reqParams) {
		if !controller.isRedirectSafe(reqParams.RedirectURI) {
			controller.log.App.Warn().Str("redirectUri", reqParams.RedirectURI).Msg("Unsafe redirect URI, ignoring")
			reqParams.RedirectURI = ""
		}
	}

	sessionId, err := controller.auth.NewOAuthSession(req.Provider, reqParams)

	if err != nil {
		controller.log.App.Error().Err(err).Msg("Failed to create new OAuth session")
		c.JSON(500, gin.H{
			"status":  500,
			"message": "Internal Server Error",
		})
		return
	}

	authUrl, err := controller.auth.GetOAuthURL(sessionId)

	if err != nil {
		controller.log.App.Error().Err(err).Msg("Failed to get OAuth URL for session")
		c.JSON(500, gin.H{
			"status":  500,
			"message": "Internal Server Error",
		})
		return
	}

	cookieDomain, err := controller.helpers.GetCookieDomain(c, c.RemoteIP())

	if err != nil {
		controller.log.App.Error().Err(err).Msg("Failed to determine cookie domain")
		c.JSON(500, gin.H{
			"status":  500,
			"message": "Internal Server Error",
		})
		return
	}

	c.SetCookie(controller.runtime.OAuthSessionCookieName, sessionId, int(time.Hour.Seconds()), "/", cookieDomain, controller.config.Auth.SecureCookie, true)

	c.JSON(200, gin.H{
		"status":  200,
		"message": "OK",
		"url":     authUrl,
	})
}

func (controller *OAuthController) oauthCallbackHandler(c *gin.Context) {
	var req OAuthRequest

	err := c.BindUri(&req)
	if err != nil {
		controller.log.App.Error().Err(err).Msg("Failed to bind URI")
		c.JSON(400, gin.H{
			"status":  400,
			"message": "Bad Request",
		})
		return
	}

	sessionIdCookie, err := c.Cookie(controller.runtime.OAuthSessionCookieName)

	if err != nil {
		controller.log.App.Error().Err(err).Msg("Failed to get OAuth session cookie")
		c.Redirect(http.StatusTemporaryRedirect, fmt.Sprintf("%s/error", controller.runtime.AppURL))
		return
	}

	cookieDomain, err := controller.helpers.GetCookieDomain(c, c.RemoteIP())

	if err != nil {
		controller.log.App.Error().Err(err).Msg("Failed to determine cookie domain")
		c.Redirect(http.StatusTemporaryRedirect, fmt.Sprintf("%s/error", controller.runtime.AppURL))
		return
	}

	c.SetCookie(controller.runtime.OAuthSessionCookieName, "", -1, "/", cookieDomain, controller.config.Auth.SecureCookie, true)

	oauthPendingSession, err := controller.auth.GetOAuthPendingSession(sessionIdCookie)

	if err != nil {
		controller.log.App.Error().Err(err).Msg("Failed to get pending OAuth session")
		c.Redirect(http.StatusTemporaryRedirect, fmt.Sprintf("%s/error", controller.runtime.AppURL))
		return
	}

	defer controller.auth.EndOAuthSession(sessionIdCookie)

	state := c.Query("state")
	if state != oauthPendingSession.State {
		controller.log.App.Warn().Msg("OAuth state mismatch")
		c.Redirect(http.StatusTemporaryRedirect, fmt.Sprintf("%s/error", controller.runtime.AppURL))
		return
	}

	code := c.Query("code")
	_, err = controller.auth.GetOAuthToken(sessionIdCookie, code)

	if err != nil {
		controller.log.App.Error().Err(err).Msg("Failed to exchange code for token")
		c.Redirect(http.StatusTemporaryRedirect, fmt.Sprintf("%s/error", controller.runtime.AppURL))
		return
	}

	user, err := controller.auth.GetOAuthUserinfo(sessionIdCookie)

	if err != nil {
		controller.log.App.Error().Err(err).Msg("Failed to get user info from OAuth provider")
		c.Redirect(http.StatusTemporaryRedirect, fmt.Sprintf("%s/error", controller.runtime.AppURL))
		return
	}

	if user == nil {
		controller.log.App.Warn().Msg("OAuth provider did not return user info")
		c.Redirect(http.StatusTemporaryRedirect, fmt.Sprintf("%s/error", controller.runtime.AppURL))
		return
	}

	if user.Email == "" {
		controller.log.App.Warn().Msg("OAuth provider did not return an email")
		c.Redirect(http.StatusTemporaryRedirect, fmt.Sprintf("%s/error", controller.runtime.AppURL))
		return
	}

	svc, err := controller.auth.GetOAuthService(sessionIdCookie)

	if err != nil {
		controller.log.App.Error().Err(err).Msg("Failed to get OAuth service for session")
		c.Redirect(http.StatusTemporaryRedirect, fmt.Sprintf("%s/error", controller.runtime.AppURL))
		return
	}

	if svc.ID() != req.Provider {
		controller.log.App.Warn().Msgf("OAuth provider mismatch: expected %s, got %s", req.Provider, svc.ID())
		c.Redirect(http.StatusTemporaryRedirect, fmt.Sprintf("%s/error", controller.runtime.AppURL))
		return
	}

	if !controller.auth.IsEmailWhitelisted(svc.ID(), user.Email) {
		controller.log.App.Warn().Str("email", user.Email).Msg("Email not whitelisted, denying access")
		controller.log.AuditLoginFailure(user.Email, svc.ID(), c.ClientIP(), "email not whitelisted")

		queries, err := query.Values(UnauthorizedQuery{
			Username: user.Email,
		})

		if err != nil {
			controller.log.App.Error().Err(err).Msg("Failed to encode unauthorized query")
			c.Redirect(http.StatusTemporaryRedirect, fmt.Sprintf("%s/error", controller.runtime.AppURL))
			return
		}

		c.Redirect(http.StatusTemporaryRedirect, fmt.Sprintf("%s/unauthorized?%s", controller.runtime.AppURL, queries.Encode()))
		return
	}

	var name string

	if strings.TrimSpace(user.Name) != "" {
		controller.log.App.Debug().Msg("Using name from OAuth provider")
		name = user.Name
	} else {
		controller.log.App.Debug().Msg("No name from OAuth provider, generating from email")
		parts := strings.SplitN(user.Email, "@", 2)
		if len(parts) == 2 {
			name = fmt.Sprintf("%s (%s)", utils.Capitalize(parts[0]), parts[1])
		} else {
			name = utils.Capitalize(user.Email)
		}
	}

	var username string

	if strings.TrimSpace(user.PreferredUsername) != "" {
		controller.log.App.Debug().Msg("Using preferred username from OAuth provider")
		username = user.PreferredUsername
	} else {
		controller.log.App.Debug().Msg("No preferred username from OAuth provider, generating from email")
		username = strings.Replace(user.Email, "@", "_", 1)
	}

	sessionCookie := repository.Session{
		Username:    username,
		Name:        name,
		Email:       user.Email,
		Provider:    svc.ID(),
		OAuthGroups: utils.CoalesceToString(user.Groups),
		OAuthName:   svc.Name(),
		OAuthSub:    user.Sub,
	}

	controller.log.App.Debug().Msg("Creating session cookie for user")

	cookie, err := controller.auth.CreateSession(c, sessionCookie, c.RemoteIP())

	if err != nil {
		controller.log.App.Error().Err(err).Msg("Failed to create session cookie")
		c.Redirect(http.StatusTemporaryRedirect, fmt.Sprintf("%s/error", controller.runtime.AppURL))
		return
	}

	http.SetCookie(c.Writer, cookie)

	controller.log.AuditLoginSuccess(sessionCookie.Username, sessionCookie.Provider, c.ClientIP())

	if controller.isOidcRequest(oauthPendingSession.CallbackParams) {
		controller.log.App.Debug().Msg("OIDC request detected, redirecting to authorization endpoint with callback params")
		queries, err := query.Values(oauthPendingSession.CallbackParams)
		if err != nil {
			controller.log.App.Error().Err(err).Msg("Failed to encode OIDC callback query")
			c.Redirect(http.StatusTemporaryRedirect, fmt.Sprintf("%s/error", controller.runtime.AppURL))
			return
		}
		c.Redirect(http.StatusTemporaryRedirect, fmt.Sprintf("%s/oidc/authorize?%s", controller.runtime.AppURL, queries.Encode()))
		return
	}

	if oauthPendingSession.CallbackParams.RedirectURI != "" {
		queries, err := query.Values(RedirectQuery{
			RedirectURI: oauthPendingSession.CallbackParams.RedirectURI,
			LoginFor:    FrontendLoginForApp,
		})

		if err != nil {
			controller.log.App.Error().Err(err).Msg("Failed to encode redirect query")
			c.Redirect(http.StatusTemporaryRedirect, fmt.Sprintf("%s/error", controller.runtime.AppURL))
			return
		}

		c.Redirect(http.StatusTemporaryRedirect, fmt.Sprintf("%s/continue?%s", controller.runtime.AppURL, queries.Encode()))
		return
	}

	c.Redirect(http.StatusTemporaryRedirect, controller.runtime.AppURL)
}

func (controller *OAuthController) isOidcRequest(params service.OAuthCallbackParams) bool {
	return params.LoginFor == string(FrontendLoginForOIDC)
}

func (controller *OAuthController) getCookieDomain() string {
	if controller.config.Auth.SubdomainsEnabled {
		return "." + controller.runtime.CookieDomain
	}
	return controller.runtime.CookieDomain
}

func (controller *OAuthController) isRedirectSafe(redirectURI string) bool {
	u, err := url.Parse(redirectURI)

	if err != nil || u.Host == "" || u.Scheme == "" {
		return false
	}

	for _, allowed := range controller.runtime.TrustedDomains {
		tu, err := url.Parse(allowed)
		if err != nil {
			controller.log.App.Error().Err(err).Str("allowed", allowed).Msg("Failed to parse trusted domain")
			continue
		}

		if tu.Scheme != u.Scheme {
			continue
		}

		// exact match
		if strings.EqualFold(u.Host, tu.Host) {
			return true
		}

		// if subdomains are disabled, end here
		if !controller.config.Auth.SubdomainsEnabled {
			continue
		}

		// get the root domain (e.g. tinyauth.example.com -> example.com or
		// tinyauth.sub.example.com -> sub.example.com)
		_, root, ok := strings.Cut(tu.Host, ".")
		if !ok {
			continue
		}

		root = strings.ToLower(root)

		// check if the root domain is in the psl
		_, err = publicsuffix.DomainFromListWithOptions(publicsuffix.DefaultList, root, nil)

		if err != nil {
			continue
		}

		// subdomain match
		if strings.HasSuffix(strings.ToLower(u.Host), "."+root) {
			return true
		}
	}

	return false
}
