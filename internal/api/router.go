package api

import (
	"context"
	"io/fs"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	"hydra/web"
)

func contextWithUser(r *http.Request, user interface{}) context.Context {
	return context.WithValue(r.Context(), userContextKey, user)
}

func (s *Server) Router() http.Handler {
	router := chi.NewRouter()
	router.Use(middleware.Recoverer)
	router.Use(middleware.Compress(5, "application/json", "text/html", "text/plain", "text/css", "application/javascript"))
	router.Use(s.commonMiddleware)
	router.Get("/api/health", s.handleHealth)
	router.Get("/", s.handleHome)
	router.Get("/pricing", s.handlePricing)
	router.Get("/faq", s.handleFAQ)
	router.Get("/legal", s.handleLegal)
	router.Get("/status", s.handleStatus)
	router.Get("/hits", s.handlePublicHits)
	router.Get("/lists", s.handlePublicLists)
	router.Get("/lists/manifest.json", s.handleManifest)
	router.Get("/lists/{id}", s.handlePublicList)
	router.Get("/lists/{id}/raw", s.handlePublicListRaw)
	router.Post("/api/auth/login", s.handleLogin)
	router.Get("/api/auth/session", s.handleSession)
	router.Group(func(private chi.Router) {
		private.Use(s.requireAuth)
		private.Use(s.csrf)
		private.Post("/api/auth/logout", s.handleLogout)
		private.Get("/api/auth/me", s.handleMe)
		private.Post("/api/auth/password", s.handlePassword)
		private.Post("/api/auth/totp/setup", s.handleTOTPSetup)
		private.Post("/api/auth/totp/enable", s.handleTOTPEnable)
		private.Post("/api/auth/totp/disable", s.handleTOTPDisable)
		private.Get("/api/dashboard", s.handleDashboard)
		private.Get("/api/lists", s.handleLists)
		private.Post("/api/lists", s.handleCreateList)
		private.Delete("/api/lists/{id}", s.handleDeleteList)
		private.Get("/api/paths", s.handlePaths)
		private.Post("/api/paths", s.handleCreatePath)
		private.Delete("/api/paths/{id}", s.handleDeletePath)
		private.Get("/api/scans", s.handleScans)
		private.Post("/api/scans", s.handleStartScan)
		private.Get("/api/scans/{id}", s.handleScan)
		private.Get("/api/hits", s.handleHits)
		private.Get("/api/hits/export.csv", s.handleHitsExport)
		private.Post("/api/hits/{id}/send", s.handleHitSend)
		private.Get("/api/addons", s.handleAddons)
		private.Get("/api/notifications", s.handleNotifications)
		private.Post("/api/notifications", s.handleSaveNotification)
		private.Post("/api/notifications/test", s.handleTestNotification)
		private.Delete("/api/notifications/{id}", s.handleDeleteNotification)
		private.Post("/api/send/config", s.handleSendConfig)
		private.Post("/api/send/control", s.handleSendControl)
		private.Get("/api/send/history", s.handleSendHistory)
		private.Get("/api/license", s.handleLicense)
		private.Group(func(admin chi.Router) {
			admin.Use(s.requireAdmin)
			admin.Get("/api/admin/users", s.handleAdminUsers)
			admin.Post("/api/admin/users", s.handleAdminCreateUser)
			admin.Post("/api/admin/users/{id}/ban", s.handleAdminBan)
			admin.Get("/api/admin/plans", s.handleAdminPlans)
			admin.Put("/api/admin/plans/{id}", s.handleAdminUpdatePlan)
			admin.Post("/api/admin/licenses", s.handleAdminIssueLicense)
			admin.Post("/api/admin/licenses/{id}/revoke", s.handleAdminRevokeLicense)
			admin.Get("/api/admin/audit", s.handleAdminAudit)
			admin.Get("/api/admin/settings", s.handleAdminSettings)
			admin.Post("/api/admin/settings", s.handleAdminUpdateSettings)
			admin.Post("/api/admin/queue/clear", s.handleAdminClearQueue)
			admin.Get("/api/admin/impersonate", s.handleAdminImpersonate)
			admin.Post("/api/admin/public-lists", s.handleAdminPublishList)
			admin.Post("/api/admin/public-lists/{id}/hide", s.handleAdminHideList)
		})
	})
	assets, _ := fs.Sub(web.Assets, "dist")
	fileServer := http.FileServer(http.FS(assets))
	router.Handle("/assets/*", fileServer)
	router.Get("/manifest.webmanifest", func(w http.ResponseWriter, r *http.Request) { serveAsset(w, r, assets, "manifest.webmanifest") })
	router.Get("/sw.js", func(w http.ResponseWriter, r *http.Request) { serveAsset(w, r, assets, "sw.js") })
	router.Get("/icon.svg", func(w http.ResponseWriter, r *http.Request) { serveAsset(w, r, assets, "icon.svg") })
	router.Get("/login", s.handleSPA)
	router.Get("/app", s.handleSPA)
	router.Get("/app/*", s.handleSPA)
	return router
}
