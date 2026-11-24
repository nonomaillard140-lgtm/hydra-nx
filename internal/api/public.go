package api

import (
	"html/template"
	"io"
	"io/fs"
	"net/http"
	"strconv"
	"strings"
	"time"

	"hydra/web"
)

var publicTemplate = template.Must(template.New("public").Parse(`<!doctype html>
<html lang="fr"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{{.Title}} — HYDRA</title><style>
:root{color-scheme:dark;--bg:#050810;--panel:#0c1220;--line:#263019;--text:#edf0df;--muted:#aab19c;--accent:#ffee20}*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:16px/1.6 ui-monospace,SFMono-Regular,Consolas,monospace}header,main,footer{max-width:1180px;margin:auto;padding:24px}header{border-bottom:1px solid var(--line);display:flex;gap:24px;align-items:center;flex-wrap:wrap}strong.brand{color:var(--accent);letter-spacing:.18em}nav{display:flex;gap:16px;flex-wrap:wrap}a{color:var(--accent);text-underline-offset:4px}a:focus-visible{outline:2px solid var(--accent);outline-offset:4px}h1{font-size:clamp(1.7rem,4vw,3rem);line-height:1.15}h2{font-size:1rem;text-transform:uppercase;letter-spacing:.12em}p{max-width:72ch;color:var(--muted)}table{border-collapse:collapse;width:100%;font-size:.9rem}th,td{text-align:left;border-bottom:1px solid var(--line);padding:10px;vertical-align:top}th{color:var(--accent);text-transform:uppercase;font-size:.75rem;letter-spacing:.08em}.notice{border:1px solid var(--line);padding:16px;background:var(--panel)}code,.data{font-variant-numeric:tabular-nums}.wrap{overflow-x:auto}footer{color:var(--muted);border-top:1px solid var(--line);font-size:.85rem}form{display:flex;gap:12px;flex-wrap:wrap;margin:0 0 20px}input,select{background:var(--panel);color:var(--text);border:1px solid var(--line);padding:10px;min-height:44px;font:inherit}input:focus,select:focus{outline:2px solid var(--accent)}.button{display:inline-block;border:1px solid var(--accent);padding:8px 12px;min-height:44px}@media(max-width:600px){header,main,footer{padding:16px}th,td{padding:8px}.hide-mobile{display:none}}
</style></head><body><header><strong class="brand">HYDRA</strong><nav><a href="/">Accueil</a><a href="/lists">Téléchargements</a><a href="/pricing">Tarifs</a><a href="/status">Statut</a><a href="/legal">Mentions</a><a href="/login">Connexion</a></nav></header><main>{{.Body}}</main><footer>Analyse défensive sur actifs possédés ou explicitement autorisés. Preuves systématiquement rédigées.</footer></body></html>`))

type publicPage struct {
	Title string
	Body  template.HTML
}

func renderPublic(w http.ResponseWriter, title, body string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := publicTemplate.Execute(w, publicPage{Title: title, Body: template.HTML(body)}); err != nil {
		return
	}
}

func (s *Server) handleHome(w http.ResponseWriter, r *http.Request) {
	renderPublic(w, "Surface maîtrisée", `<h1>Voyez l'exposition.<br>Réparez avant l'incident.</h1><p>HYDRA inventorie les actifs que vous déclarez, détecte les configurations et codes sources exposés, puis conserve uniquement des preuves rédigées. Aucun secret n'est validé contre un service tiers.</p><p><a class="button" href="/login">Ouvrir la console</a> <a class="button" href="/lists">Listes publiques</a></p><h2>Chaîne de remédiation</h2><p>Inventaire autorisé → référence HTTP → détection différentielle → preuve rédigée → rotation et correction.</p>`)
}

func (s *Server) handlePricing(w http.ResponseWriter, r *http.Request) {
	plans, err := s.store.Plans(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, cleanMessage(err))
		return
	}
	var body strings.Builder
	body.WriteString(`<h1>Tarifs à durée</h1><p>Licences Ed25519 vérifiées hors ligne. Aucun essai gratuit. Le paiement est provisionné par l'opérateur après vérification.</p><div class="wrap"><table><thead><tr><th>Plan</th><th>Prix</th><th>Durée</th><th>Appareils</th><th>Crédits/jour</th></tr></thead><tbody>`)
	for _, plan := range plans {
		body.WriteString("<tr><td>" + template.HTMLEscapeString(plan.Name) + "</td><td>" + strconv.FormatInt(plan.PriceCents/100, 10) + " €</td><td>" + strconv.Itoa(plan.DurationHours) + " h</td><td>" + strconv.Itoa(plan.MaxDevices) + "</td><td>" + strconv.Itoa(plan.DailyCredits) + "</td></tr>")
	}
	body.WriteString(`</tbody></table></div><p>Les conditions de remboursement et la durée de grâce sont fixées par l'opérateur dans son contrat commercial.</p>`)
	renderPublic(w, "Tarifs", body.String())
}

func (s *Server) handleFAQ(w http.ResponseWriter, r *http.Request) {
	renderPublic(w, "FAQ", `<h1>Questions fréquentes</h1><h2>Quelles cibles sont acceptées ?</h2><p>Uniquement vos systèmes ou ceux pour lesquels vous détenez une autorisation écrite. La confirmation est obligatoire pour chaque liste et chaque scan.</p><h2>Les secrets sont-ils affichés ?</h2><p>Non. Leurs valeurs sont immédiatement remplacées par une mention rédigée. Seule une empreinte HMAC sert à la déduplication.</p><h2>Le service contourne-t-il les protections ?</h2><p>Non. Les variantes sont canoniques, les redirections restent sur la même cible, et les limitations 429/503 sont respectées.</p><h2>Comment déployer ?</h2><p>Le README fournit la procédure Debian 12, l'unité systemd, la sauvegarde et la restauration.</p>`)
}

func (s *Server) handleLegal(w http.ResponseWriter, r *http.Request) {
	renderPublic(w, "Mentions légales", `<h1>Mentions et conditions</h1><h2>Éditeur</h2><p>Le service est exploité en privé par son opérateur. Les coordonnées légales doivent être ajoutées par cet opérateur avant toute commercialisation publique.</p><h2>Usage autorisé</h2><p>L'abonné ne peut analyser que ses propres actifs ou ceux couverts par une autorisation écrite. L'accès peut être révoqué en cas de violation.</p><h2>Données</h2><p>Les preuves sont rédigées et les configurations sensibles sont chiffrées. Les journaux d'envoi sont purgés après 90 jours. L'opérateur doit documenter sa durée de conservation comptable et ses obligations locales.</p><h2>Remboursement</h2><p>Les conditions commerciales et la durée de grâce applicables sont celles affichées au moment de la souscription.</p>`)
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	renderPublic(w, "Statut", `<h1>Statut des services</h1><div class="notice"><span class="data">API&nbsp;: opérationnelle</span><br><span class="data">SQLite&nbsp;: embarqué</span><br><span class="data">File de scans&nbsp;: `+strconv.Itoa(s.scheduler.Depth())+`</span><br><span class="data">Démarrage&nbsp;: `+s.started.Format(time.RFC3339)+`</span></div><p>Cette page ne divulgue ni cible, ni erreur contenant une donnée sensible.</p>`)
}

func (s *Server) handlePublicHits(w http.ResponseWriter, r *http.Request) {
	if s.store.StringSetting(r.Context(), "public_hits", "false") != "true" {
		writeError(w, http.StatusNotFound, "canal public désactivé")
		return
	}
	hits, err := s.store.Hits(r.Context(), 0, "", "", "", 100)
	if err != nil {
		writeError(w, http.StatusInternalServerError, cleanMessage(err))
		return
	}
	var body strings.Builder
	body.WriteString(`<h1>Expositions publiques rédigées</h1><p>Canal volontairement activé par l'opérateur. Aucune valeur secrète n'est publiée.</p><div class="wrap"><table><thead><tr><th>Hôte</th><th>Type</th><th>Service</th><th>Preuve</th><th>Dernier passage</th></tr></thead><tbody>`)
	for _, hit := range hits {
		body.WriteString("<tr><td>" + template.HTMLEscapeString(hit.Host) + "</td><td>" + template.HTMLEscapeString(hit.Vuln) + "</td><td>" + template.HTMLEscapeString(hit.Service) + "</td><td>" + template.HTMLEscapeString(hit.SecretRedacted) + "</td><td>" + hit.LastSeen.Format(time.RFC3339) + "</td></tr>")
	}
	body.WriteString(`</tbody></table></div>`)
	renderPublic(w, "Expositions publiques", body.String())
}

func (s *Server) handlePublicLists(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	items, err := s.store.PublicLists(r.Context(), false, query.Get("kind"), query.Get("q"), query.Get("sort"))
	if err != nil {
		writeError(w, http.StatusInternalServerError, cleanMessage(err))
		return
	}
	var body strings.Builder
	body.WriteString(`<h1>Téléchargements</h1><p>Listes de cibles et chemins publiés par l'opérateur. SHA-256 vérifiable, téléchargement direct sans JavaScript.</p><form method="get" action="/lists"><input name="q" value="` + template.HTMLEscapeString(query.Get("q")) + `" placeholder="Recherche" aria-label="Recherche"><select name="kind" aria-label="Type"><option value="">Tous types</option><option>L7</option><option>L4</option><option>PATHS</option></select><select name="sort" aria-label="Tri"><option value="date">Date</option><option value="volume">Volume</option><option value="downloads">Téléchargements</option><option value="name">Nom</option></select><button class="button" type="submit">Filtrer</button></form><p><a href="/lists/manifest.json">manifest.json</a></p><div class="wrap"><table><thead><tr><th>Nom</th><th>Type</th><th>Lignes</th><th>Taille</th><th>SHA-256</th><th>Publication</th><th>Vues</th></tr></thead><tbody>`)
	for _, item := range items {
		body.WriteString(`<tr><td><a href="/lists/` + strconv.FormatInt(item.ID, 10) + `">` + template.HTMLEscapeString(item.Name) + `</a></td><td>` + item.Kind + `</td><td>` + strconv.Itoa(item.Lines) + `</td><td>` + strconv.FormatInt(item.SizeBytes, 10) + ` o</td><td class="hide-mobile"><code>` + item.SHA256[:16] + `…</code></td><td>` + item.PublishedAt.Format("2006-01-02") + `</td><td>` + strconv.FormatInt(item.Downloads, 10) + `</td></tr>`)
	}
	if len(items) == 0 {
		body.WriteString(`<tr><td colspan="7">Aucune liste publiée.</td></tr>`)
	}
	body.WriteString(`</tbody></table></div>`)
	renderPublic(w, "Téléchargements", body.String())
}

func (s *Server) handlePublicList(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, errInvalidID.Error())
		return
	}
	item, err := s.store.PublicListByID(r.Context(), id, false)
	if err != nil {
		writeError(w, http.StatusNotFound, cleanMessage(err))
		return
	}
	body := `<h1>` + template.HTMLEscapeString(item.Name) + `</h1><div class="notice"><p>Type: ` + item.Kind + `<br>Format: ` + item.Format + `<br>Lignes: ` + strconv.Itoa(item.Lines) + `<br>Taille: ` + strconv.FormatInt(item.SizeBytes, 10) + ` octets<br>Téléchargements: ` + strconv.FormatInt(item.Downloads, 10) + `</p><p>SHA-256<br><code>` + item.SHA256 + `</code></p><p><a class="button" href="/lists/` + strconv.FormatInt(id, 10) + `/raw">Télécharger</a></p></div>`
	renderPublic(w, item.Name, body)
}

func (s *Server) handlePublicListRaw(w http.ResponseWriter, r *http.Request) {
	if !s.limiter.allow("download:"+clientIP(r), 0.5, 5) {
		writeError(w, http.StatusTooManyRequests, "limite de téléchargement atteinte")
		return
	}
	id, err := pathID(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, errInvalidID.Error())
		return
	}
	item, err := s.store.PublicListByID(r.Context(), id, false)
	if err != nil {
		writeError(w, http.StatusNotFound, cleanMessage(err))
		return
	}
	if err := s.lists.Verify(item); err != nil {
		writeError(w, http.StatusInternalServerError, cleanMessage(err))
		return
	}
	file, err := s.lists.Open(item)
	if err != nil {
		writeError(w, http.StatusNotFound, cleanMessage(err))
		return
	}
	defer file.Close()
	if err := s.store.IncrementPublicListDownload(r.Context(), id); err != nil {
		writeError(w, http.StatusInternalServerError, cleanMessage(err))
		return
	}
	contentType := "text/plain; charset=utf-8"
	if item.Format == "csv" {
		contentType = "text/csv; charset=utf-8"
	}
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Content-Disposition", `attachment; filename="`+strings.ReplaceAll(item.Filename, `"`, "")+`"`)
	w.Header().Set("X-Content-SHA256", item.SHA256)
	http.ServeContent(w, r, item.Filename, item.PublishedAt, file)
}

func (s *Server) handleManifest(w http.ResponseWriter, r *http.Request) {
	manifest, err := s.lists.Manifest(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, cleanMessage(err))
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_, _ = w.Write(manifest)
}

func serveAsset(w http.ResponseWriter, r *http.Request, assets fs.FS, name string) {
	file, err := assets.Open(name)
	if err != nil {
		writeError(w, http.StatusNotFound, "ressource introuvable")
		return
	}
	defer file.Close()
	content, err := io.ReadAll(file)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "lecture impossible")
		return
	}
	switch {
	case strings.HasSuffix(name, ".js"):
		w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
	case strings.HasSuffix(name, ".webmanifest"):
		w.Header().Set("Content-Type", "application/manifest+json")
	case strings.HasSuffix(name, ".svg"):
		w.Header().Set("Content-Type", "image/svg+xml")
	}
	_, _ = w.Write(content)
}

func (s *Server) handleSPA(w http.ResponseWriter, r *http.Request) {
	assets, _ := fs.Sub(web.Assets, "dist")
	content, err := fs.ReadFile(assets, "index.html")
	if err != nil {
		writeError(w, http.StatusInternalServerError, "frontend embarqué absent")
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(content)
}
