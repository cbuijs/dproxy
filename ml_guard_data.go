/*
File: ml_guard_data.go
Version: 1.0.0
Description: Contains static datasets for the ML Guard engine.
             Separated from ml_guard.go to reduce file size and improve readability.
*/

package main

// --- 1. Common Labels (Ignored during scoring to reduce false positives) ---
// These are "Safe Harbor" labels. If a token matches these, it contributes 0.0 to the "Bad" score.
var commonLabels = map[string]struct{}{
	// --- CDN & Edge Infrastructure ---
	"akadns": {}, "akamai": {}, "akamaiedge": {}, "akamaihd": {}, "akamaitechnologies": {},
	"akamaized": {}, "edgekey": {}, "edgesuite": {}, "tl88": {},
	"amazonaws": {}, "cloudfront": {}, "elb": {}, "s3": {}, "ec2": {},
	"cloudflare": {}, "cloudflare-dns": {}, "workers": {}, "cdn-cgi": {},
	"1e100": {}, "googleapis": {}, "googleusercontent": {}, "gstatic": {}, "appspot": {}, "ggpht": {},
	"azure": {}, "azureedge": {}, "azurewebsites": {}, "edgecast": {}, "azr": {},
	"trafficmanager": {}, "cloudapp": {}, "windows": {},
	"anycast": {}, "b-cdn": {}, "bunnycdn": {}, "cachefly": {}, "cdn-ovh": {},
	"cdn77": {}, "cdn77-ssl": {}, "fastly": {}, "fastlylb": {}, "gcdn": {},
	"gcore": {}, "hwcdn": {}, "stackpathcdn": {}, "keycdn": {}, "limelight": {},
	"netlify": {}, "vercel": {}, "herokuapp": {}, "firebase": {}, "firebaseapp": {},

	// --- Protocols, Infra & Network ---
	"api": {}, "apis": {}, "rest": {}, "graphql": {}, "rpc": {}, "soap": {},
	"connect": {}, "connectivitycheck": {}, "dns": {}, "host": {}, "hostname": {},
	"imap": {}, "ns": {}, "ns1": {}, "ns2": {}, "ns3": {}, "ns4": {},
	"ntp": {}, "pool": {}, "pop": {}, "pop3": {}, "smtp": {}, "mail": {}, "webmail": {},
	"remote": {}, "server": {}, "ssl": {}, "tls": {}, "vpn": {}, "www": {}, "www1": {},
	"gateway": {}, "gw": {}, "proxy": {}, "relay": {}, "node": {}, "cluster": {},
	"status": {}, "health": {}, "metrics": {}, "telemetry": {}, "monitor": {}, "log": {}, "logs": {},

	// --- Tech, Dev & Versions ---
	"app": {}, "apps": {}, "assets": {}, "cloud": {}, "dev": {}, "docs": {},
	"mobile": {}, "portal": {}, "secure": {}, "static": {}, "test": {},
	"web": {}, "staging": {}, "stage": {}, "prod": {}, "production": {}, "beta": {},
	"alpha": {}, "demo": {}, "sandbox": {}, "internal": {}, "intranet": {}, "corp": {},
	"v1": {}, "v2": {}, "v3": {}, "v4": {}, "v5": {}, "k8s": {}, "docker": {},

	// --- Auth, Identity & Security ---
	"account": {}, "accounts": {}, "auth": {}, "oauth": {}, "oauth2": {}, "sso": {},
	"saml": {}, "openid": {}, "identity": {}, "login": {}, "signin": {}, "signup": {},
	"register": {}, "verify": {}, "verification": {}, "challenge": {}, "captcha": {},
	"recaptcha": {}, "security": {}, "session": {}, "token": {}, "cookie": {},
	"cert": {}, "certificate": {}, "pki": {}, "key": {}, "keys": {},

	// --- Content, Media & Files ---
	"blog": {}, "chat": {}, "download": {}, "downloads": {}, "upload": {}, "uploads": {},
	"images": {}, "img": {}, "media": {}, "video": {}, "audio": {}, "stream": {},
	"hls": {}, "dash": {}, "live": {}, "vod": {}, "gallery": {}, "cdn": {}, "dist": {},
	"play": {}, "files": {}, "doc": {}, "manual": {}, "wiki": {}, "forum": {}, "support": {},

	// --- Business & Commerce ---
	"calendar": {}, "drive": {}, "keep": {}, "shop": {}, "store": {}, "cart": {},
	"checkout": {}, "pay": {}, "payment": {}, "billing": {}, "invoice": {},
	"marketing": {}, "sales": {}, "promo": {}, "offer": {}, "deal": {},

	// --- Apple / Microsoft Ecosystems ---
	"apple": {}, "icloud": {}, "itunes": {}, "mzstatic": {}, "aaplimg": {},
	"microsoft": {}, "windowsupdate": {}, "xbox": {}, "office": {}, "office365": {},
	"sharepoint": {}, "onedrive": {}, "skype": {}, "teams": {}, "outlook": {},
	"msn": {}, "bing": {}, "visualstudio": {}, "yammer": {},

	// --- Major Brands / Platforms ---
	"android": {}, "facebook": {}, "fbcdn": {}, "google": {}, "googlevideo": {},
	"instagram": {}, "linkedin": {}, "youtube": {}, "ytimg": {}, "whatsapp": {},
	"twitter": {}, "twimg": {}, "t": {}, "github": {}, "gitlab": {}, "bitbucket": {},
	"slack": {}, "zoom": {}, "salesforce": {}, "adobe": {}, "dropbox": {},
	"wordpress": {}, "shopify": {}, "stripe": {}, "paypal": {}, "amazon": {},
	"netflix": {}, "spotify": {}, "twitch": {}, "reddit": {}, "tumblr": {},
}

// --- 2. Safe TLDs (Excluded from dynamic frequency penalties) ---
// These TLDs are considered "generally safe" or "high reputation".
var safeTLDs = map[string]struct{}{
	// Tech & Startups (Often high entropy but legit)
	"io": {}, "ai": {}, "me": {}, "tv": {}, "cc": {}, "so": {},
	"app": {}, "dev": {}, "tech": {}, "net": {}, "org": {}, "com": {},
	"cloud": {}, "online": {}, "store": {}, "shop": {},

	// Infrastructure / Gov / Edu
	"arpa": {}, "edu": {}, "gov": {}, "int": {}, "mil": {},

	// Americas
	"us": {}, "ca": {}, "mx": {}, "br": {}, "ar": {}, "cl": {}, "co": {},

	// Europe
	"uk": {}, "de": {}, "fr": {}, "nl": {}, "eu": {}, "ch": {}, "se": {},
	"no": {}, "fi": {}, "dk": {}, "es": {}, "it": {}, "pt": {}, "gr": {},
	"pl": {}, "cz": {}, "at": {}, "be": {}, "ie": {}, "ru": {}, "ua": {}, "ro": {},

	// Asia / Pacific
	"jp": {}, "cn": {}, "tw": {}, "kr": {}, "in": {}, "sg": {}, "hk": {},
	"my": {}, "id": {}, "th": {}, "vn": {}, "ph": {}, "au": {}, "nz": {},
	"il": {}, "tr": {}, "ae": {}, "sa": {}, "za": {},
}

// --- 3. High Risk TLDs (Heavier penalties applied) ---
var highRiskTLDs = map[string]struct{}{
	// Generic / Spammy / Abused
	"accountant": {}, "bargains": {}, "best": {}, "bid": {}, "buzz": {}, "cam": {},
	"casa": {}, "cf": {}, "cfd": {}, "click": {}, "country": {}, "cricket": {},
	"cyou": {}, "date": {}, "download": {}, "faith": {}, "fun": {}, "ga": {},
	"gdn": {}, "gq": {}, "icu": {}, "kim": {}, "kred": {}, "lat": {}, "link": {},
	"loan": {}, "men": {}, "ml": {}, "mom": {}, "monster": {}, "mov": {}, "ooo": {},
	"party": {}, "pic": {}, "pics": {}, "pw": {}, "quest": {}, "racing": {},
	"rest": {}, "review": {}, "sbs": {}, "science": {}, "stream": {}, "surf": {},
	"tk": {}, "trade": {}, "uno": {}, "wang": {}, "win": {}, "work": {}, "xin": {},
	"zip": {},
}

// --- 4. High Risk Labels (Keywords indicative of abuse/warez/malware) ---
var highRiskLabels = map[string]struct{}{
	// Abuse / Malware / Hack
	"abuse": {}, "anon": {}, "anonymous": {}, "carding": {}, "crack": {}, "ddos": {},
	"exploit": {}, "hack": {}, "hacker": {}, "leak": {}, "malware": {}, "phish": {},
	"phishing": {}, "spam": {}, "spoof": {}, "stress": {}, "stresser": {}, "warez": {},
	"crypto": {}, "bitcoin": {}, "btc": {}, "eth": {}, "wallet": {}, // Context dependent, but risky in unknown domains

	// File Sharing / Torrent
	"1337x": {}, "bittorrent": {}, "eztv": {}, "fitgirl": {}, "fitgirl-repacks": {},
	"kickass": {}, "kickasstorrents": {}, "limetorrents": {}, "magnet": {}, "nyaa": {},
	"piratebay": {}, "rarbg": {}, "rutracker": {}, "skidrow": {}, "thepiratebay": {},
	"torrent": {}, "tracker": {}, "yify": {}, "yts": {},

	// Hosting / Bulletproof / Offshore
	"4chan": {}, "a2hosting": {}, "abelohost": {}, "aeza": {}, "alexhost": {},
	"amarutu": {}, "bits": {}, "botshield": {}, "bp-hosting": {}, "bulletproof": {},
	"cinfu": {}, "cockbox": {}, "colocrossing": {}, "datacamp": {}, "dmca-ignored": {},
	"ehostict": {}, "elude": {}, "flokinet": {}, "ginernet": {}, "host-palace": {},
	"hostcay": {}, "hostinger": {}, "hostkey": {}, "hostsailor": {}, "hostwinds": {},
	"interserver": {}, "ititch": {}, "koddos": {}, "layer-6": {}, "lyrahosting": {},
	"mivocloud": {}, "njal": {}, "njalla": {}, "offshore": {}, "orangehost": {},
	"panamaserver": {}, "privatealps": {}, "privatelayer": {}, "prohoster": {},
	"qhoster": {}, "serverion": {}, "shinjiru": {}, "si-hosting": {}, "singlehop": {},
	"underground": {}, "undernet": {}, "unmanaged": {}, "vsys": {}, "web-project": {},
	"zomro": {},
}

// NEW: Neutral Words (Dictionary words to explicitly ignore during training)
// These are common words that appear in blocklists but aren't inherently malicious.
// We add colors, numbers, and common verbs to prevent the model from learning them as "Bad".
var neutralWords = map[string]struct{}{
	// Action / State
	"best": {}, "chat": {}, "deal": {}, "free": {}, "live": {}, "login": {},
	"new": {}, "promo": {}, "search": {}, "secure": {}, "top": {}, "update": {},
	"verify": {}, "get": {}, "try": {}, "use": {}, "buy": {}, "sell": {},
	"find": {}, "click": {}, "join": {}, "visit": {}, "view": {}, "read": {},

	// Business / Commerce
	"account": {}, "service": {}, "services": {}, "shop": {}, "store": {},
	"support": {}, "group": {}, "team": {}, "member": {}, "client": {}, "customer": {},

	// Content / Media
	"blog": {}, "files": {}, "game": {}, "games": {}, "image": {}, "info": {},
	"music": {}, "news": {}, "video": {}, "page": {}, "site": {}, "home": {},

	// Tech / Infrastructure
	"app": {}, "cloud": {}, "com": {}, "hosting": {}, "link": {}, "mail": {},
	"mobile": {}, "net": {}, "online": {}, "org": {}, "portal": {}, "server": {},
	"web": {},

	// Colors / Numbers / Time
	"red": {}, "blue": {}, "green": {}, "black": {}, "white": {}, "orange": {},
	"yellow": {}, "purple": {}, "gold": {}, "silver": {},
	"one": {}, "two": {}, "three": {}, "first": {}, "second": {}, "today": {},
	"daily": {}, "weekly": {}, "monthly": {}, "year": {}, "now": {},
}

// --- 5. Top 500 Domains (Categorized & Sorted) ---
// Expanded to include major infrastructure that might generate dynamic subdomains.
func getTop500Domains() []string {
	return []string{
		// Infrastructure / Cloud / Tech
		"amazonaws.com", "azure.com", "google.com", "googleapis.com", "gstatic.com",
		"microsoft.com", "apple.com", "icloud.com", "cloudflare.com", "cloudfront.net",
		"akamaihd.net", "akamaized.net", "fastly.net", "github.com", "gitlab.com",
		"bitbucket.org", "heroku.com", "netlify.app", "vercel.app",

		// E-Commerce & Finance
		"amazon.com", "ebay.com", "paypal.com", "shopify.com", "stripe.com",
		"aliexpress.com", "booking.com", "airbnb.com",

		// Government / Health / International
		"cdc.gov", "europa.eu", "nih.gov", "who.int", "un.org", "nasa.gov",

		// Media & Entertainment
		"bbc.co.uk", "cnn.com", "fandom.com", "imdb.com", "medium.com",
		"netflix.com", "nytimes.com", "soundcloud.com", "spotify.com",
		"twitch.tv", "vimeo.com", "disneyplus.com", "hulu.com", "roblox.com",
		"steampowered.com",

		// Others
		"live.com", "weather.com", "office.com", "office365.com", "sharepoint.com",
		"salesforce.com", "zoom.us", "slack.com", "atlassian.net", "dropbox.com",
		"adobe.com",

		// Search & Information
		"bing.com", "quora.com", "wikipedia.org", "yahoo.com", "yandex.ru",
		"duckduckgo.com", "stackoverflow.com",

		// Social Media
		"facebook.com", "instagram.com", "linkedin.com", "pinterest.com",
		"reddit.com", "tiktok.com", "tumblr.com", "twitter.com", "whatsapp.com",
		"youtube.com", "snapchat.com", "discord.com", "telegram.org",
	}
}

