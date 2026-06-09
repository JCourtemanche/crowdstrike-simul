# CrowdStrike Falcon Mock Server

Simule l'API CrowdStrike Falcon (`https://api.crowdstrike.com`) pour tester le **Content Pack CrowdStrike Falcon** Cortex XSIAM sans tenant CrowdStrike réel.

Basé sur [xsiam-simulator-template](https://github.com/JCourtemanche/xsiam-simulator-template). Utilise le package [xsiam-shared-personas](https://github.com/JCourtemanche/xsiam-shared-personas) pour des données cohérentes entre tous les simulateurs XSIAM.

---

## Démarrage rapide

```bash
cd simulator
pip install -r requirements.txt
python app.py
# Serveur démarré sur http://0.0.0.0:8080
```

## Configuration de l'intégration dans XSIAM

| Champ | Valeur |
|---|---|
| **Server URL** | `http://<mock-host>:8080` |
| **Client ID** | `mock-client-id` |
| **Secret** | `mock-client-secret` |

## Variables d'environnement

| Variable | Défaut | Description |
|---|---|---|
| `CLIENT_ID` | `mock-client-id` | Client ID OAuth2 accepté |
| `CLIENT_SECRET` | `mock-client-secret` | Secret OAuth2 accepté |
| `NUM_DEVICES` | `20` | Nombre d'endpoints générés |
| `NUM_ALERTS` | `50` | Nombre de détections générées |
| `NUM_IOCS` | `30` | Nombre d'IOCs personnalisés |
| `NUM_VULNERABILITIES` | `40` | Nombre de vulnérabilités Spotlight |
| `NUM_HOST_GROUPS` | `5` | Nombre de groupes d'hôtes |
| `PORT` | `8080` | Port du serveur |

## Authentification — OAuth2 Client Credentials

```bash
# Obtenir un token
curl -X POST http://localhost:8080/oauth2/token \
  -d "client_id=mock-client-id&client_secret=mock-client-secret"
# → { "access_token": "...", "token_type": "bearer", "expires_in": 1799 }

# Utiliser dans les requêtes suivantes
curl http://localhost:8080/devices/queries/devices/v1 \
  -H "Authorization: Bearer <token>"
```

## Endpoints implémentés

### Auth
| Méthode | Endpoint | Description |
|---|---|---|
| `POST` | `/oauth2/token` | Obtenir un token Bearer |

### Devices
| Méthode | Endpoint | Description |
|---|---|---|
| `GET` | `/devices/queries/devices/v1` | Requête IDs devices (FQL, pagination) |
| `POST` | `/devices/entities/devices/v2` | Détails devices par IDs |
| `GET` | `/devices/entities/online-state/v1` | État online des devices |
| `POST` | `/devices/entities/devices-actions/v2` | Containment / lift containment |
| `GET` | `/devices/combined/host-groups/v1` | Lister les groupes d'hôtes |
| `GET/POST/PATCH/DELETE` | `/devices/entities/host-groups/v1` | CRUD groupes d'hôtes |
| `GET` | `/devices/combined/host-group-members/v1` | Membres d'un groupe |
| `POST` | `/devices/entities/host-group-actions/v1` | Ajouter/retirer membres |

### Alertes / Détections
| Méthode | Endpoint | Description |
|---|---|---|
| `GET` | `/alerts/queries/alerts/v2` | Requête IDs alertes |
| `POST` | `/alerts/entities/alerts/v2` | Entités alertes par composite IDs |
| `PATCH` | `/alerts/entities/alerts/v3` | Résoudre / assigner / tagger |
| `GET` | `/detects/queries/iom/v2` | IDs misconfigurations Cloud |
| `GET` | `/detects/entities/iom/v2` | Entités misconfigurations Cloud |

### IOCs personnalisés
| Méthode | Endpoint | Description |
|---|---|---|
| `GET` | `/iocs/combined/indicator/v1` | Recherche IOCs (pagination curseur) |
| `GET/POST/PATCH/DELETE` | `/iocs/entities/indicators/v1` | CRUD IOCs |
| `GET` | `/indicators/queries/devices/v1` | Devices ayant exécuté un IOC |
| `GET` | `/indicators/aggregates/devices-count/v1` | Comptage devices par IOC |
| `GET` | `/indicators/queries/processes/v1` | Processus ayant exécuté un IOC |

### Spotlight (Gestion des vulnérabilités)
| Méthode | Endpoint | Description |
|---|---|---|
| `GET` | `/spotlight/combined/vulnerabilities/v1` | Recherche vulnérabilités (curseur) |

### Processus / Quarantaine / Cases / Exclusions / RTR
Voir la liste complète dans `simulator/routes/`.

## Format de réponse

Standard CrowdStrike API :

```json
{
  "meta": {
    "query_time": 0.001,
    "pagination": { "offset": 0, "limit": 100, "total": 500 },
    "trace_id": "uuid"
  },
  "resources": [...],
  "errors": []
}
```

Les endpoints avec pagination curseur (Spotlight, IOC combined) incluent `"after": "base64cursor"`.

## Champs des données générées

Les générateurs produisent tous les champs requis par le Content Pack :

- **Devices** : tous les champs de `SEARCH_DEVICE_VERBOSE_KEY_MAP` (device_id, hostname, local_ip, external_ip, platform_name, os_version, mac_address, first_seen, last_seen, status, groups, policies…)
- **Alertes** : tous les champs de `DETECTIONS_BASE_KEY_MAP` et `DETECTIONS_BEHAVIORS_KEY_MAP` (detection_id, max_severity, status, behaviors avec tactic/technique/sha256/md5/cmdline/filepath, device, hostinfo.domain…)
- **IOCs** : tous les champs de `IOC_KEY_MAP` (type, value, action, severity, policy, source, platforms, tags, created_on, created_by…)
- **Vulnérabilités** : CVE id/severity/base_score/published_date/vector, host_info, remediation
- **Host Groups** : tous les champs de `HOST_GROUP_HEADERS` (id, name, group_type, description, assignment_rule, created_by, created_timestamp…)

---

## Déploiement GCP Cloud Run

```bash
# Depuis la racine du repo
bash deploy-cloudrun.sh
```

Le script déploie automatiquement sur `europe-west1` dans le projet GCP actif (`gcloud config get-value project`).
Voir [DEPLOYMENT_GCP.md](DEPLOYMENT_GCP.md) pour le détail complet.

Pour personnaliser les credentials avant déploiement, modifier les variables dans `deploy-cloudrun.sh` :
```bash
# Ligne à modifier dans deploy-cloudrun.sh
--set-env-vars CLIENT_ID=<votre-id>,CLIENT_SECRET=<votre-secret>,DEBUG=False
```

## Structure du projet

```
simulator/
├── app.py                      # Flask app factory, blueprints, seed data
├── auth.py                     # OAuth2 Bearer token (émission + validation)
├── config.py                   # Configuration via variables d'environnement
├── helpers.py                  # Envelope CrowdStrike, pagination offset + curseur
├── store.py                    # Données seed en mémoire
├── requirements.txt
├── generators/
│   ├── base.py                 # Helpers partagés + imports personas Business Corp
│   └── crowdstrike.py          # Générateurs : devices, alertes, IOCs, vulns, etc.
└── routes/
    ├── oauth.py                # POST /oauth2/token
    ├── devices.py              # Devices + Host Groups
    ├── alerts.py               # Alertes/Détections + IOM Cloud
    ├── iocs.py                 # IOCs personnalisés
    ├── spotlight.py            # Vulnérabilités Spotlight
    ├── processes.py            # Processus
    ├── quarantine.py           # Quarantaine
    ├── cases.py                # Cases
    ├── exclusions.py           # Exclusions ML + IOA
    └── rtr.py                  # Real Time Response
deployment/
├── Dockerfile                  # python:3.11-slim + gunicorn
└── app.yaml                    # App Engine config
cloudbuild.yaml                 # GCP Cloud Build (service: crowdstrike-simul)
deploy-cloudrun.sh              # Script de déploiement one-command
```

## Personas partagés — Business Corp

Identiques dans tous les simulateurs XSIAM. Source : [xsiam-shared-personas](https://github.com/JCourtemanche/xsiam-shared-personas).

| Utilisateur | Email | Hostname | IP interne | OS |
|---|---|---|---|---|
| Alice Dupont | alice.dupont@business.org | BSNS-WIN-ALICE | 192.168.1.1 | Windows 10 Pro |
| Bob Martin | bob.martin@business.org | BSNS-MAC-BOB | 192.168.1.2 | macOS 13 Ventura |
| Charlie Durant | charlie.durant@business.org | BSNS-WIN-CHARLIE | 192.168.1.3 | Windows 11 Pro |
| David Lefebvre | david.lefebvre@business.org | BSNS-WIN-DAVID | 192.168.1.4 | Windows 10 Pro |
| Emma Leroy | emma.leroy@business.org | BSNS-MAC-EMMA | 192.168.1.5 | macOS 14 Sonoma |
| Flora Moreau | flora.moreau@business.org | BSNS-MOB-FLORA | 192.168.1.6 | iOS 17 |

## Autres simulateurs XSIAM

| Projet | API simulée |
|---|---|
| [proofpoint-tap-simulator](https://github.com/JCourtemanche/proofpoint-tap-simulator) | ProofPoint TAP |
| [sentinelone-simul](https://github.com/JCourtemanche/sentinelone-simul) | SentinelOne |
| [cato-networks-simul](https://github.com/JCourtemanche/cato-networks-simul) | Cato Networks |
