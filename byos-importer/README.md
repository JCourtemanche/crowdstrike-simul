# CrowdStrike Falcon Spotlight → Cortex XSIAM Exposure Management (BYOS)

XSIAM Automation Script that imports CrowdStrike Falcon Spotlight vulnerabilities into **Cortex Exposure Management** through the [Bring Your Own Scanner (BYOS)](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSIAM-Platform-APIs/Bring-Your-Own-Scanner) API.

## Approche : XQL sur le dataset, pas d'appel à l'intégration CrowdStrike

Contrairement au [`CyberwatchBYOSImporter`](https://github.com/JCourtemanche/cyberwatch-simul/tree/main/byos-importer) qui appelle les commandes de l'intégration Cyberwatch (`cyberwatch-list-cves`, `cyberwatch-fetch-cve`) via `demisto.executeCommand`, ce script **lit directement les datasets XSIAM** que le pack CrowdStrike a déjà alimentés.

Trois raisons pour ce choix :

1. **Le dataset `crowdstrike_falcon_spotlight_vulnerabilities_raw` est déjà dénormalisé** — chaque ligne contient `host_info` (hostname, ipv4, os_version, platform, groups) *et* `cve` (id, description, base_score, severity, exprt_rating, cisa_info, actors...) *et* `remediation`. Tout ce dont BYOS a besoin, en une seule requête.
2. **Pas de dépendance à l'intégration CrowdStrike** — le script marche même si l'intégration est en rate-limit ou désactivée.
3. **Scalable** — XQL est fait pour manipuler des millions de lignes ; la pagination Falcon API a des limites strictes.

## Ce que fait le script

1. Lance une requête XQL :
   ```
   dataset = crowdstrike_falcon_spotlight_vulnerabilities_raw
   | fields aid, id, cve, host_info, remediation, apps, status, updated_timestamp
   | limit <xql_limit>
   ```
   avec optionnellement un `time_frame` (défaut 7 jours) et un `extra_xql_filter`.

2. Poll `get_query_results` jusqu'au statut `SUCCESS` ou `PARTIAL_SUCCESS`.

3. Parse les colonnes JSON (`cve`, `host_info`, `remediation`, `apps`) et **agrège par `aid`** (agent CrowdStrike = asset) — un asset porte N vulnérabilités.

4. `POST` en batches sur `/public_api/vulnerability-management/v1/external-scans/assets` avec `vendor="CrowdStrike"`, `product="Falcon Spotlight"`.

5. **Auto-poll** chaque `job_id` retourné jusqu'à un état terminal (`COMPLETED` / `COMPLETED_WITH_ERRORS` / `FAILED`) ou timeout.

6. **Mode standalone** : `poll_job_id=<id>` court-circuite le flow et vérifie l'état d'un job existant.

## Fichiers

| Fichier | Rôle |
|---|---|
| [`script-CrowdStrikeBYOSImporter.yml`](script-CrowdStrikeBYOSImporter.yml) | **Bundle à importer** dans XSIAM via *Settings → Configurations → Automations → Scripts → ⋮ → Import Script* |
| [`cs_byos_importer.py`](cs_byos_importer.py) | Source Python (à copier-coller si tu préfères créer le script manuellement) |
| [`examples/payload_example.json`](examples/payload_example.json) | Exemple concret du payload BYOS que le script génère |

## Arguments

| Argument | Requis | Défaut | Description |
|---|---|---|---|
| `api_url` | ✅ | — | URL API Cortex XSIAM (ex. `https://api-<tenant>.xdr.<region>.paloaltonetworks.com`) |
| `api_key` | ✅ | — | Valeur de la clé API Cortex |
| `api_key_id` | ✅ | — | ID de la clé (envoyé en header `x-xdr-auth-id`) |
| `time_frame` | — | `7 days` | Fenêtre temporelle XQL (`7 days`, `24 hours`, `1 week`...) |
| `dataset` | — | `crowdstrike_falcon_spotlight_vulnerabilities_raw` | Dataset source |
| `extra_xql_filter` | — | — | Filtre XQL supplémentaire (voir exemples ci-dessous) |
| `xql_limit` | — | `10000` | Max de lignes XQL par requête |
| `xql_timeout` | — | `120` | Timeout d'attente des résultats XQL (secondes) |
| `batch_size` | — | `100` | Nombre d'assets par POST BYOS |
| `dry_run` | — | `false` | Construit le payload sans POST |
| `verify` | — | `true` | Vérifier le certificat TLS Cortex |
| `poll_after_submit` | — | `true` | Auto-poll les job_id après submit |
| `poll_timeout` | — | `180` | Max secondes d'attente par job |
| `poll_interval` | — | `5` | Délai initial entre polls (backoff jusqu'à 30s) |
| `poll_job_id` | — | — | **Mode standalone** : reporter l'état d'un job existant |

## Install

**Recommandé : importer le YAML**
1. XSIAM → **Settings → Configurations → Automations → Scripts**
2. ⋮ → **Import Script**
3. Sélectionne [`script-CrowdStrikeBYOSImporter.yml`](script-CrowdStrikeBYOSImporter.yml)
4. Le script apparaît sous le nom `CrowdStrikeBYOSImporter` et est prêt à être exécuté

## Récupérer la clé API Cortex

1. XSIAM → **Settings → Configurations → API Keys → + New Key**
2. Rôle avec la permission `manage_vulnerabilities_action` (obligatoire pour BYOS)
3. Copie la valeur → argument `api_key`
4. Copie l'ID (entier) → argument `api_key_id`
5. L'URL du tenant est affichée en haut de la page

## Exemples d'usage

### Import basique (7 derniers jours, tout est envoyé)

```
!CrowdStrikeBYOSImporter api_url="https://api-mytenant.xdr.eu.paloaltonetworks.com" api_key_id=42 api_key="XXX"
```

### Dry-run — inspecter le payload sans POST

```
!CrowdStrikeBYOSImporter api_url="https://api-mytenant.xdr.eu.paloaltonetworks.com" api_key_id=42 api_key="XXX" dry_run=true xql_limit=50
```

### Filtrer sur les CVE critiques uniquement

```
!CrowdStrikeBYOSImporter api_url="..." api_key_id=42 api_key="XXX" extra_xql_filter="json_extract_scalar(cve, '$.severity') = 'CRITICAL'"
```

### Filtrer par host name

```
!CrowdStrikeBYOSImporter api_url="..." api_key_id=42 api_key="XXX" extra_xql_filter="json_extract_scalar(host_info, '$.hostname') contains 'BSNS-'"
```

### Ne pas polling après submit (fire-and-forget)

```
!CrowdStrikeBYOSImporter api_url="..." api_key_id=42 api_key="XXX" poll_after_submit=false
```

### Vérifier l'état d'un job précédent

```
!CrowdStrikeBYOSImporter api_url="..." api_key_id=42 api_key="XXX" poll_job_id="abcd-1234-..."
```

### Job récurrent (recommandé)

**Settings → Playbooks → Jobs → + New Job** :
- Nom : `CrowdStrike Falcon Spotlight → BYOS Sync`
- Type : **Recurring** toutes les 4 heures
- Playbook : appelle `CrowdStrikeBYOSImporter` avec `api_url`, `api_key`, `api_key_id` fixés et `time_frame="4 hours"` (aligné avec la récurrence)

## Sortie contexte

Le script écrit dans le contexte sous `CrowdStrike.BYOS` :

| Path | Description |
|---|---|
| `CrowdStrike.BYOS.assets_count` | Total assets soumis |
| `CrowdStrike.BYOS.vulnerabilities_count` | Total vulnérabilités soumises |
| `CrowdStrike.BYOS.xql_rows` | Nombre de lignes brutes retournées par XQL |
| `CrowdStrike.BYOS.jobs` | Liste des réponses par batch (avec `job_id`, `assets_in_batch`, `vulnerabilities_in_batch`, `poll_result`) |
| `CrowdStrike.BYOS.poll_summary` | `{polled, total_jobs, completed, completed_with_errors, failed}` |
| `CrowdStrike.BYOS.Poll.*` | Mode standalone uniquement : `job_id`, `job_status`, `poll_attempts`, `poll_elapsed_seconds`, `error_log` |

## Mapping confidence

| Falcon Spotlight `status` | BYOS `confidence` |
|---|---|
| Any autre | `Confirmed` (Spotlight remonte activement la vuln) |
| `closed`, `lift_containment_pending`, `reopen` | `Potential` |

## Payload BYOS

Voir [`examples/payload_example.json`](examples/payload_example.json). Extrait :

```json
{
  "vendor": "CrowdStrike",
  "product": "Falcon Spotlight",
  "version": "1.0",
  "assets": [{
    "origin_asset_id": "crowdstrike-agent-0cd620c20ea2622b504867babf7b539b",
    "asset_name": "BSNS-MAC-EMMA",
    "ipv4": ["192.168.1.1"],
    "os_name": "macOS 13.6",
    "origin_tags": [
      "crowdstrike:agent_id:0cd620c20ea2622b504867babf7b539b",
      "group:Executive Endpoints",
      "site:Default",
      "platform:Mac"
    ],
    "vulnerabilities": [{
      "vulnerability_id": "CVE-2021-68215",
      "cve_id": ["CVE-2021-68215"],
      "description": "Remote Code Execution in Hines, Rodriguez and Smith Product",
      "confidence": "Potential",
      "last_seen": 1784716267874,
      "evidence": "Patch: Update to patched version to mitigate CVE-2021-68215 ..."
    }]
  }]
}
```

## Prérequis

- L'intégration **CrowdStrike Falcon** est configurée dans XSIAM et a déjà alimenté `crowdstrike_falcon_spotlight_vulnerabilities_raw` (sinon la requête XQL renvoie 0 ligne).
- Ton tenant Cortex a la licence **Exposure Management**.
- La clé API utilisée a la permission RBAC `manage_vulnerabilities_action`.

## Validation locale

Testé bout-en-bout contre les 39 lignes du sample `crowdstrike-simul/dataset/crowdstrike_falcon_spotlight_vulnerabilities_raw.tsv` :
- **39 lignes XQL → 14 assets → 39 vulnérabilités**
- **3 batches** de 5 assets max (batch_size=5)
- **3 jobs COMPLETED** après auto-poll

## Références

- BYOS overview — https://docs-cortex.paloaltonetworks.com/r/Cortex-XSIAM-Platform-APIs/Bring-Your-Own-Scanner
- Submit endpoint — https://docs-cortex.paloaltonetworks.com/r/Cortex-XSIAM-Platform-APIs/Submit-assets-and-vulnerabilities-from-an-external-scanner
- Poll import job — https://docs-cortex.paloaltonetworks.com/r/Cortex-XSIAM-Platform-APIs/Poll-the-status-of-a-BYOS-import-job
- Start XQL query — https://docs-cortex.paloaltonetworks.com/r/Cortex-XSIAM-Platform-APIs/Start-an-XQL-query
- Get XQL results — https://docs-cortex.paloaltonetworks.com/r/Cortex-XSIAM-Platform-APIs/Get-XQL-query-results
- Cyberwatch BYOS importer (variant qui appelle une intégration au lieu du dataset) — https://github.com/JCourtemanche/cyberwatch-simul/tree/main/byos-importer
