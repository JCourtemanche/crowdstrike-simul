"""
CrowdStrike Falcon Mock Server
Simulates the CrowdStrike Falcon API for XSIAM Content Pack testing.
"""
import logging
from flask import Flask, jsonify
from config import Config
import store

from routes.oauth import oauth_bp
from routes.devices import devices_bp
from routes.alerts import alerts_bp
from routes.iocs import iocs_bp
from routes.spotlight import spotlight_bp
from routes.processes import processes_bp
from routes.quarantine import quarantine_bp
from routes.cases import cases_bp
from routes.exclusions import exclusions_bp
from routes.rtr import rtr_bp
from routes.container_security import container_security_bp


def create_app():
    app = Flask(__name__)

    logging.basicConfig(
        level=logging.INFO if Config.DEBUG else logging.WARNING,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    )
    logger = logging.getLogger(__name__)
    logger.info("Starting CrowdStrike Falcon Mock Server")

    # Bootstrap seed data
    store.bootstrap()
    logger.info(
        f"Seeded: {len(store.devices)} devices, {len(store.alerts)} alerts, "
        f"{len(store.iocs)} IOCs, {len(store.vulnerabilities)} vulnerabilities, "
        f"{len(store.host_groups)} host groups, {len(store.cnapp_alerts)} CNAPP alerts"
    )

    # Register blueprints
    app.register_blueprint(oauth_bp)
    app.register_blueprint(devices_bp)
    app.register_blueprint(alerts_bp)
    app.register_blueprint(iocs_bp)
    app.register_blueprint(spotlight_bp)
    app.register_blueprint(processes_bp)
    app.register_blueprint(quarantine_bp)
    app.register_blueprint(cases_bp)
    app.register_blueprint(exclusions_bp)
    app.register_blueprint(rtr_bp)
    app.register_blueprint(container_security_bp)

    @app.route('/health', methods=['GET'])
    def health():
        return jsonify({
            'status': 'healthy',
            'service': 'CrowdStrike Falcon Mock',
            'version': '1.0.0',
            'seed_data': {
                'devices': len(store.devices),
                'alerts': len(store.alerts),
                'iocs': len(store.iocs),
                'vulnerabilities': len(store.vulnerabilities),
                'host_groups': len(store.host_groups),
                'cnapp_alerts': len(store.cnapp_alerts),
            },
        }), 200

    @app.route('/', methods=['GET'])
    def root():
        return jsonify({
            'service': 'CrowdStrike Falcon Mock',
            'version': '1.0.0',
            'base_url': 'https://api.crowdstrike.com',
            'authentication': 'POST /oauth2/token (client_credentials)',
            'endpoints': {
                'POST /oauth2/token': 'Get OAuth2 bearer token',
                'GET /devices/queries/devices/v1': 'Query device IDs',
                'POST /devices/entities/devices/v2': 'Get device details',
                'GET /devices/entities/online-state/v1': 'Get device online state',
                'POST /devices/entities/devices-actions/v2': 'Contain/lift containment',
                'GET /devices/combined/host-groups/v1': 'List host groups',
                'GET /alerts/queries/alerts/v2': 'Query alert IDs',
                'POST /alerts/entities/alerts/v2': 'Get alert entities',
                'PATCH /alerts/entities/alerts/v3': 'Update alerts',
                'GET /iocs/combined/indicator/v1': 'Search custom IOCs',
                'POST /iocs/entities/indicators/v1': 'Create IOC',
                'GET /spotlight/combined/vulnerabilities/v1': 'Search vulnerabilities (facet + FQL filter, cursor pagination — used by fetch-assets)',
                'GET /container-security/combined/container-alerts/v1': 'List CNAPP alerts (used by fetch-assets CNAPP track)',
                'GET /processes/entities/processes/v1': 'Get process details',
                'GET /quarantine/queries/quarantined-files/v1': 'Query quarantined files',
                'GET /health': 'Health check',
            },
        }), 200

    @app.errorhandler(404)
    def not_found(error):
        return jsonify({
            'meta': {'query_time': 0.001, 'trace_id': ''},
            'errors': [{'code': 404, 'message': 'Endpoint not found in mock server'}],
            'resources': [],
        }), 404

    @app.errorhandler(500)
    def internal_error(error):
        logger.error(f"Internal server error: {error}")
        return jsonify({
            'meta': {'query_time': 0.001, 'trace_id': ''},
            'errors': [{'code': 500, 'message': 'Internal server error'}],
            'resources': [],
        }), 500

    return app


app = create_app()

if __name__ == '__main__':
    app.run(host=Config.HOST, port=Config.PORT, debug=Config.DEBUG)
