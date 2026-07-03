export const ENTERPRISE_DATA_POLICIES = Object.freeze([
    "local_only",
    "metadata_only",
    "raw_allowed",
]);

export function createEnterpriseProvider(config = {}) {
    if (config.provider) return config.provider;

    return {
        name: "enterprise_disabled",
        async check(request) {
            return {
                request_id: request && request.request_id ? request.request_id : "",
                action: "allow",
                findings: [],
                source: "enterprise",
                error: "enterprise_not_configured",
            };
        },
    };
}
