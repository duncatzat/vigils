import { scanText } from "../redaction-rules.js";
import { decideRisk } from "../risk-decision.js";

export function createConsumerJsProvider(options = {}) {
    const customRiskRules = options.customRiskRules || [];
    return {
        name: "consumer_js",
        async check(request) {
            const findings = scanText(request && request.text, customRiskRules);
            return decideRisk(request, findings, customRiskRules);
        },
    };
}
