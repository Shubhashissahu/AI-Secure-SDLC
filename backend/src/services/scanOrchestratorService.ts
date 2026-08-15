import Scan, { IScan } from "../models/Scan";
import Finding, { FindingCategory, FindingStatus } from "../models/Finding";
import Repository from "../models/Repository";
import { checkoutRepo } from "./repoCheckoutService";
import { SecurityScanner } from "./scanners/SecurityScanner";
import { SastScanner } from "./scanners/sastScannerService";
import { SecretScanner } from "./scanners/secretScannerService";
import { AiSecurityScanner } from "./scanners/aiSecurityScannerService";
import { TrivyScanner } from "./scanners/trivyService";
import { OsvDependencyScanner } from "./scanners/osvScannerService";
import { ContainerScanner } from "./scanners/containerScannerService";
import { IacScanner } from "./scanners/iacScannerService";
import { CicdScanner } from "./scanners/cicdScannerService";
import { NormalizedFinding } from "./scanners/types";
import { extractCodeContext } from "./ai/contextExtractor";
import { reviewFinding, generateRemediation } from "./ai/aiReviewerService";
import { computeRisk, RiskResult } from "./riskService";
import { PolicyEngine, getSecurityPolicyForRepository, SecurityPolicy } from "./policyEngine";
import { GitHubService } from "./githubService";
import { ReportService } from "./reportService";
import { verifyFindingAccuracy } from "./findingVerifier";
import { generateFindingFingerprint } from "../utils/fingerprint";
import { maskAllSecretsInText, safeLog } from "../utils/secretMasker";

export async function runScanPipeline(scanId: string): Promise<void> {
    const pipelineStart = Date.now();
    const scan = await Scan.findById(scanId);
    if (!scan) {
        safeLog.error(`[orchestrator] Scan ${scanId} not found`);
        return;
    }

    const repository = await Repository.findById(scan.repositoryId).select("+webhookSecret");
    if (!repository) {
        await markScanFailed(scan, "Repository not found");
        return;
    }

    const policy: SecurityPolicy = getSecurityPolicyForRepository(repository.policyConfig);
    const githubToken = process.env.GITHUB_TOKEN || process.env.GITHUB_APP_TOKEN;
    const ghService = githubToken ? new GitHubService(githubToken) : null;

    safeLog.info(`\n${"=".repeat(60)}`);
    safeLog.info(`[START] Security Scan Pipeline (SAST + SCA + SECRETS + CONTAINER + IAC)`);
    safeLog.info(`  Repository:  ${repository.owner}/${repository.name}`);
    safeLog.info(`  Commit:      ${scan.commitSha}`);
    safeLog.info(`  Scan ID:     ${scanId}`);
    safeLog.info(`  PR #:        ${scan.prNumber}`);
    safeLog.info(`${"=".repeat(60)}`);

    scan.status = "scanning";
    scan.scannerVersion = "2.0.0";
    await scan.save();

    if (ghService && repository.owner && repository.name) {
        await ghService.createCommitStatus(
            repository.owner,
            repository.name,
            scan.commitSha,
            "pending",
            "AI Security Scan in progress (SAST, SCA & Secrets)..."
        );
    }

    let checkout: Awaited<ReturnType<typeof checkoutRepo>> | null = null;

    try {
        checkout = await checkoutRepo(
            repository.githubUrl,
            scan.commitSha,
            githubToken
        );

        safeLog.info(`[CHECKOUT] Repository cloned successfully`);
        safeLog.info(`  Path:   ${checkout.repoPath}`);
        safeLog.info(`  Source: ${repository.githubUrl}`);
        safeLog.info(`  Commit: ${scan.commitSha}`);

        // ── Run all scanners (SAST, Secrets, SCA) ──────────────────
        const scannerResults = await runAllScanners(checkout.repoPath, repository.scanConfig);
        const allRawFindings: NormalizedFinding[] = [];
        const scannerSummary: Record<string, { found: number; status: string; error?: string }> = {};

        for (const res of scannerResults) {
            scannerSummary[res.scanner] = {
                found: res.findings.length,
                status: res.status,
                error: res.error
            };
            if (res.status === "success") {
                // Ensure secret masking on all findings
                for (const f of res.findings) {
                    if (f.category === "SECRETS" || f.tool === "gitleaks") {
                        f.codeSnippet = maskAllSecretsInText(f.codeSnippet);
                        f.isMasked = true;
                    }
                    allRawFindings.push(f);
                }
            } else {
                safeLog.error(`[${res.scanner.toUpperCase()}] Scan failed: ${res.error || "unknown error"}`);
            }
        }

        safeLog.info(`\n[SAST - SEMGREP & CODE] Found: ${scannerSummary.semgrep?.found ?? 0} findings`);
        safeLog.info(`[SECRETS - GITLEAKS]   Found: ${(scannerSummary.gitleaks?.found ?? 0) + (scannerSummary["secret-scanner"]?.found ?? 0)} findings`);
        safeLog.info(`[AI SECURITY - LLM]   Found: ${scannerSummary["ai-security-scanner"]?.found ?? 0} findings`);
        safeLog.info(`[SCA - TRIVY & OSV]    Found: ${(scannerSummary.trivy?.found ?? 0) + (scannerSummary.osv?.found ?? 0)} findings`);
        safeLog.info(`[CONTAINER - DOCKER]   Found: ${scannerSummary["container-scanner"]?.found ?? 0} findings`);
        safeLog.info(`[IAC - TERRAFORM/K8S]  Found: ${scannerSummary["iac-scanner"]?.found ?? 0} findings`);
        safeLog.info(`[CI/CD - ACTIONS]      Found: ${scannerSummary["cicd-scanner"]?.found ?? 0} findings`);

        // Check if critical scanner failed
        const failedScanners = scannerResults.filter((s) => s.status === "failed");
        if (failedScanners.length > 0) {
            const failReasons = failedScanners.map((s) => `${s.scanner} (${s.error || "Execution failed"})`).join("; ");
            safeLog.error(`\n[SCANNER ERROR] Scanner(s) failed execution: ${failReasons}`);
            scan.status = "failed";
            scan.gateResult = "fail";
            scan.completedAt = new Date();
            await scan.save();

            const durationMs = Date.now() - pipelineStart;
            safeLog.info(`\n[FAILED] Gate Result: FAIL (Scanner Error) — ${durationMs}ms`);
            safeLog.info(`${"=".repeat(60)}\n`);

            if (ghService && repository.owner && repository.name) {
                await ghService.createCommitStatus(
                    repository.owner,
                    repository.name,
                    scan.commitSha,
                    "failure",
                    `Security Scan Failed: ${failReasons}`.slice(0, 140)
                );
                if (scan.prNumber) {
                    await ghService.commentOnPR(
                        repository.owner,
                        repository.name,
                        scan.prNumber,
                        `### ❌ Security Scan Pipeline Error\n\nScanner execution failed: ${failReasons}`
                    );
                }
            }
            return;
        }

        // ── Validate findings accuracy: File, Line, and Code existence checks ──
        const validFindings: NormalizedFinding[] = [];
        let discardedCount = 0;

        for (const nf of allRawFindings) {
            const verification = await verifyFindingAccuracy(checkout.repoPath, nf);
            if (!verification.isValid) {
                safeLog.warn(`[VERIFICATION REJECTED] Discarded invalid finding: ${nf.file}:${nf.line} (${nf.ruleId}) - Reason: ${verification.reason}`);
                discardedCount++;
                continue;
            }

            // Path normalization
            nf.file = nf.file.replace(/\\/g, "/");
            validFindings.push(nf);
        }

        safeLog.info(`\n[ACCURACY CHECK] Validated: ${validFindings.length} findings | Discarded: ${discardedCount} invalid`);

        // Query previously active findings for this repository to track rescan resolution
        const previouslyActiveFindings = await Finding.find({
            repositoryId: repository._id,
            status: { $in: ["OPEN", "CONFIRMED", "DISCOVERED", "open", "confirmed"] }
        });

        const currentScanFingerprints = new Set<string>();

        if (validFindings.length === 0) {
            // All previous active findings are now resolved in this commit
            for (const prev of previouslyActiveFindings) {
                prev.status = "RESOLVED";
                await prev.save();
            }

            scan.status = "completed";
            scan.gateResult = "pass";
            scan.completedAt = new Date();
            scan.summary = { critical: 0, high: 0, medium: 0, low: 0, total: 0 };
            await scan.save();

            const durationMs = Date.now() - pipelineStart;
            safeLog.info(`\n[COMPLETE] Gate Result: PASS (0 findings, resolved previous) — ${durationMs}ms`);
            safeLog.info(`${"=".repeat(60)}\n`);

            if (ghService && repository.owner && repository.name) {
                await ghService.createCommitStatus(repository.owner, repository.name, scan.commitSha, "success", "Security Gate Passed: 0 findings (SAST/SCA/Secrets clean).");
                if (scan.prNumber) {
                    await ghService.commentOnPR(repository.owner, repository.name, scan.prNumber, ReportService.generatePRComment(scan, []));
                }
            }
            return;
        }

        // ── AI Review & Finding Fingerprint Upsert Phase ────────────
        scan.status = "ai_review";
        await scan.save();

        const summary = { critical: 0, high: 0, medium: 0, low: 0, total: 0 };
        const evaluatedFindings: Array<{
            score: number;
            severity: NormalizedFinding["severity"];
            decision: RiskResult["decision"];
            category?: string;
            cvss?: number;
        }> = [];
        let aiReviewedCount = 0;
        let newFindingsCount = 0;
        let unchangedFindingsCount = 0;

        // Deduplicate validFindings by deterministic fingerprint
        const uniqueFindingsMap = new Map<string, { nf: NormalizedFinding; fingerprint: string }>();
        for (const nf of validFindings) {
            const fp = generateFindingFingerprint(
                String(repository._id),
                scan.commitSha,
                nf.file,
                nf.line,
                nf.ruleId,
                nf.tool
            );
            if (!uniqueFindingsMap.has(fp)) {
                uniqueFindingsMap.set(fp, { nf, fingerprint: fp });
            }
        }

        for (const { nf, fingerprint } of uniqueFindingsMap.values()) {
            currentScanFingerprints.add(fingerprint);

            const result = await processAndUpsertFinding(
                nf,
                fingerprint,
                checkout.repoPath,
                scan,
                repository._id,
                policy
            );

            if (result) {
                summary[nf.severity] += 1;
                summary.total += 1;
                evaluatedFindings.push({
                    score: result.risk.score,
                    severity: nf.severity,
                    decision: result.risk.decision,
                    category: nf.category,
                    cvss: nf.cvss
                });
                if (result.isNew) newFindingsCount++;
                else unchangedFindingsCount++;
                aiReviewedCount++;
            }
        }

        // ── Rescan Resolution: Mark disappeared vulnerabilities as RESOLVED ──
        let resolvedCount = 0;
        for (const prev of previouslyActiveFindings) {
            if (!currentScanFingerprints.has(prev.fingerprint)) {
                prev.status = "RESOLVED";
                prev.resolvedCommitSha = scan.commitSha;
                prev.resolvedAt = new Date();
                await prev.save();
                resolvedCount++;
                safeLog.info(`[RESCAN RESOLUTION] Marked previous finding as RESOLVED: ${prev.file}:${prev.line} (${prev.ruleId}) in commit ${scan.commitSha.slice(0, 7)}`);
            }
        }

        scan.rescanSummary = {
            newFindings: newFindingsCount,
            resolvedFindings: resolvedCount,
            unchangedFindings: unchangedFindingsCount
        };

        safeLog.info(`\n[ASSESSMENT] Processed: ${aiReviewedCount} findings | Rescan: +${newFindingsCount} new, -${resolvedCount} resolved, ${unchangedFindingsCount} unchanged`);

        scan.summary = summary;
        scan.status = "completed";
        scan.completedAt = new Date();

        const gateEval = PolicyEngine.evaluateGateDecision(evaluatedFindings, policy);
        scan.gateResult = gateEval.gateResult;

        await scan.save();

        const durationMs = Date.now() - pipelineStart;
        safeLog.info(`\n[COMPLETE] Gate Result: ${scan.gateResult.toUpperCase()} (${gateEval.decisionReason}) — ${durationMs}ms`);
        safeLog.info(`  Critical: ${summary.critical} | High: ${summary.high} | Medium: ${summary.medium} | Low: ${summary.low} | Total: ${summary.total}`);
        safeLog.info(`${"=".repeat(60)}\n`);

        if (ghService && repository.owner && repository.name) {
            const state = scan.gateResult === "pass" ? "success" : "failure";
            await ghService.createCommitStatus(repository.owner, repository.name, scan.commitSha, state, gateEval.decisionReason.slice(0, 140));

            const storedFindings = await Finding.find({ scanId: scan._id });
            if (scan.prNumber) {
                const commentMarkdown = ReportService.generatePRComment(scan, storedFindings);
                await ghService.commentOnPR(repository.owner, repository.name, scan.prNumber, commentMarkdown);
            }
        }
    } catch (err: unknown) {
        const message = err instanceof Error ? err.message : "unknown error";
        await markScanFailed(scan, message);
        safeLog.error(`[FAILED] Scan ${scanId} failed: ${message}`);
        safeLog.info(`${"=".repeat(60)}\n`);
    } finally {
        if (checkout) {
            await checkout.cleanup();
        }
    }
}

async function runAllScanners(
    repoPath: string,
    scanConfig?: {
        enableSemgrep?: boolean;
        enableGitleaks?: boolean;
        enableTrivy?: boolean;
        enableContainer?: boolean;
        enableIac?: boolean;
        enableCicd?: boolean;
    }
) {
    const config = scanConfig || {
        enableSemgrep: true,
        enableGitleaks: true,
        enableTrivy: true,
        enableContainer: true,
        enableIac: true,
        enableCicd: true
    };
    const scanners: SecurityScanner[] = [];

    // 1. SAST Scanner (Semgrep + Native Multi-Language AST/Regex Engine)
    if (config.enableSemgrep !== false) {
        scanners.push(new SastScanner());
    }

    // 2. Secret Scanner (Gitleaks + Native Deep Regex Scanner)
    if (config.enableGitleaks !== false) {
        scanners.push(new SecretScanner());
    }

    // 3. AI Security Scanner (Prompt Injection, System Prompt Exposure, PII in LLMs)
    scanners.push(new AiSecurityScanner());

    // 4. SCA Dependency Scanner (Trivy + OSV Live Database)
    if (config.enableTrivy !== false) {
        scanners.push(new TrivyScanner());
    }
    scanners.push(new OsvDependencyScanner());

    // 5. Container Scanner (Dockerfile & Compose Security)
    if (config.enableContainer !== false) {
        scanners.push(new ContainerScanner());
    }

    // 6. IaC Scanner (Terraform, Kubernetes & Compose Security)
    if (config.enableIac !== false) {
        scanners.push(new IacScanner());
    }

    // 7. CI/CD Security Scanner (GitHub Actions Workflows)
    if (config.enableCicd !== false) {
        scanners.push(new CicdScanner());
    }

    return Promise.all(scanners.map((s) => s.scan(repoPath)));
}

/**
 * Processes a verified finding: extracts context, reviews with AI,
 * computes risk score, and performs deterministic fingerprint upsert.
 */
async function processAndUpsertFinding(
    nf: NormalizedFinding,
    fingerprint: string,
    repoPath: string,
    scan: IScan,
    repositoryId: unknown,
    policy: SecurityPolicy
): Promise<{ risk: RiskResult; isNew: boolean } | null> {
    // 1. Context Extraction
    const context = await extractCodeContext(repoPath, nf.file, nf.line);
    const codeSnippet = nf.category === "SECRETS"
        ? maskAllSecretsInText(nf.codeSnippet)
        : (context?.surroundingCode || nf.codeSnippet);

    const category: FindingCategory = nf.category || (
        nf.tool === "ai-security-scanner" ? "AI_SECURITY" :
        nf.tool === "gitleaks" || nf.tool === "secret-scanner" ? "SECRETS" :
        nf.tool === "container-scanner" ? "CONTAINER" :
        nf.tool === "iac-scanner" ? "IAC" :
        nf.tool === "cicd-scanner" ? "CI_CD" :
        nf.tool === "trivy" || nf.tool === "osv" ? "SCA" : "SAST"
    );

    // 2. Finding Upsert lookup by deterministic unique fingerprint
    let findingDoc = await Finding.findOne({ fingerprint });
    const isNew = !findingDoc;

    if (!findingDoc) {
        findingDoc = new Finding({
            scanId: scan._id,
            repositoryId,
            commitSha: scan.commitSha,
            fingerprint,
            category,
            tool: nf.tool,
            file: nf.file,
            line: nf.line,
            ruleId: nf.ruleId,
            cwe: nf.cwe || (category === "SECRETS" ? "CWE-798" : category === "AI_SECURITY" ? "CWE-20" : category === "SCA" ? "CWE-1395" : category === "CONTAINER" ? "CWE-250" : category === "IAC" ? "CWE-16" : category === "CI_CD" ? "CWE-78" : "CWE-89"),
            title: nf.title || `${nf.ruleId} detected in ${nf.file}`,
            description: nf.description || "",
            codeSnippet: codeSnippet.slice(0, 4000),
            secretRef: nf.secretRef,
            secretType: nf.secretType,
            isMasked: category === "SECRETS" || nf.isMasked || false,
            package: nf.package,
            installedVersion: nf.installedVersion,
            fixedVersion: nf.fixedVersion,
            cve: nf.cve,
            cvss: nf.cvss,
            scaRemediation: nf.scaRemediation,
            resourceName: nf.resourceName,
            resourceType: nf.resourceType,
            containerImage: nf.containerImage,
            iacPlatform: nf.iacPlatform,
            complianceStandard: nf.complianceStandard,
            workflowName: nf.workflowName,
            actionName: nf.actionName,
            severity: nf.severity,
            status: "AI_REVIEWING",
            occurrences: 1,
            firstSeenAt: new Date(),
            lastSeenAt: new Date()
        });
    } else {
        findingDoc.scanId = scan._id;
        findingDoc.category = category;
        findingDoc.lastSeenAt = new Date();
        findingDoc.occurrences = (findingDoc.occurrences || 1) + 1;
        if (nf.package) findingDoc.package = nf.package;
        if (nf.installedVersion) findingDoc.installedVersion = nf.installedVersion;
        if (nf.fixedVersion) findingDoc.fixedVersion = nf.fixedVersion;
        if (nf.cve) findingDoc.cve = nf.cve;
        if (nf.cvss) findingDoc.cvss = nf.cvss;
        if (nf.scaRemediation) findingDoc.scaRemediation = nf.scaRemediation;
        if (nf.secretType) findingDoc.secretType = nf.secretType;
        if (nf.resourceName) findingDoc.resourceName = nf.resourceName;
        if (nf.resourceType) findingDoc.resourceType = nf.resourceType;
        if (nf.containerImage) findingDoc.containerImage = nf.containerImage;
        if (nf.iacPlatform) findingDoc.iacPlatform = nf.iacPlatform;
        if (nf.complianceStandard) findingDoc.complianceStandard = nf.complianceStandard;
        if (nf.workflowName) findingDoc.workflowName = nf.workflowName;
        if (nf.actionName) findingDoc.actionName = nf.actionName;
    }

    // 3. AI Verification / Triage
    const effectiveContext = context || {
        surroundingCode: nf.codeSnippet,
        language: "text",
        imports: []
    };

    const review = await reviewFinding(nf, effectiveContext, scan._id, findingDoc._id);

    // 4. Remediation Generation
    const remediation =
        category === "SCA"
            ? { patch: review.secureFix || "", explanation: nf.scaRemediation || review.recommendation || "" }
            : category === "SECRETS"
            ? { patch: review.secureFix || "", explanation: review.recommendation || "" }
            : review.isRealVulnerability && !review.reviewFailed
            ? await generateRemediation(nf, effectiveContext, review)
            : { patch: review.secureFix || "", explanation: review.recommendation || "Finding triaged as false positive." };

    // 5. Multi-Factor Risk Calculation
    const risk = computeRisk(nf, review, policy);

    // 6. Finding Lifecycle Status Assignment
    const lifecycleStatus: FindingStatus = review.status;

    findingDoc.status = lifecycleStatus;
    findingDoc.ai = {
        isRealVulnerability: review.isRealVulnerability,
        confidence: review.confidence,
        confidenceLevel: review.confidenceLevel,
        reason: review.reason,
        attackScenario: review.attackScenario,
        cwe: review.cwe,
        owasp: review.owasp,
        exploitability: review.exploitability,
        recommendation: review.recommendation,
        secureFix: review.secureFix,
        remediation,
        reviewFailed: review.reviewFailed
    };
    findingDoc.risk = {
        score: risk.score,
        severityWeight: risk.severityWeight,
        exploitabilityWeight: risk.exploitabilityWeight,
        businessImpactWeight: risk.businessImpactWeight,
        exposureWeight: risk.exposureWeight,
        assetCriticalityWeight: risk.assetCriticalityWeight,
        authRequiredWeight: risk.authRequiredWeight,
        exploitAvailabilityWeight: risk.exploitAvailabilityWeight,
        reason: risk.reason,
        decision: risk.decision
    };

    try {
        await findingDoc.save();
    } catch (err: unknown) {
        const mongoErr = err as { code?: number; name?: string };
        if (mongoErr?.code === 11000 || mongoErr?.name === "MongoServerError") {
            const existing = await Finding.findOne({ fingerprint });
            if (existing) {
                existing.scanId = scan._id;
                existing.category = category;
                existing.status = lifecycleStatus;
                existing.ai = findingDoc.ai;
                existing.risk = findingDoc.risk;
                existing.lastSeenAt = new Date();
                existing.occurrences = (existing.occurrences || 1) + 1;
                await existing.save();
            }
        } else {
            throw err;
        }
    }
    safeLog.info(`[orchestrator] ${isNew ? "Created" : "Updated"} [${category}] finding: ${nf.file}:${nf.line} [${lifecycleStatus}]`);

    return { risk, isNew };
}


async function markScanFailed(scan: IScan, reason: string): Promise<void> {
    console.error(`[orchestrator] Scan ${scan._id} failed: ${reason}`);
    scan.status = "failed";
    scan.gateResult = "fail";
    scan.completedAt = new Date();
    await scan.save();
}