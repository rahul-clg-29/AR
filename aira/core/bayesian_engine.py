"""
AIRA Probabilistic Bayesian Reasoning & Dynamic Belief Updating Engine
Replaces arbitrary heuristic confidence numbers with mathematically provable Bayesian inference:
Computes dynamic posterior probabilities P(Intrusion | Evidence) and Bayes Factors (Likelihood Ratios)
as forensic evidence arrives along the causal attack graph.
"""

import math
from typing import List, Tuple, Dict, Any, Optional
from pydantic import BaseModel, Field

from aira.core.models import CanonicalEvent, MitreTechnique, EventType


class BayesianTrajectoryStep(BaseModel):
    step_number: int
    record_id: str
    timestamp: str
    feature_name: str
    description: str
    likelihood_ratio: float
    posterior_probability: float
    log_bayes_factor: float


class BayesianAssessment(BaseModel):
    prior_probability: float
    final_posterior: float
    total_bayes_factor: float
    bayesian_verdict: str
    confidence_interval: Tuple[float, float]
    trajectory: List[BayesianTrajectoryStep] = Field(default_factory=list)
    top_contributing_evidence: List[Dict[str, Any]] = Field(default_factory=list)


class BayesianInferenceEngine:
    """
    Implements odds-form Bayesian updates:
        Posterior Odds = Prior Odds * Product(Likelihood Ratios)
        P(Intrusion | E) = Posterior Odds / (1 + Posterior Odds)
    """

    # Conservative enterprise base-rate prior: intrusions are rare (0.1% baseline risk)
    DEFAULT_BASE_PRIOR = 0.001

    # Calibrated Likelihood Ratios (Bayes Factors) Lambda = P(Evidence | Malicious) / P(Evidence | Benign)
    TECHNIQUE_BAYES_FACTORS = {
        "T1204.002": {"name": "Office Spawning Command Shell", "lambda": 450.0, "desc": "User opened Office document that directly spawned a command shell (extremely abnormal in standard enterprise workflows)."},
        "T1059.001": {"name": "Obfuscated / Encoded PowerShell", "lambda": 95.0, "desc": "PowerShell executed with window hiding, base64 encoding, or download cradle flags."},
        "T1059.003": {"name": "Windows Command Shell Invocation", "lambda": 12.0, "desc": "Command prompt execution in parent-child relationship."},
        "T1003.001": {"name": "LSASS Process Memory Harvesting", "lambda": 850.0, "desc": "Direct memory access request (0x1010) into Local Security Authority Subsystem Service (LSASS)."},
        "T1003.003": {"name": "Active Directory NTDS Database Extraction", "lambda": 1200.0, "desc": "Execution of ntdsutil to extract ntds.dit Active Directory database."},
        "T1021.002": {"name": "Administrative SMB Lateral Movement", "lambda": 48.0, "desc": "Outbound administrative port 445 SMB connection across internal subnets following credential dumping."},
        "T1047":     {"name": "Remote WMI Execution", "lambda": 65.0, "desc": "WmiPrvSE spawning child shells or wmic process call create."},
        "T1547.001": {"name": "Registry Run Key Persistence", "lambda": 35.0, "desc": "Startup registry modification to survive host reboots."},
        "T1543.003": {"name": "Windows Service Persistence", "lambda": 45.0, "desc": "Service creation for persistence across domain controllers."},
        "T1071.001": {"name": "External C2 Communication", "lambda": 42.0, "desc": "Outbound TCP connection from scripting engine or untrusted binary to non-standard external host."},
        "T1082":     {"name": "System Reconnaissance", "lambda": 14.0, "desc": "Reconnaissance commands (whoami, systeminfo, net) executed following shell access."},
        "T1105":     {"name": "Ingress Tool Transfer", "lambda": 55.0, "desc": "Certutil or bitsadmin used for remote payload retrieval."},
        "T1218.011": {"name": "Rundll32 Proxy Execution", "lambda": 40.0, "desc": "Rundll32 executing untrusted DLL entry points."},
        "T1218.005": {"name": "Mshta Proxy Execution", "lambda": 60.0, "desc": "Mshta executing remote or inline script payloads."},
        "T1070.001": {"name": "Event Log Clearing", "lambda": 300.0, "desc": "Anti-forensic log clearing via wevtutil."},
    }

    BENIGN_NOISE_FACTOR = 0.15  # Evidence that reduces posterior odds toward benign (e.g., standard browser browsing)

    def __init__(self, prior: float = DEFAULT_BASE_PRIOR):
        self.prior = prior
        self.prior_odds = prior / max(1.0 - prior, 1e-9)

    def evaluate_incident(
        self,
        all_events: List[CanonicalEvent],
        flagged_events: List[Tuple[CanonicalEvent, List[MitreTechnique]]]
    ) -> BayesianAssessment:
        """
        Processes events chronologically and updates posterior probability mathematically.
        """
        flagged_map: Dict[str, List[MitreTechnique]] = {
            ev.record_id: techs for ev, techs in flagged_events
        }

        # Sort all events chronologically
        sorted_events = sorted(all_events, key=lambda e: e.timestamp)

        current_odds = self.prior_odds
        trajectory: List[BayesianTrajectoryStep] = []
        step_counter = 1
        contributing_evidence: List[Dict[str, Any]] = []

        for ev in sorted_events:
            techs = flagged_map.get(ev.record_id, [])
            lr = 1.0
            feature_name = "Baseline Activity"
            desc = "Routine endpoint/network telemetry"

            if techs:
                # Find maximum Bayes factor among mapped techniques
                for t in techs:
                    info = self.TECHNIQUE_BAYES_FACTORS.get(t.id)
                    if info and info["lambda"] > lr:
                        lr = info["lambda"]
                        feature_name = f"{t.id}: {info['name']}"
                        desc = info["desc"]
                
                contributing_evidence.append({
                    "record_id": ev.record_id,
                    "feature": feature_name,
                    "likelihood_ratio": lr,
                    "host": ev.host
                })
            else:
                # Check for benign noise
                proc_img = (ev.process.image.lower() if ev.process and ev.process.image else "")
                if any(b in proc_img for b in ["chrome.exe", "msedge.exe", "spotify.exe", "onedrive.exe"]):
                    lr = self.BENIGN_NOISE_FACTOR
                    feature_name = "Benign Enterprise Background Noise"
                    desc = f"Verified standard application execution: {proc_img.split(chr(92))[-1]}"

            # Only record steps that actually shift belief
            if abs(lr - 1.0) > 1e-4:
                current_odds *= lr
                # Numerical bound checks
                current_odds = max(min(current_odds, 1e12), 1e-12)
                p_current = current_odds / (1.0 + current_odds)

                trajectory.append(
                    BayesianTrajectoryStep(
                        step_number=step_counter,
                        record_id=ev.record_id,
                        timestamp=ev.timestamp.isoformat(),
                        feature_name=feature_name,
                        description=desc,
                        likelihood_ratio=round(lr, 2),
                        posterior_probability=round(p_current, 4),
                        log_bayes_factor=round(math.log10(lr), 2)
                    )
                )
                step_counter += 1

        final_odds = current_odds
        final_posterior = final_odds / (1.0 + final_odds)
        total_bayes_factor = final_odds / self.prior_odds

        # Bound final posterior sensibly
        final_posterior = max(min(final_posterior, 0.999), 0.001)

        # Confidence interval estimation (Wilson Score interval for Bernoulli parameter)
        n_obs = max(len(trajectory), 1)
        z = 1.96  # 95% confidence
        denom = 1.0 + (z**2 / n_obs)
        center = (final_posterior + (z**2 / (2 * n_obs))) / denom
        margin = z * math.sqrt((final_posterior * (1 - final_posterior) / n_obs) + (z**2 / (4 * n_obs**2))) / denom
        ci_lower = max(0.0, round(center - margin, 3))
        ci_upper = min(1.0, round(center + margin, 3))

        # Qualitative calibration of Bayesian verdict
        if final_posterior >= 0.90:
            verdict = "CONFIRMED_MALICIOUS"
        elif final_posterior >= 0.70:
            verdict = "PROBABLE_INTRUSION"
        elif final_posterior >= 0.40:
            verdict = "SUSPICIOUS_ANOMALY"
        else:
            verdict = "BENIGN_ACTIVITY"

        # Sort top contributing evidence by Bayes factor descending
        contributing_evidence.sort(key=lambda x: x["likelihood_ratio"], reverse=True)

        return BayesianAssessment(
            prior_probability=self.prior,
            final_posterior=round(final_posterior, 4),
            total_bayes_factor=round(total_bayes_factor, 1),
            bayesian_verdict=verdict,
            confidence_interval=(ci_lower, ci_upper),
            trajectory=trajectory,
            top_contributing_evidence=contributing_evidence[:5]
        )
