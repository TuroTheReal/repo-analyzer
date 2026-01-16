"""
Unified security score calculator with equitable weighting.

PRINCIPE ÉQUITABLE:
- Les sections non applicables (N/A) ne pénalisent pas le score
- Pas de Docker ? → Section Docker = N/A, pas 0/100
- Le score global est calculé sur les sections APPLICABLES uniquement
- Transparence: chaque section indique son statut (applicable, N/A, partial)

SECTIONS:
1. Security (secrets + CVE) - Toujours applicable
2. Docker - Applicable SI Dockerfiles présents
3. Best Practices - Toujours applicable (mais adaptatif)
4. Dependencies - Applicable SI fichiers de dépendances présents
"""

from typing import Dict, List, Optional

# === SCORING CONSTANTS ===
# Poids par défaut (recalculés dynamiquement si sections N/A)
DEFAULT_WEIGHT_SECURITY = 0.50  # 50%
DEFAULT_WEIGHT_DOCKER = 0.20  # 20%
DEFAULT_WEIGHT_BEST_PRACTICES = 0.15  # 15%
DEFAULT_WEIGHT_DEPENDENCIES = 0.15  # 15%

# Severity penalties
PENALTY_CRITICAL = 15
PENALTY_HIGH = 8
PENALTY_MEDIUM = 4
PENALTY_LOW = 1
PENALTY_INFO = 0.5

# Best practices points (total = 100)
POINTS_TESTS_BASE = 25
POINTS_TESTS_QUALITY = 10
POINTS_CI_CD = 30
POINTS_GITIGNORE = 20
POINTS_NO_SECRETS = 15

# Status constants
STATUS_APPLICABLE = 'applicable'
STATUS_NOT_APPLICABLE = 'not_applicable'
STATUS_PARTIAL = 'partial'


class SecurityScoreCalculator:
    """Calculates unified security score with equitable weighting."""

    def calculate_unified_score(
        self,
        security_results: Dict,
        docker_results: Dict,
        structure: Dict,
        has_github_data: bool = True
    ) -> Dict:
        """
        Calculate unified score with equitable weighting.

        Sections non applicables ne pénalisent pas le score.

        Args:
            security_results: Results from vulnerability cascade
            docker_results: Results from DockerScanner
            structure: Repository structure info
            has_github_data: Boolean indicating if GitHub API data is available

        Returns:
            dict: Complete scoring breakdown with section applicability
        """
        # Déterminer quelles sections sont applicables
        sections = self._determine_applicable_sections(
            security_results, docker_results, structure
        )

        # Calculer les scores par section
        scores = {}

        # 1. Security (secrets + CVE) - Toujours applicable
        scores['security'] = self._calculate_security_score(security_results)

        # 2. Docker - Applicable si Dockerfiles présents
        if sections['docker']['status'] == STATUS_APPLICABLE:
            scores['docker'] = self._calculate_docker_score(docker_results)
        else:
            scores['docker'] = None  # N/A

        # 3. Best Practices - Toujours applicable
        scores['best_practices'] = self._calculate_best_practices_score(
            security_results, structure
        )

        # 4. Dependencies - Applicable si dépendances présentes
        if sections['dependencies']['status'] == STATUS_APPLICABLE:
            scores['dependencies'] = self._calculate_dependencies_score(security_results)
        else:
            scores['dependencies'] = None  # N/A

        # Calculer les poids dynamiques (redistribuer si sections N/A)
        weights = self._calculate_dynamic_weights(sections)

        # Calculer le score total pondéré
        total_score = self._calculate_weighted_total(scores, weights)
        total_score = round(max(0, min(100, total_score)))

        # Grade
        grade = self._calculate_grade(total_score)

        # Construire le breakdown détaillé
        breakdown = self._build_breakdown(
            scores, weights, sections, security_results, docker_results
        )

        # Description
        description = self._get_score_description(total_score)
        if not has_github_data:
            description += " (Local analysis - limited metadata)"

        # Ajouter info sur les sources de scan
        scan_sources = security_results.get('sources', [])
        recommendations = security_results.get('recommendations', [])

        return {
            'total_score': total_score,
            'grade': grade,
            'scores': scores,
            'weights': weights,
            'sections': sections,
            'breakdown': breakdown,
            'description': description,
            'is_local_analysis': not has_github_data,
            'scan_sources': scan_sources,
            'recommendations': recommendations,
            # Compatibilité avec l'ancien format
            'security_score': scores['security'],
            'docker_score': scores['docker'] if scores['docker'] is not None else 'N/A',
            'best_practices_score': scores['best_practices']
        }

    def _determine_applicable_sections(
        self,
        security_results: Dict,
        docker_results: Dict,
        structure: Dict
    ) -> Dict:
        """
        Détermine quelles sections sont applicables pour ce repo.

        Returns:
            dict: Statut de chaque section
        """
        sections = {}

        # Security - Toujours applicable
        sections['security'] = {
            'status': STATUS_APPLICABLE,
            'reason': 'Always applicable - scans for secrets and vulnerabilities'
        }

        # Docker - Applicable si Dockerfiles présents
        has_docker = bool(
            docker_results.get('dockerfiles') or
            docker_results.get('compose_files')
        )
        if has_docker:
            sections['docker'] = {
                'status': STATUS_APPLICABLE,
                'reason': f"Found {len(docker_results.get('dockerfiles', []))} Dockerfile(s)"
            }
        else:
            sections['docker'] = {
                'status': STATUS_NOT_APPLICABLE,
                'reason': 'No Docker configuration detected'
            }

        # Best Practices - Toujours applicable
        sections['best_practices'] = {
            'status': STATUS_APPLICABLE,
            'reason': 'Always applicable - checks tests, CI/CD, .gitignore'
        }

        # Dependencies - Applicable si fichiers de dépendances présents
        has_deps = bool(structure.get('dependencies', {}))
        # Ou vérifier dans security_results s'il y a des vulnérabilités de dépendances
        has_dep_vulns = any(
            alert.get('type') in ['vulnerability', 'dependency_vulnerability']
            for severity in ['critical', 'high', 'medium', 'low']
            for alert in security_results.get(severity, [])
        )

        if has_deps or has_dep_vulns:
            sections['dependencies'] = {
                'status': STATUS_APPLICABLE,
                'reason': 'Dependency files detected'
            }
        else:
            sections['dependencies'] = {
                'status': STATUS_NOT_APPLICABLE,
                'reason': 'No dependency files detected'
            }

        return sections

    def _calculate_dynamic_weights(self, sections: Dict) -> Dict:
        """
        Calcule les poids dynamiques en fonction des sections applicables.

        Si une section est N/A, son poids est redistribué aux autres.
        """
        # Commencer avec les poids par défaut
        weights = {
            'security': DEFAULT_WEIGHT_SECURITY,
            'docker': DEFAULT_WEIGHT_DOCKER,
            'best_practices': DEFAULT_WEIGHT_BEST_PRACTICES,
            'dependencies': DEFAULT_WEIGHT_DEPENDENCIES
        }

        # Identifier les sections N/A
        na_sections = [
            name for name, info in sections.items()
            if info['status'] == STATUS_NOT_APPLICABLE
        ]

        if not na_sections:
            return weights

        # Calculer le poids total à redistribuer
        weight_to_redistribute = sum(weights[name] for name in na_sections)

        # Mettre les sections N/A à 0
        for name in na_sections:
            weights[name] = 0.0

        # Redistribuer proportionnellement aux sections actives
        active_sections = [
            name for name in weights.keys()
            if name not in na_sections
        ]

        if active_sections:
            total_active = sum(weights[name] for name in active_sections)
            for name in active_sections:
                proportion = weights[name] / total_active
                weights[name] += weight_to_redistribute * proportion

        # Normaliser pour s'assurer que la somme = 1.0
        total = sum(weights.values())
        if total > 0:
            weights = {k: v / total for k, v in weights.items()}

        return weights

    def _calculate_weighted_total(self, scores: Dict, weights: Dict) -> float:
        """Calcule le score total pondéré."""
        total = 0.0

        for section, score in scores.items():
            if score is not None:  # Ignorer les sections N/A
                total += score * weights.get(section, 0)

        return total

    def _calculate_security_score(self, security_results: Dict) -> int:
        """
        Calculate security score (secrets + CVE) out of 100.

        Compte uniquement les secrets et fichiers sensibles.
        Les vulnérabilités CVE sont comptées séparément dans dependencies.
        """
        score = 100

        # Compter uniquement les secrets (pas les CVE)
        for severity in ['critical', 'high', 'medium', 'low']:
            for alert in security_results.get(severity, []):
                alert_type = alert.get('type', '')

                # Secrets et fichiers sensibles
                if alert_type in ['secret_exposed', 'sensitive_file']:
                    if severity == 'critical':
                        score -= PENALTY_CRITICAL
                    elif severity == 'high':
                        score -= PENALTY_HIGH
                    elif severity == 'medium':
                        score -= PENALTY_MEDIUM
                    elif severity == 'low':
                        score -= PENALTY_LOW

        # Pénalité supplémentaire si beaucoup de secrets critiques
        critical_secrets = sum(
            1 for alert in security_results.get('critical', [])
            if alert.get('type') == 'secret_exposed'
        )
        if critical_secrets >= 3:
            score -= 10

        return max(0, score)

    def _calculate_docker_score(self, docker_results: Dict) -> int:
        """Calculate Docker score out of 100."""
        score = 100

        score -= len(docker_results.get('critical', [])) * PENALTY_CRITICAL
        score -= len(docker_results.get('high', [])) * PENALTY_HIGH
        score -= len(docker_results.get('medium', [])) * PENALTY_MEDIUM
        score -= len(docker_results.get('low', [])) * PENALTY_LOW
        score -= len(docker_results.get('info', [])) * PENALTY_INFO

        return max(0, int(score))

    def _calculate_dependencies_score(self, security_results: Dict) -> int:
        """
        Calculate dependencies/CVE score out of 100.

        Compte les vulnérabilités CVE (Trivy, auditors, OSV).
        """
        score = 100

        for severity in ['critical', 'high', 'medium', 'low']:
            for alert in security_results.get(severity, []):
                alert_type = alert.get('type', '')

                # Vulnérabilités de dépendances
                if alert_type in ['vulnerability', 'dependency_vulnerability']:
                    if severity == 'critical':
                        score -= PENALTY_CRITICAL
                    elif severity == 'high':
                        score -= PENALTY_HIGH
                    elif severity == 'medium':
                        score -= PENALTY_MEDIUM
                    elif severity == 'low':
                        score -= PENALTY_LOW

        return max(0, score)

    def _calculate_best_practices_score(
        self,
        security_results: Dict,
        structure: Dict
    ) -> int:
        """Calculate best practices score out of 100."""
        score = 0

        # Tests present (up to 35 points)
        if structure.get('has_tests'):
            score += POINTS_TESTS_BASE

            test_quality = structure.get('test_quality', 'unknown')
            quality_bonus = {
                'extensive': 10,
                'good': 7,
                'basic': 4,
                'minimal': 2,
                'empty': 0,
                'unknown': 5
            }
            score += quality_bonus.get(test_quality, 5)

        # CI/CD configured (+30 points)
        if structure.get('has_ci'):
            score += POINTS_CI_CD

        # Proper .gitignore (+20 points)
        has_proper_gitignore = not any(
            a.get('type') in ['incomplete_gitignore', 'missing_gitignore']
            for a in security_results.get('low', [])
        )
        if has_proper_gitignore:
            score += POINTS_GITIGNORE

        # No exposed secrets (+15 points)
        no_secrets = not any(
            a.get('type') == 'secret_exposed'
            for a in security_results.get('critical', []) + security_results.get('high', [])
        )
        if no_secrets:
            score += POINTS_NO_SECRETS

        return min(100, score)

    def _build_breakdown(
        self,
        scores: Dict,
        weights: Dict,
        sections: Dict,
        security_results: Dict,
        docker_results: Dict
    ) -> Dict:
        """Construit le breakdown détaillé pour les rapports."""
        breakdown = {}

        # Security
        breakdown['security'] = {
            'score': scores['security'],
            'weight': int(weights['security'] * 100),
            'status': sections['security']['status'],
            'reason': sections['security']['reason'],
            'details': {
                'secrets_critical': sum(
                    1 for a in security_results.get('critical', [])
                    if a.get('type') == 'secret_exposed'
                ),
                'secrets_high': sum(
                    1 for a in security_results.get('high', [])
                    if a.get('type') == 'secret_exposed'
                ),
                'sensitive_files': sum(
                    1 for a in security_results.get('high', []) + security_results.get('medium', [])
                    if a.get('type') == 'sensitive_file'
                )
            }
        }

        # Docker
        if scores['docker'] is not None:
            breakdown['docker'] = {
                'score': scores['docker'],
                'weight': int(weights['docker'] * 100),
                'status': sections['docker']['status'],
                'reason': sections['docker']['reason'],
                'details': {
                    'critical': len(docker_results.get('critical', [])),
                    'high': len(docker_results.get('high', [])),
                    'medium': len(docker_results.get('medium', [])),
                    'low': len(docker_results.get('low', [])),
                    'info': len(docker_results.get('info', []))
                }
            }
        else:
            breakdown['docker'] = {
                'score': 'N/A',
                'weight': 0,
                'status': sections['docker']['status'],
                'reason': sections['docker']['reason'],
                'details': {}
            }

        # Best Practices
        breakdown['best_practices'] = {
            'score': scores['best_practices'],
            'weight': int(weights['best_practices'] * 100),
            'status': sections['best_practices']['status'],
            'reason': sections['best_practices']['reason']
        }

        # Dependencies
        if scores['dependencies'] is not None:
            breakdown['dependencies'] = {
                'score': scores['dependencies'],
                'weight': int(weights['dependencies'] * 100),
                'status': sections['dependencies']['status'],
                'reason': sections['dependencies']['reason'],
                'details': {
                    'cve_critical': sum(
                        1 for a in security_results.get('critical', [])
                        if a.get('type') in ['vulnerability', 'dependency_vulnerability']
                    ),
                    'cve_high': sum(
                        1 for a in security_results.get('high', [])
                        if a.get('type') in ['vulnerability', 'dependency_vulnerability']
                    ),
                    'cve_medium': sum(
                        1 for a in security_results.get('medium', [])
                        if a.get('type') in ['vulnerability', 'dependency_vulnerability']
                    ),
                    'cve_low': sum(
                        1 for a in security_results.get('low', [])
                        if a.get('type') in ['vulnerability', 'dependency_vulnerability']
                    )
                }
            }
        else:
            breakdown['dependencies'] = {
                'score': 'N/A',
                'weight': 0,
                'status': sections['dependencies']['status'],
                'reason': sections['dependencies']['reason'],
                'details': {}
            }

        return breakdown

    def _calculate_grade(self, score: int) -> str:
        """Return letter grade based on score."""
        if score >= 95:
            return 'A+'
        elif score >= 90:
            return 'A'
        elif score >= 85:
            return 'A-'
        elif score >= 80:
            return 'B+'
        elif score >= 75:
            return 'B'
        elif score >= 70:
            return 'B-'
        elif score >= 65:
            return 'C+'
        elif score >= 60:
            return 'C'
        elif score >= 55:
            return 'C-'
        elif score >= 50:
            return 'D'
        else:
            return 'F'

    def _get_score_description(self, score: int) -> str:
        """Return human-readable description based on score."""
        if score >= 90:
            return "Excellent! Very few security issues detected."
        elif score >= 75:
            return "Good. Some improvements recommended."
        elif score >= 60:
            return "Average. Several issues need attention."
        elif score >= 40:
            return "Below average. Important issues to fix."
        else:
            return "⚠️ CRITICAL! Major security problems detected."
