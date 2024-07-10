from django.shortcuts import get_object_or_404
from rest_framework import viewsets, status
from rest_framework.decorators import action

from apps.users.models import User

from .tasks import initiate_zap_scan

from .models.zap_models import ZAPCredential, ZAPReport, ZAPReportsList
from .serializers import (
    CodeLevelCategorySerializer,
    CodeLevelVulnerabilityDetailSerializer,
    CodeLevelVulnerabilitySerializer,
    CodeQualityAnalyzerDetailSerializer,
    CodeQualityAnalyzerPeriodicScanSerializer,
    CodeQualityAnalyzerRuleSetSerializer,
    CodeQualityAnalyzerSerializer,
    CredentialExposureDetailSerializer,
    CredentialExposureSerializer,
    IssuesSummary,
    JiraTicketTrackerSerializer,
    JiraTicketTrackerUpdateSerializer,
    LicenseExposureDetailSerializer,
    LicenseExposureSerializer,
    CreatePeriodicScanSerializer,
    PeriodicScanSerializer,
    ScanIssueSerializer,
    ScanListSerializer,
    ScanSerializer,
    VulnerablePackageSerializer,
    VulnerabilityQueryParamsSerializer,
    VulnerablePackageDetailSerializer,
    PeriodicScanListSerializer,
    SASTReportSerializer,
    SASTReportDownloadSerializer,
    SourceCodeQualityAnalyzerReportSerializer,
    CombinedVulnerabilityAlertSerializer,
    AIVAParamSerializer,
    ZAPCredentialSerializer,
    ZAPReportDownloadSerializer,
    ZAPReportSerializer,
    ZAPReportsListSerializer,
)
from .models import (
    CodeLevelVulnerability,
    CodeQualityAnalyserScanAlerts,
    CredentialExposure,
    LicenseExposure,
    Scan,
    ScanIssue,
    VulnerablePackage,
    SeverityKind,
    SCAN_INTERVALS,
    PeriodicScan,
    ScanStatus,
    ScanIssue,
)
from .models.sast_report import SASTReport
from .models.jira_tickets import JiraTicketTracker
from rest_framework.response import Response
from rest_framework.exceptions import ValidationError
from rest_framework.filters import SearchFilter, OrderingFilter
from apps.core.viewsets import BaseModelViewSet, StandardResultsSetPagination
from django.db.models import Count, Q, F, IntegerField, Value, When, Case, CharField, Sum
from django.db.models import Count, Q, Subquery, OuterRef
from django.db.models.functions import Coalesce
from .filter import VulnerabilitiesFilterBackend, ZapFilterBackend
from .services.sast_report_services import get_sast_report_url
from .models.scqa_report import SCQAReport
from .services.scqa_report_services import get_scqa_report_url
from .services.zap import get_dast_report_url, remove_duplicates
from .services.ai_va_services import get_vulnerabilities_rank, get_vulnerabilities_recommendation_cost
from django.shortcuts import get_object_or_404
from itertools import chain
from constants.scan_issues_categories import CODE_VULNERABILITY, CODE_QUALITY, LANG_PKGS, LICENSE, CREDENTIAL
from .services.hashing_unique_services import hashing_values


class ScanViewSet(BaseModelViewSet):
    serializer_class = ScanSerializer
    queryset = Scan.objects.filter(is_periodic=False)
    filterset_fields = ['repo__url', 'branch']
    search_fields = ['repo__name', 'branch']

    def get_queryset(self):
        if self.action == 'list':
            queryset = Scan.objects.filter(is_periodic=False)
            queryset = self.filter_queryset(queryset)
            vulnerable_high_subquery = (
                VulnerablePackage.objects.filter(scan=OuterRef('pk'), severity=SeverityKind.HIGH)
                .values('scan')
                .annotate(count=Count('id'))
                .values('count')
            )

            # Subquery to count high severity CodeLevelVulnerability
            code_high_subquery = (
                CodeLevelVulnerability.objects.filter(scan=OuterRef('pk'), severity=SeverityKind.HIGH)
                .values('scan')
                .annotate(count=Count('id'))
                .values('count')
            )
            # CredentialExposure
            credential_high_subquery = (
                CredentialExposure.objects.filter(scan=OuterRef('pk'), severity=SeverityKind.HIGH)
                .values('scan')
                .annotate(count=Count('id'))
                .values('count')
            )

            # LicenseExposure
            license_high_subquery = (
                LicenseExposure.objects.filter(scan=OuterRef('pk'), severity=SeverityKind.HIGH)
                .values('scan')
                .annotate(count=Count('id'))
                .values('count')
            )

            # Source Code Quality Analyzer
            scqa_high_subquery = (
                CodeQualityAnalyserScanAlerts.objects.filter(scan=OuterRef('pk'), severity=SeverityKind.HIGH)
                .values('scan')
                .annotate(count=Count('id'))
                .values('count')
            )

            vulnerable_medium_subquery = (
                VulnerablePackage.objects.filter(scan=OuterRef('pk'), severity=SeverityKind.MEDIUM)
                .values('scan')
                .annotate(count=Count('id'))
                .values('count')
            )

            # Subquery to count high severity CodeLevelVulnerability
            code_medium_subquery = (
                CodeLevelVulnerability.objects.filter(scan=OuterRef('pk'), severity=SeverityKind.MEDIUM)
                .values('scan')
                .annotate(count=Count('id'))
                .values('count')
            )

            # CredentialExposure
            credential_medium_subquery = (
                CredentialExposure.objects.filter(scan=OuterRef('pk'), severity=SeverityKind.MEDIUM)
                .values('scan')
                .annotate(count=Count('id'))
                .values('count')
            )

            # LicenseExposure
            license_medium_subquery = (
                LicenseExposure.objects.filter(scan=OuterRef('pk'), severity=SeverityKind.MEDIUM)
                .values('scan')
                .annotate(count=Count('id'))
                .values('count')
            )

            # Source Code Quality Analyzer
            scqa_medium_subquery = (
                CodeQualityAnalyserScanAlerts.objects.filter(scan=OuterRef('pk'), severity=SeverityKind.MEDIUM)
                .values('scan')
                .annotate(count=Count('id'))
                .values('count')
            )

            vulnerable_low_subquery = (
                VulnerablePackage.objects.filter(scan=OuterRef('pk'), severity=SeverityKind.LOW)
                .values('scan')
                .annotate(count=Count('id'))
                .values('count')
            )

            # Subquery to count high severity CodeLevelVulnerability
            code_low_subquery = (
                CodeLevelVulnerability.objects.filter(scan=OuterRef('pk'), severity=SeverityKind.LOW)
                .values('scan')
                .annotate(count=Count('id'))
                .values('count')
            )

            # CredentialExposure
            credential_low_subquery = (
                CredentialExposure.objects.filter(scan=OuterRef('pk'), severity=SeverityKind.LOW)
                .values('scan')
                .annotate(count=Count('id'))
                .values('count')
            )

            # LicenseExposure
            license_low_subquery = (
                LicenseExposure.objects.filter(scan=OuterRef('pk'), severity=SeverityKind.LOW)
                .values('scan')
                .annotate(count=Count('id'))
                .values('count')
            )

            # Source Code Quality Analyzer
            scqa_low_subquery = (
                CodeQualityAnalyserScanAlerts.objects.filter(scan=OuterRef('pk'), severity=SeverityKind.LOW)
                .values('scan')
                .annotate(count=Count('id'))
                .values('count')
            )

            vulnerable_unknown_subquery = (
                VulnerablePackage.objects.filter(scan=OuterRef('pk'), severity=SeverityKind.UNKNOWN)
                .values('scan')
                .annotate(count=Count('id'))
                .values('count')
            )

            # Subquery to count high severity CodeLevelVulnerability
            code_unknown_subquery = (
                CodeLevelVulnerability.objects.filter(scan=OuterRef('pk'), severity=SeverityKind.UNKNOWN)
                .values('scan')
                .annotate(count=Count('id'))
                .values('count')
            )

            # CredentialExposure
            credential_unknown_subquery = (
                CredentialExposure.objects.filter(scan=OuterRef('pk'), severity=SeverityKind.UNKNOWN)
                .values('scan')
                .annotate(count=Count('id'))
                .values('count')
            )

            # LicenseExposure
            license_unknown_subquery = (
                LicenseExposure.objects.filter(scan=OuterRef('pk'), severity=SeverityKind.UNKNOWN)
                .values('scan')
                .annotate(count=Count('id'))
                .values('count')
            )

            # Source Code Quality Analyzer
            scqa_unknown_subquery = (
                CodeQualityAnalyserScanAlerts.objects.filter(scan=OuterRef('pk'), severity=SeverityKind.UNKNOWN)
                .values('scan')
                .annotate(count=Count('id'))
                .values('count')
            )

            # Annotate the counts using the subqueries
            queryset = queryset.annotate(
                vulnerable_high=Coalesce(Subquery(vulnerable_high_subquery, output_field=IntegerField()), Value(0)),
                code_high=Coalesce(Subquery(code_high_subquery, output_field=IntegerField()), Value(0)),
                cred_high=Coalesce(Subquery(credential_high_subquery, output_field=IntegerField()), Value(0)),
                license_high=Coalesce(Subquery(license_high_subquery, output_field=IntegerField()), Value(0)),
                scqa_high=Coalesce(Subquery(scqa_high_subquery, output_field=IntegerField()), Value(0)),
                vulnerable_medium=Coalesce(Subquery(vulnerable_medium_subquery, output_field=IntegerField()), Value(0)),
                code_medium=Coalesce(Subquery(code_medium_subquery, output_field=IntegerField()), Value(0)),
                cred_medium=Coalesce(Subquery(credential_medium_subquery, output_field=IntegerField()), Value(0)),
                license_medium=Coalesce(Subquery(license_medium_subquery, output_field=IntegerField()), Value(0)),
                scqa_medium=Coalesce(Subquery(scqa_medium_subquery, output_field=IntegerField()), Value(0)),
                vulnerable_low=Coalesce(Subquery(vulnerable_low_subquery, output_field=IntegerField()), Value(0)),
                code_low=Coalesce(Subquery(code_low_subquery, output_field=IntegerField()), Value(0)),
                cred_low=Coalesce(Subquery(credential_low_subquery, output_field=IntegerField()), Value(0)),
                license_low=Coalesce(Subquery(license_low_subquery, output_field=IntegerField()), Value(0)),
                scqa_low=Coalesce(Subquery(scqa_low_subquery, output_field=IntegerField()), Value(0)),
                vulnerable_unknown=Coalesce(
                    Subquery(vulnerable_unknown_subquery, output_field=IntegerField()), Value(0)
                ),
                code_unknown=Coalesce(Subquery(code_unknown_subquery, output_field=IntegerField()), Value(0)),
                cred_unknown=Coalesce(Subquery(credential_unknown_subquery, output_field=IntegerField()), Value(0)),
                license_unknown=Coalesce(Subquery(license_unknown_subquery, output_field=IntegerField()), Value(0)),
                scqa_unknown=Coalesce(Subquery(scqa_unknown_subquery, output_field=IntegerField()), Value(0)),
                high=Coalesce(
                    F('code_high') + F('vulnerable_high') + F('cred_high') + F('license_high') + F('scqa_high'),
                    Value(0),
                ),
                medium=Coalesce(
                    F('code_medium')
                    + F('vulnerable_medium')
                    + F('cred_medium')
                    + F('license_medium')
                    + F('scqa_medium'),
                    Value(0),
                ),
                low=Coalesce(
                    F('code_low') + F('vulnerable_low') + F('cred_low') + F('license_low') + F('scqa_low'), Value(0)
                ),
                unknown=Coalesce(
                    F('code_unknown')
                    + F('vulnerable_unknown')
                    + F('cred_unknown')
                    + F('license_unknown')
                    + F('scqa_unknown'),
                    Value(0),
                ),
            )
            return queryset.order_by('-updated_at')
        return super().get_queryset()

    def get_serializer_class(self):
        if self.action == 'list':
            return ScanListSerializer
        return super().get_serializer_class()

    def list(self, request, *args, **kwargs):
        return super().list(request, *args, **kwargs)


class VulnerablePackageViewSet(BaseModelViewSet):
    serializer_class = VulnerablePackageSerializer
    queryset = VulnerablePackage.objects.all().order_by('-severity')
    # filterset_fields = ['scan', 'scan__repo__url', 'scan__branch', 'severity']
    filter_backends = [VulnerabilitiesFilterBackend]
    ordering_fields = ['library', 'file', 'severity', 'installed_version', 'fixed_version', 'vulnerability_id']

    def get_serializer_class(self):
        if self.action == 'retrieve':
            return VulnerablePackageDetailSerializer
        return super().get_serializer_class()

    def list(self, request, *args, **kwargs):
        serializer = VulnerabilityQueryParamsSerializer(data=request.GET)
        serializer.is_valid(raise_exception=True)

        scan_id = serializer.data.get('scan')
        queryset = VulnerablePackage.objects.filter(scan__id=scan_id).aggregate(
            high=Count('severity', filter=Q(severity=SeverityKind.HIGH)),
            medium=Count('severity', filter=Q(severity=SeverityKind.MEDIUM)),
            low=Count('severity', filter=Q(severity=SeverityKind.LOW)),
            unknown=Count('severity', filter=Q(severity=SeverityKind.UNKNOWN)),
        )
        response = super().list(request, *args, **kwargs)
        response.data['severity_count'] = {
            'HIGH': queryset['high'],
            'MEDIUM': queryset['medium'],
            'LOW': queryset['low'],
            'UNKNOWN': queryset['unknown'],
        }
        return response


class CodeLevelVulnerabilityViewSet(BaseModelViewSet):
    serializer_class = CodeLevelVulnerabilitySerializer
    queryset = CodeLevelVulnerability.objects.all().order_by('-severity')
    # filterset_fields = ['scan', 'scan__repo__url', 'scan__branch', 'severity', 'category']
    filter_backends = [VulnerabilitiesFilterBackend]
    ordering_fields = ['library', 'file', 'severity', 'installed_version', 'fixed_version', 'vulnerability_id']

    def get_serializer_class(self):
        if self.action == 'retrieve':
            return CodeLevelVulnerabilityDetailSerializer
        return super().get_serializer_class()

    def list(self, request, *args, **kwargs):
        serializer = VulnerabilityQueryParamsSerializer(data=request.GET)
        serializer.is_valid(raise_exception=True)

        scan_id = serializer.data.get('scan')
        category = serializer.data.get('category')
        queryset = CodeLevelVulnerability.objects.filter(scan__id=scan_id)
        if category:
            queryset = queryset.filter(category=category)
        queryset = queryset.aggregate(
            # critical = Count('severity', filter=Q(severity=SeverityKind.CRITICAL)),
            high=Count('severity', filter=Q(severity=SeverityKind.HIGH)),
            medium=Count('severity', filter=Q(severity=SeverityKind.MEDIUM)),
            low=Count('severity', filter=Q(severity=SeverityKind.LOW)),
            unknown=Count('severity', filter=Q(severity=SeverityKind.UNKNOWN)),
        )

        response = super().list(request, *args, **kwargs)
        response.data['severity_count'] = {
            # 'CRITICAL': queryset['critical'],
            'HIGH': queryset['high'],
            'MEDIUM': queryset['medium'],
            'LOW': queryset['low'],
            'UNKNOWN': queryset['unknown'],
        }
        return response

    @action(['get'], detail=False, serializer_class=CodeLevelCategorySerializer)
    def category(self, request, *args, **kwargs):
        serializer = VulnerabilityQueryParamsSerializer(data=request.GET)
        if not serializer.is_valid():
            first_key = next(iter(serializer.errors.values()), None)
            raise ValidationError(str(first_key[0]))

        scan_id = serializer.data['scan']
        queryset = CodeLevelVulnerability.objects.filter(scan__id=scan_id)
        queryset = queryset.distinct('category')
        serializer = self.get_serializer(queryset, many=True)
        return Response({'results': serializer.data})


class CredentialExposureViewSet(BaseModelViewSet):
    serializer_class = CredentialExposureSerializer
    queryset = CredentialExposure.objects.all().order_by('-severity')
    # filterset_fields = ['scan', 'scan__repo__url', 'scan__branch', 'severity']
    filter_backends = [VulnerabilitiesFilterBackend]
    ordering_fields = ['id', 'filename', 'rule', 'severity', 'category', 'begin_line']

    def get_serializer_class(self):
        if self.action == 'retrieve':
            return CredentialExposureDetailSerializer
        return super().get_serializer_class()

    def list(self, request, *args, **kwargs):
        serializer = VulnerabilityQueryParamsSerializer(data=request.GET)
        serializer.is_valid(raise_exception=True)

        scan_id = serializer.data.get('scan')
        queryset = CredentialExposure.objects.filter(scan__id=scan_id).aggregate(
            # critical = Count('severity', filter=Q(severity=SeverityKind.CRITICAL)),
            high=Count('severity', filter=Q(severity=SeverityKind.HIGH)),
            medium=Count('severity', filter=Q(severity=SeverityKind.MEDIUM)),
            low=Count('severity', filter=Q(severity=SeverityKind.LOW)),
            unknown=Count('severity', filter=Q(severity=SeverityKind.UNKNOWN)),
        )

        response = super().list(request, *args, **kwargs)
        response.data['severity_count'] = {
            # 'CRITICAL': queryset['critical'],
            'HIGH': queryset['high'],
            'MEDIUM': queryset['medium'],
            'LOW': queryset['low'],
            'UNKNOWN': queryset['unknown'],
        }
        return response


class LicenseExposureViewSet(BaseModelViewSet):
    serializer_class = LicenseExposureSerializer
    queryset = LicenseExposure.objects.order_by('-severity')
    # filterset_fields = ['scan', 'scan__repo__url', 'scan__branch', 'severity']
    filter_backends = [VulnerabilitiesFilterBackend]
    ordering_fields = ['id', 'package', 'license', 'severity', 'classification', 'filename']

    def get_serializer_class(self):
        if self.action == 'retrieve':
            return LicenseExposureDetailSerializer
        return super().get_serializer_class()

    def list(self, request, *args, **kwargs):
        serializer = VulnerabilityQueryParamsSerializer(data=request.GET)
        serializer.is_valid(raise_exception=True)

        scan_id = serializer.data.get('scan')
        queryset = LicenseExposure.objects.filter(scan__id=scan_id).aggregate(
            # critical = Count('severity', filter=Q(severity=SeverityKind.CRITICAL)),
            high=Count('severity', filter=Q(severity=SeverityKind.HIGH)),
            medium=Count('severity', filter=Q(severity=SeverityKind.MEDIUM)),
            low=Count('severity', filter=Q(severity=SeverityKind.LOW)),
            unknown=Count('severity', filter=Q(severity=SeverityKind.UNKNOWN)),
        )

        response = super().list(request, *args, **kwargs)
        response.data['severity_count'] = {
            # 'CRITICAL': queryset['critical'],
            'HIGH': queryset['high'],
            'MEDIUM': queryset['medium'],
            'LOW': queryset['low'],
            'UNKNOWN': queryset['unknown'],
        }
        return response


class PeriodicScanViewSet(BaseModelViewSet):
    serializer_class = CreatePeriodicScanSerializer
    queryset = PeriodicScan.objects.all()
    filterset_fields = ['interval']
    search_fields = ['repo__name', 'branch']

    def get_queryset(self):
        from django.db.models import Value

        if self.action == 'list':
            # Subquery to get the updated_at from the latest periodic Scan model
            latest_scan_subquery = Scan.objects.filter(
                repo=OuterRef('repo'), branch=OuterRef('branch'), is_periodic=True, status=ScanStatus.COMPLETED
            ).order_by('-updated_at')

            latest_scan_updated_at = latest_scan_subquery.values('updated_at')[:1]
            latest_scan_id = latest_scan_subquery.values('id')[:1]
            lat_scan_id = Subquery(
                Scan.objects.filter(repo=OuterRef('repo'), is_periodic=True).order_by('-created_at').values('id')[:1]
            )

            queryset = PeriodicScan.objects.annotate(
                generated_on=Subquery(latest_scan_updated_at),
                scan_id=Subquery(latest_scan_id),
                # high=(
                #     Count(
                #         'repo__scans__vulnerable_packages__severity',
                #         filter=Q(repo__scans__id=Subquery(latest_scan_subquery.values('id')[:1])) & Q(repo__scans__vulnerable_packages__severity=SeverityKind.HIGH)
                #     ) + Count(
                #         'repo__scans__code_level_vulnerability__severity',
                #         filter=Q(repo__scans__id=Subquery(latest_scan_subquery.values('id')[:1])) & Q(repo__scans__code_level_vulnerability__severity=SeverityKind.HIGH)
                #     )
                # ),
                # medium=(
                #     Count(
                #         'repo__scans__vulnerable_packages__severity',
                #         filter=Q(repo__scans__id=Subquery(latest_scan_subquery.values('id')[:1])) & Q(repo__scans__vulnerable_packages__severity=SeverityKind.MEDIUM)
                #     ) + Count(
                #         'repo__scans__code_level_vulnerability__severity',
                #         filter=Q(repo__scans__id=Subquery(latest_scan_subquery.values('id')[:1])) & Q(repo__scans__code_level_vulnerability__severity=SeverityKind.MEDIUM)
                #     )
                # ),
                # low=(
                #     Count(
                #         'repo__scans__vulnerable_packages__severity',
                #         filter=Q(repo__scans__id=Subquery(latest_scan_subquery.values('id')[:1])) & Q(repo__scans__vulnerable_packages__severity=SeverityKind.LOW)
                #     ) + Count(
                #         'repo__scans__code_level_vulnerability__severity',
                #         filter=Q(repo__scans__id=Subquery(latest_scan_subquery.values('id')[:1])) & Q(repo__scans__code_level_vulnerability__severity=SeverityKind.LOW)
                #     )
                # ),
                # unknown=(
                #     Count(
                #         'repo__scans__vulnerable_packages__severity',
                #         filter=Q(repo__scans__id=Subquery(latest_scan_subquery.values('id')[:1])) & Q(repo__scans__vulnerable_packages__severity=SeverityKind.UNKNOWN)
                #     ) + Count(
                #         'repo__scans__code_level_vulnerability__severity',
                #         filter=Q(repo__scans__id=Subquery(latest_scan_subquery.values('id')[:1])) & Q(repo__scans__code_level_vulnerability__severity=SeverityKind.UNKNOWN)
                #     )
                # )
            )
            return queryset
        return super().get_queryset()

    def get_serializer_class(self):
        if self.action == 'list':
            return PeriodicScanSerializer
        return super().get_serializer_class()

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data, many=isinstance(request.data, list))
        serializer.is_valid(raise_exception=True)
        self.perform_create(serializer)
        headers = self.get_success_headers(serializer.data)
        return Response(serializer.data, status=status.HTTP_201_CREATED, headers=headers)

    def list(self, request, *args, **kwargs):
        return super().list(request, *args, **kwargs)

    @action(['get'], detail=False)
    def interval(self, request, *args, **kwargs):
        scan_intervals = [{'value': interval[0], 'name': interval[1]} for interval in SCAN_INTERVALS]
        return Response({'results': scan_intervals})


class CodeQualityAnalyzerViewSet(BaseModelViewSet):
    serializer_class = CodeQualityAnalyzerSerializer
    queryset = CodeQualityAnalyserScanAlerts.objects.all().order_by('-severity')
    filter_backends = [VulnerabilitiesFilterBackend]
    ordering_fields = [
        'id',
        'filename',
        'rule',
        'severity',
        'description',
        'begin_line',
        'rule_set',
        'column',
        'details',
    ]

    def get_serializer_class(self):
        if self.action == 'retrieve':
            return CodeQualityAnalyzerDetailSerializer
        return super().get_serializer_class()

    def list(self, request, *args, **kwargs):
        serializer = VulnerabilityQueryParamsSerializer(data=request.GET)
        serializer.is_valid(raise_exception=True)

        scan_id = serializer.data.get('scan')
        rule_set = serializer.data.get('rule_set')
        queryset = CodeQualityAnalyserScanAlerts.objects.filter(scan__id=scan_id)
        if rule_set:
            queryset = queryset.filter(rule_set=rule_set)
        queryset = queryset.aggregate(
            # critical = Count('severity', filter=Q(severity=SeverityKind.CRITICAL)),
            high=Count('severity', filter=Q(severity=SeverityKind.HIGH)),
            medium=Count('severity', filter=Q(severity=SeverityKind.MEDIUM)),
            low=Count('severity', filter=Q(severity=SeverityKind.LOW)),
            unknown=Count('severity', filter=Q(severity=SeverityKind.UNKNOWN)),
        )

        response = super().list(request, *args, **kwargs)
        response.data['severity_count'] = {
            # 'CRITICAL': queryset['critical'],
            'HIGH': queryset['high'],
            'MEDIUM': queryset['medium'],
            'LOW': queryset['low'],
            'UNKNOWN': queryset['unknown'],
        }
        return response

    @action(
        ['get'],
        detail=False,
        serializer_class=CodeQualityAnalyzerRuleSetSerializer,
        url_path='rule',
        url_name='rule-set-list',
    )
    def rule_set(self, request, *args, **kwargs):
        serializer = VulnerabilityQueryParamsSerializer(data=request.GET)
        if not serializer.is_valid():
            first_key = next(iter(serializer.errors.values()), None)
            raise ValidationError(str(first_key[0]))

        scan_id = serializer.data['scan']
        queryset = CodeQualityAnalyserScanAlerts.objects.filter(scan__id=scan_id)
        queryset = queryset.distinct('rule_set')
        serializer = self.get_serializer(queryset, many=True)
        return Response({'results': serializer.data})


class CodeQualityAnalyzerScanViewSet(BaseModelViewSet):
    serializer_class = ScanSerializer
    queryset = Scan.objects.filter(is_periodic=False)
    filterset_fields = ['repo__url', 'branch']
    search_fields = ['repo__name', 'branch']

    def get_queryset(self):
        if self.action == 'list':
            queryset = Scan.objects.filter(is_periodic=False)
            queryset = self.filter_queryset(queryset)
            code_quality_high_subquery = (
                CodeQualityAnalyserScanAlerts.objects.filter(scan=OuterRef('pk'), severity=SeverityKind.HIGH)
                .values('scan')
                .annotate(count=Count('id'))
                .values('count')
            )

            code_quality_medium_subquery = (
                CodeQualityAnalyserScanAlerts.objects.filter(scan=OuterRef('pk'), severity=SeverityKind.MEDIUM)
                .values('scan')
                .annotate(count=Count('id'))
                .values('count')
            )

            code_quality_low_subquery = (
                CodeQualityAnalyserScanAlerts.objects.filter(scan=OuterRef('pk'), severity=SeverityKind.LOW)
                .values('scan')
                .annotate(count=Count('id'))
                .values('count')
            )

            code_quality_unknown_subquery = (
                CodeQualityAnalyserScanAlerts.objects.filter(scan=OuterRef('pk'), severity=SeverityKind.UNKNOWN)
                .values('scan')
                .annotate(count=Count('id'))
                .values('count')
            )

            # Annotate the counts using the subqueries
            queryset = queryset.annotate(
                high=Coalesce(Subquery(code_quality_high_subquery, output_field=IntegerField()), Value(0)),
                medium=Coalesce(Subquery(code_quality_medium_subquery, output_field=IntegerField()), Value(0)),
                low=Coalesce(Subquery(code_quality_low_subquery, output_field=IntegerField()), Value(0)),
                unknown=Coalesce(Subquery(code_quality_unknown_subquery, output_field=IntegerField()), Value(0)),
            )
            return queryset.order_by('-updated_at')
        return super().get_queryset()

    def get_serializer_class(self):
        if self.action == 'list':
            return ScanListSerializer
        return super().get_serializer_class()

    def list(self, request, *args, **kwargs):
        return super().list(request, *args, **kwargs)


class PeriodicScanCodeQualityAnalyzerViewSet(BaseModelViewSet):
    serializer_class = CreatePeriodicScanSerializer
    queryset = PeriodicScan.objects.all()
    filterset_fields = ['interval']
    search_fields = ['repo__name', 'branch']

    def get_queryset(self):
        from django.db.models import Value

        if self.action == 'list':
            # Subquery to get the updated_at from the latest periodic Scan model
            latest_scan_subquery = Scan.objects.filter(
                repo=OuterRef('repo'), branch=OuterRef('branch'), is_periodic=True
            ).order_by('-updated_at')

            latest_scan_updated_at = latest_scan_subquery.values('updated_at')[:1]
            latest_scan_id = latest_scan_subquery.values('id')[:1]
            lat_scan_id = Subquery(
                Scan.objects.filter(repo=OuterRef('repo'), is_periodic=True).order_by('-created_at').values('id')[:1]
            )

            queryset = PeriodicScan.objects.annotate(
                generated_on=Subquery(latest_scan_updated_at),
                scan_id=Subquery(latest_scan_id),
            )
            return queryset
        return super().get_queryset()

    def get_serializer_class(self):
        if self.action == 'list':
            return CodeQualityAnalyzerPeriodicScanSerializer
        return super().get_serializer_class()

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data, many=isinstance(request.data, list))
        serializer.is_valid(raise_exception=True)
        self.perform_create(serializer)
        headers = self.get_success_headers(serializer.data)
        return Response(serializer.data, status=status.HTTP_201_CREATED, headers=headers)

    def list(self, request, *args, **kwargs):
        return super().list(request, *args, **kwargs)

    @action(['get'], detail=False)
    def interval(self, request, *args, **kwargs):
        scan_intervals = [{'value': interval[0], 'name': interval[1]} for interval in SCAN_INTERVALS]
        return Response({'results': scan_intervals})


class AllScanViewSet(BaseModelViewSet):
    serializer_class = ScanSerializer
    queryset = Scan.objects.filter().order_by('-updated_at')
    filterset_fields = ['repo__url', 'branch']
    search_fields = ['repo__name', 'branch']


class SASTReportViewSet(BaseModelViewSet):
    serializer_class = SASTReportSerializer
    queryset = SASTReport.objects.filter().order_by('-updated_at')
    filterset_fields = ['scan__repo__url', 'scan__branch', 'file_name']
    search_fields = ['scan__repo__url', 'scan__branch', 'file_name']

    @action(['get'], detail=False)
    def download(self, request, *args, **kwargs):
        serializer = SASTReportDownloadSerializer(data=request.GET)
        serializer.is_valid(raise_exception=True)
        filename = serializer.data.get('filename')
        response = get_sast_report_url(filename, request.tenant.uid)
        return Response({'results': response})


class ScanIssueViewSet(BaseModelViewSet):
    queryset = Scan.objects.all()
    serializer_class = ScanSerializer

    def retrieve(self, request, *args, **kwargs):
        scan = self.get_object()

        # Get parameters from the request
        severity_param = request.query_params.get('severity', '')
        exposure_category_param = request.query_params.get('category', '')
        sort_field = request.query_params.get('sort_field', '')
        sort_order_val = request.query_params.get('sort_order', 'asc').lower()  # asc, desc
        search_param = request.query_params.get('search', '')
        if sort_order_val == 'asc':
            sort_order = 'ascending'
        else:
            sort_order = 'descending'

        # Map severity string to SeverityKind value
        severity_mapping = {label.upper(): value for value, label in SeverityKind.choices}
        severity_value = severity_mapping.get(severity_param.upper(), None)

        # Get vulnerabilities related to the scan
        code_vulnerabilities = (
            CodeLevelVulnerability.objects.filter(scan=scan)
            .annotate(
                line=F('line_number'),
                severity_level=F('severity'),
                file_name=F('filename'),
                exposure_category=F('category'),
                code_vulnerability_id=F('id'),
            )
            .values('line', 'severity_level', 'file_name', 'exposure_category', 'code_vulnerability_id')
        )

        # Get alerts related to the scan
        code_alerts = (
            CodeQualityAnalyserScanAlerts.objects.filter(scan=scan)
            .annotate(
                line=F('begin_line'),
                severity_level=F('severity'),
                file_name=F('filename'),
                exposure_category=F('rule'),
                code_alert_id=F('id'),
            )
            .values('line', 'severity_level', 'file_name', 'exposure_category', 'code_alert_id')
        )

        # Get credential exposures related to the scan
        credential_exposures = (
            CredentialExposure.objects.filter(scan=scan)
            .annotate(
                line=F('begin_line'),
                severity_level=F('severity'),
                file_name=F('filename'),
                exposure_category=F('category'),
                credential_exposure_id=F('id'),
            )
            .values('line', 'severity_level', 'file_name', 'exposure_category', 'credential_exposure_id')
        )

        # Get vulnerable packages related to the scan
        vulnerable_packages = (
            VulnerablePackage.objects.filter(scan=scan)
            .annotate(
                line=Case(When(file__isnull=True, then=Value(1)), default=Value(1), output_field=IntegerField()),
                severity_level=F('severity'),
                file_name=F('file'),
                exposure_category=Value(None, output_field=CharField()),
                vulnerable_package_id=F('id'),
            )
            .values('line', 'severity_level', 'file_name', 'exposure_category', 'vulnerable_package_id')
        )

        # Get license exposures related to the scan
        license_exposures = (
            LicenseExposure.objects.filter(scan=scan)
            .annotate(
                line=Case(When(filename__isnull=True, then=Value(1)), default=Value(1), output_field=IntegerField()),
                severity_level=F('severity'),
                file_name=F('filename'),
                exposure_category=Value(None, output_field=CharField()),
                license_exposure_id=F('id'),
            )
            .values('line', 'severity_level', 'file_name', 'exposure_category', 'license_exposure_id')
        )

        # Combine results
        combined_results = (
            list(code_vulnerabilities)
            + list(code_alerts)
            + list(credential_exposures)
            + list(vulnerable_packages)
            + list(license_exposures)
        )

        # Severity kind choices mapping
        severity_labels = dict(SeverityKind.choices)

        # Initialize a dictionary to store the highest severity result for each file and line
        unique_results = {}

        for result in combined_results:
            # Apply severity labels
            result['severity'] = severity_labels.get(result['severity_level'], 'UNKNOWN')
            # Initialize the ids dictionary to ensure it is always present
            result['ids'] = {
                'code_vulnerability_id': result.pop('code_vulnerability_id', None),
                'code_alert_id': result.pop('code_alert_id', None),
                'credential_exposure_id': result.pop('credential_exposure_id', None),
                'vulnerable_package_id': result.pop('vulnerable_package_id', None),
                'license_exposure_id': result.pop('license_exposure_id', None),
            }

            # Apply severity filter if it is present
            if severity_value is not None and result['severity_level'] != severity_value:
                continue

            # Apply exposure category filter if it is present and exclude null values
            if exposure_category_param:
                if (
                    not result['exposure_category']
                    or result['exposure_category'].upper() != exposure_category_param.upper()
                ):
                    continue

            # Generate the key for unique results
            key = (result['file_name'], result['line'])

            # If the key is not in unique_results or the current result has higher severity, update the dictionary
            if key not in unique_results or result['severity_level'] > unique_results[key]['severity_level']:
                unique_results[key] = result

        # Convert the dictionary back into a list
        filtered_results = list(unique_results.values())

        # Apply search filter if present
        if search_param:
            search_param_upper = search_param.upper()
            filtered_results = [
                result
                for result in filtered_results
                if (
                    search_param_upper in (result['file_name'] or '').upper()
                    or search_param_upper in str(result['line'])
                    or search_param_upper in str(result['severity'])
                    or search_param_upper in (result['exposure_category'] or '').upper()
                )
            ]

        # Sort the filtered results based on sort_field and sort_order
        if sort_field:
            reverse = sort_order == 'descending'
            if sort_field == 'file_name':
                filtered_results.sort(key=lambda x: x['file_name'], reverse=reverse)
            elif sort_field == 'line':
                filtered_results.sort(key=lambda x: x['line'], reverse=reverse)
            elif sort_field == 'severity':
                filtered_results.sort(key=lambda x: x['severity_level'], reverse=reverse)
            elif sort_field == 'exposure_category' or sort_field == 'category':
                filtered_results.sort(key=lambda x: (x['exposure_category'] or '').lower(), reverse=reverse)
            else:
                # Default sort by severity, filename, and line number if no valid sort field is provided
                filtered_results.sort(
                    key=lambda x: (
                        -x['severity_level'],  # Sort by descending severity
                        x['file_name'],
                        x['line'],
                    ),
                    reverse=reverse,
                )
        else:
            # Default sort by severity, filename, and line number if no sort field is provided
            filtered_results.sort(
                key=lambda x: (
                    -x['severity_level'],  # Sort by descending severity
                    x['file_name'],
                    x['line'],
                )
            )

        # Paginate the results
        paginator = StandardResultsSetPagination()
        paginated_results = paginator.paginate_queryset(filtered_results, request, view=self)

        # Serialize the paginated results
        serializer = CombinedVulnerabilityAlertSerializer(paginated_results, many=True)
        return paginator.get_paginated_response(serializer.data)

    @action(['get'], detail=True)
    def severity(self, request, *args, **kwargs):
        severity_count = [{'high': 12, 'medium': 14, 'low': 6, 'unknown': 0}]
        return Response({'results': severity_count})


class SCQAReportViewSet(BaseModelViewSet):
    serializer_class = SourceCodeQualityAnalyzerReportSerializer
    queryset = SCQAReport.objects.filter().order_by('-updated_at')
    filterset_fields = ['scan__repo__url', 'scan__branch', 'file_name']
    search_fields = ['scan__repo__url', 'scan__branch', 'file_name']

    @action(['get'], detail=False)
    def download(self, request, *args, **kwargs):
        serializer = SASTReportDownloadSerializer(data=request.GET)
        serializer.is_valid(raise_exception=True)
        filename = serializer.data.get('filename')
        response = get_scqa_report_url(filename, request.tenant.uid)
        return Response({'results': response})


class SCQAReportRuleSetViewSet(BaseModelViewSet):
    serializer_class = CodeQualityAnalyzerSerializer
    queryset = CodeQualityAnalyserScanAlerts.objects.order_by('-severity')
    filter_backends = [VulnerabilitiesFilterBackend]
    ordering_fields = [
        'id',
        'filename',
        'rule',
        'severity',
        'description',
        'begin_line',
        'rule_set',
        'column',
        'details',
    ]

    def list(self, request, *args, **kwargs):
        serializer = VulnerabilityQueryParamsSerializer(data=request.GET)
        serializer.is_valid(raise_exception=True)

        scan_id = serializer.data.get('scan')
        queryset = CodeQualityAnalyserScanAlerts.objects.filter(scan__id=scan_id)

        queryset_count = queryset.aggregate(
            critical=Count('severity', filter=Q(severity=SeverityKind.CRITICAL)),
            high=Count('severity', filter=Q(severity=SeverityKind.HIGH)),
            medium=Count('severity', filter=Q(severity=SeverityKind.MEDIUM)),
            low=Count('severity', filter=Q(severity=SeverityKind.LOW)),
            unknown=Count('severity', filter=Q(severity=SeverityKind.UNKNOWN)),
        )
        high_queryset = list(
            queryset.filter(severity=SeverityKind.HIGH)
            .values('rule_set')
            .annotate(count=Count('rule_set'))
            .order_by('-count')
        )
        medium_queryset = list(
            queryset.filter(severity=SeverityKind.MEDIUM)
            .values('rule_set')
            .annotate(count=Count('rule_set'))
            .order_by('-count')
        )
        low_queryset = list(
            queryset.filter(severity=SeverityKind.LOW)
            .values('rule_set')
            .annotate(count=Count('rule_set'))
            .order_by('-count')
        )
        unknown_queryset = list(
            queryset.filter(severity=SeverityKind.UNKNOWN)
            .values('rule_set')
            .annotate(count=Count('rule_set'))
            .order_by('-count')
        )
        high_violations = {'count': queryset_count['high'], 'reports': high_queryset}
        medium_violations = {'count': queryset_count['medium'], 'reports': medium_queryset}
        low_violations = {'count': queryset_count['low'], 'reports': low_queryset}
        unknown_violations = {'count': queryset_count['unknown'], 'reports': unknown_queryset}
        return Response(
            {
                'last_scanned_at': queryset.first().scan.updated_at,
                'risk_levels': queryset_count,
                'violations': [high_violations, medium_violations, low_violations, unknown_violations],
            }
        )


class SASTScanIssueViewSet(BaseModelViewSet):
    queryset = ScanIssue.objects.filter()
    serializer_class = ScanIssueSerializer
    filter_backends = [SearchFilter, OrderingFilter, VulnerabilitiesFilterBackend]
    search_fields = ['file_name', 'category', 'line']
    ordering_fields = ['severity', 'category', 'file_name', 'line']  # Include severity in the ordering fields
    ordering = ['-severity', 'id']  # Default ordering by id and severity in descending order

    @action(['get'], detail=False)
    def severity(self, request, *args, **kwargs):
        scan_id = request.GET.get('scan')
        severity_count = ScanIssue.objects.filter(scan=scan_id).values('severity').annotate(count=Count('severity'))

        # Create a dictionary with the counts initialized to 0
        severity_dict = {level.label.lower(): 0 for level in SeverityKind}

        # Update the dictionary with the actual counts
        for item in severity_count:
            severity_label = SeverityKind(item['severity']).label.lower()
            severity_dict[severity_label] = item['count']
        return Response({'results': severity_dict})


class ZapViewSet(BaseModelViewSet):
    serializer_class = ZAPCredentialSerializer
    queryset = ZAPCredential.objects.all()


class ZapReportViewSet(BaseModelViewSet):
    serializer_class = ZAPReportSerializer
    queryset = ZAPReport.objects.all()
    filter_backends = [ZapFilterBackend]

    def retrieve(self, request, *args, **kwargs):
        pk = self.kwargs.get('pk')
        zap_report = get_object_or_404(ZAPReport, pk=pk)
        serializer = self.get_serializer(zap_report)
        return Response(serializer.data)

    def list(self, request, *args, **kwargs):
        queryset = ZAPReport.objects.all().values('name', 'url', 'risk').annotate(zap_count=Count('id'))

        risk_count = queryset.aggregate(
            critical=Coalesce(Sum('zap_count', filter=Q(risk=SeverityKind.CRITICAL)), 0),
            high=Coalesce(Sum('zap_count', filter=Q(risk=SeverityKind.HIGH)), 0),
            medium=Coalesce(Sum('zap_count', filter=Q(risk=SeverityKind.MEDIUM)), 0),
            low=Coalesce(Sum('zap_count', filter=Q(risk=SeverityKind.LOW)), 0),
            unknown=Coalesce(Sum('zap_count', filter=Q(risk=SeverityKind.UNKNOWN)), 0),
            informational=Coalesce(Sum('zap_count', filter=Q(risk=SeverityKind.INFORMATIONAL)), 0),
        )
        response = super().list(request, *args, **kwargs)
        if response.data['results']:
            for data in response.data['results']:
                removed_value = data.pop('zap')
            response.data['zap'] = removed_value
            response.data['risk'] = risk_count
            return response
        return Response('')

    @action(['get'], detail=False)
    def scan(self, request, *args, **kwargs):
        base_url = request.GET.get('base_url')
        tenant = request.tenant.uid
        user = User.objects.all().first()
        initiate_zap_scan.delay(base_url, user.id, tenant)
        return Response('Scanning Initiated')


class ZapRepotListViewSet(BaseModelViewSet):
    serializer_class = ZAPReportsListSerializer
    queryset = ZAPReportsList.objects.filter().order_by('-created_at')

    def list(self, request, *args, **kwargs):
        queryset = self.get_queryset()
        base_url = request.GET.get('base_url')
        latest_report = queryset.filter(base_url=base_url).first()
        if latest_report:
            serializer = ZAPReportsListSerializer(latest_report)
            return Response(serializer.data)
        else:
            return Response('')

    @action(['get'], detail=False)
    def reports(self, request, *args, **kwargs):
        base_url = request.GET.get('base_url')
        query_set = self.get_queryset()
        if base_url:
            pdf_report = query_set.filter(base_url=base_url)
        else:
            pdf_report = query_set
        page = self.paginate_queryset(pdf_report)
        if pdf_report:
            serializer = ZAPReportsListSerializer(page, many=True)
            return self.get_paginated_response(serializer.data)
        else:
            return Response('')

    @action(['get'], detail=False)
    def download(self, request, *args, **kwargs):
        serializer = ZAPReportDownloadSerializer(data=request.GET)
        serializer.is_valid(raise_exception=True)
        filename = serializer.data.get('filename')
        response = get_dast_report_url(filename, request.tenant.uid)
        return Response({'results': response})


class AIVAViewSet(BaseModelViewSet):
    serializer_class = ScanSerializer
    queryset = Scan.objects.filter(is_periodic=False)
    filterset_fields = ['repo__url', 'branch']

    @action(['get'], detail=False)
    def rank(self, request, *args, **kwargs):
        serializer = AIVAParamSerializer(data=request.GET)
        serializer.is_valid(raise_exception=True)
        id = serializer.data.get('id')
        scan = get_object_or_404(Scan, pk=id)
        response = get_vulnerabilities_rank(scan)
        return Response(response)

    @action(['get'], detail=False)
    def recommendation(self, request, *args, **kwargs):
        serializer = AIVAParamSerializer(data=request.GET)
        serializer.is_valid(raise_exception=True)
        id = serializer.data.get('id')
        scan_issue = get_object_or_404(ScanIssue, pk=id)
        response = get_vulnerabilities_recommendation_cost(scan_issue.scan, 'RECOMMENDATION')
        return Response(response)

    @action(['get'], detail=False)
    def cost(self, request, *args, **kwargs):
        serializer = AIVAParamSerializer(data=request.GET)
        serializer.is_valid(raise_exception=True)
        id = serializer.data.get('id')
        scan_issue = get_object_or_404(Scan, pk=id)
        response = get_vulnerabilities_recommendation_cost(scan_issue, 'COST')
        return Response(response)


class SASTScanIssueDetailsViewSet(BaseModelViewSet):
    queryset = ScanIssue.objects.all()
    serializer_class = ScanIssueSerializer

    @action(['get'], detail=True, url_path='exposure/credential')
    def exposure_credential(self, request, *args, **kwargs):
        scan_issue = self.get_object()
        # CredentialExposure
        queryset = CredentialExposure.objects.filter(scan_issue=scan_issue).order_by('-severity')
        paginated_queryset = self.paginate_queryset(queryset)
        serializer = CredentialExposureDetailSerializer(paginated_queryset, many=True)
        return self.get_paginated_response(serializer.data)

    @action(['get'], detail=True, url_path='exposure/license')
    def exposure_license(self, request, *args, **kwargs):
        scan_issue = self.get_object()
        # LicenseExposure
        queryset = LicenseExposure.objects.filter(scan_issue=scan_issue).order_by('-severity')
        paginated_queryset = self.paginate_queryset(queryset)
        serializer = LicenseExposureDetailSerializer(paginated_queryset, many=True)
        return self.get_paginated_response(serializer.data)

    @action(['get'], detail=True, url_path='vulnerabilities/package')
    def vulnerabilities_package(self, request, *args, **kwargs):
        scan_issue = self.get_object()
        # VulnerablePackage
        queryset = VulnerablePackage.objects.filter(scan_issue=scan_issue).order_by('-severity')
        paginated_queryset = self.paginate_queryset(queryset)
        serializer = VulnerablePackageDetailSerializer(paginated_queryset, many=True)
        return self.get_paginated_response(serializer.data)

    @action(['get'], detail=True, url_path='vulnerabilities/codelevel')
    def vulnerabilities_codelevel(self, request, *args, **kwargs):
        scan_issue = self.get_object()
        # CodeLevelVulnerability
        queryset = CodeLevelVulnerability.objects.filter(scan_issue=scan_issue).order_by('-severity')
        paginated_queryset = self.paginate_queryset(queryset)
        serializer = CodeLevelVulnerabilityDetailSerializer(paginated_queryset, many=True)
        return self.get_paginated_response(serializer.data)

    @action(['get'], detail=True, url_path='code/quality/analyzer')
    def code_quality_analyzer(self, request, *args, **kwargs):
        scan_issue = self.get_object()
        # CodeQualityAnalyserScanAlerts
        queryset = CodeQualityAnalyserScanAlerts.objects.filter(scan_issue=scan_issue).order_by('-severity')
        paginated_queryset = self.paginate_queryset(queryset)
        serializer = CodeQualityAnalyzerDetailSerializer(paginated_queryset, many=True)
        return self.get_paginated_response(serializer.data)

    @action(['get'], detail=True, url_path='issues/summary')
    def issues_summary(self, request, *args, **kwargs):
        scan_issue = self.get_object()

        credential_queryset = (
            CredentialExposure.objects.filter(scan_issue=scan_issue)
            .annotate(
                summary=F('title'),
                description=F('content'),
                issue_category=Value(CREDENTIAL, output_field=CharField()),
                line=F('begin_line'),
            )
            .values('severity', 'summary', 'description', 'filename', 'issue_category', 'line')
        )

        exposure_queryset = (
            LicenseExposure.objects.filter(scan_issue=scan_issue)
            .annotate(
                summary=F('package'),
                description=F('license'),
                issue_category=Value(LICENSE, output_field=CharField()),
                line=Case(When(filename__isnull=True, then=Value(1)), default=Value(1), output_field=IntegerField()),
            )
            .values('severity', 'summary', 'description', 'filename', 'issue_category', 'line')
        )

        vulnerabilities_queryset = (
            VulnerablePackage.objects.filter(scan_issue=scan_issue)
            .annotate(
                summary=F('title'),
                filename=F('file'),
                issue_category=Value(LANG_PKGS, output_field=CharField()),
                line=Case(When(file__isnull=True, then=Value(1)), default=Value(1), output_field=IntegerField()),
            )
            .values('severity', 'summary', 'description', 'filename', 'issue_category', 'line')
        )

        codelevel_queryset = (
            CodeLevelVulnerability.objects.filter(scan_issue=scan_issue)
            .annotate(
                summary=F('title'),
                issue_category=Value(CODE_VULNERABILITY, output_field=CharField()),
                line=F('line_number'),
            )
            .values('severity', 'summary', 'description', 'filename', 'issue_category', 'line')
        )

        scqa_queryset = (
            CodeQualityAnalyserScanAlerts.objects.filter(scan_issue=scan_issue)
            .annotate(
                summary=F('rule_set'),
                issue_category=Value(CODE_QUALITY, output_field=CharField()),
                line=F('begin_line'),
            )
            .values('severity', 'summary', 'description', 'filename', 'issue_category', 'line')
        )

        model_combination = list(
            chain(credential_queryset, exposure_queryset, vulnerabilities_queryset, codelevel_queryset, scqa_queryset)
        )
        for vulnerability in model_combination:
            hashed_value = hashing_values(
                SeverityKind.choices[vulnerability['severity']][1],
                vulnerability['summary'],
                vulnerability['description'],
                vulnerability['filename'],
                vulnerability['issue_category'],
                str(vulnerability['line']),
            )
            jira_ticket_tracker = JiraTicketTracker.objects.filter(unique_field=hashed_value)
            if jira_ticket_tracker.exists():
                jira_ticket_tracker = jira_ticket_tracker.first()
                vulnerability['ticket_link'] = jira_ticket_tracker.ticket_link
                vulnerability['ticket_id'] = jira_ticket_tracker.label
        paginator = self.pagination_class()
        paginated_queryset = paginator.paginate_queryset(model_combination, request)

        serializer = IssuesSummary(paginated_queryset, many=True)
        return paginator.get_paginated_response(serializer.data)


class JiraTicketTrackerViewSet(BaseModelViewSet):
    queryset = JiraTicketTracker.objects.all()
    serializer_class = JiraTicketTrackerSerializer

    def get_serializer_class(self):
        if self.action == 'partial_update':
            return JiraTicketTrackerUpdateSerializer
        return super().get_serializer_class()
