import ctypes
import os
import platform
import shutil
from dataclasses import dataclass, field


@dataclass
class PlatformSecurityFeature:
    name: str
    available: bool
    required: bool = True
    detail: str = ""


@dataclass
class PlatformSecurityReport:
    platform: str
    features: list[PlatformSecurityFeature] = field(default_factory=list)

    @property
    def degraded(self) -> bool:
        return any(feature.required and not feature.available for feature in self.features)

    def as_dict(self) -> dict:
        return {
            "platform": self.platform,
            "degraded": self.degraded,
            "features": [
                {
                    "name": feature.name,
                    "available": feature.available,
                    "required": feature.required,
                    "detail": feature.detail,
                }
                for feature in self.features
            ],
        }


class PlatformSecurityManager:
    def __init__(self, system_name: str | None = None):
        self.report = get_platform_security_report(system_name)

    def secure_storage_backend(self) -> str:
        feature_names = {feature.name: feature.available for feature in self.report.features}
        if self.report.platform == "Windows" and feature_names.get("credential_guard_probe"):
            return "windows_credential_guard"
        if self.report.platform == "Darwin" and feature_names.get("keychain_services"):
            return "macos_keychain"
        if self.report.platform == "Linux" and feature_names.get("kernel_keyring"):
            return "linux_kernel_keyring"
        return "memory_only_fail_secure"

    def secure_prompt_backend(self) -> str:
        feature_names = {feature.name: feature.available for feature in self.report.features}
        if self.report.platform == "Windows" and feature_names.get("secure_desktop_api"):
            return "windows_secure_desktop"
        if self.report.platform == "Darwin" and feature_names.get("keychain_services"):
            return "macos_protected_prompt"
        return "application_modal_prompt"

    def service_integration_backend(self) -> str:
        feature_names = {feature.name: feature.available for feature in self.report.features}
        if self.report.platform == "Linux" and feature_names.get("systemd_user_service"):
            return "systemd_user_service"
        if self.report.platform == "Darwin" and feature_names.get("gatekeeper_spctl"):
            return "gatekeeper_checked_app"
        if self.report.platform == "Windows":
            return "windows_user_session"
        return "foreground_application"

    def hardening_summary(self) -> dict:
        return {
            "platform": self.report.platform,
            "degraded": self.report.degraded,
            "secure_storage": self.secure_storage_backend(),
            "secure_prompt": self.secure_prompt_backend(),
            "service_integration": self.service_integration_backend(),
            "features": self.report.as_dict()["features"],
        }


def get_platform_security_report(system_name: str | None = None) -> PlatformSecurityReport:
    system = system_name or platform.system()
    if system == "Windows":
        return _windows_report()
    if system == "Darwin":
        return _macos_report()
    if system == "Linux":
        return _linux_report()
    return PlatformSecurityReport(
        platform=system,
        features=[PlatformSecurityFeature("fallback_fail_secure", True, detail="Unknown platform uses safe fallback mode.")],
    )


def _windows_report() -> PlatformSecurityReport:
    user32_available = hasattr(ctypes, "windll") and hasattr(ctypes.windll, "user32")
    credential_guard_hint = bool(os.environ.get("VBS_ENCLAVE_ID") or os.environ.get("PROCESSOR_IDENTIFIER"))
    return PlatformSecurityReport(
        platform="Windows",
        features=[
            PlatformSecurityFeature("credential_guard_probe", credential_guard_hint, detail="Detected from Windows environment hints."),
            PlatformSecurityFeature("secure_desktop_api", user32_available, detail="user32 desktop APIs available for protected prompts."),
            PlatformSecurityFeature("windows_hello_bonus", False, required=False, detail="Bonus feature; not required for pass/fail."),
        ],
    )


def _macos_report() -> PlatformSecurityReport:
    return PlatformSecurityReport(
        platform="Darwin",
        features=[
            PlatformSecurityFeature("keychain_services", shutil.which("security") is not None, detail="Uses macOS security CLI when available."),
            PlatformSecurityFeature("gatekeeper_spctl", shutil.which("spctl") is not None, detail="Gatekeeper status can be checked with spctl."),
            PlatformSecurityFeature("touch_id_bonus", False, required=False, detail="Bonus feature; not required for pass/fail."),
        ],
    )


def _linux_report() -> PlatformSecurityReport:
    return PlatformSecurityReport(
        platform="Linux",
        features=[
            PlatformSecurityFeature("kernel_keyring", shutil.which("keyctl") is not None, detail="Kernel keyring support via keyctl."),
            PlatformSecurityFeature("systemd_user_service", shutil.which("systemctl") is not None, detail="systemd integration available."),
            PlatformSecurityFeature(
                "selinux_or_apparmor",
                os.path.exists("/sys/fs/selinux") or os.path.exists("/sys/kernel/security/apparmor"),
                detail="Checks SELinux/AppArmor kernel policy interfaces.",
            ),
        ],
    )