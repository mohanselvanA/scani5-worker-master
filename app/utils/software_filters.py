import yaml
import os

class NoiseFilter:
    def __init__(self, config_path="app/config/software_noise_filters.yaml"):
        if not os.path.exists(config_path):
            raise FileNotFoundError(f"Noise filter config not found: {config_path}")

        with open(config_path, "r", encoding="utf-8") as f:
            config = yaml.safe_load(f)

        self.keywords = [k.lower() for k in config.get("keywords", [])]
        self.vendors = [v.lower() for v in config.get("vendors", [])]

    def is_noise(self, app_name: str, vendor: str = "") -> bool:
        app_name = (app_name or "").lower()
        vendor = (vendor or "").lower()

        # Check keyword match in app name
        if any(keyword in app_name for keyword in self.keywords):
            return True

        # Vendor-specific conditions
        if vendor in self.vendors:
            if any(term in app_name for term in [
                "framework", "sdk", "runtime", "toolset", "template", "setup", "pack", "host", "resolver"
            ]):
                return True

        return False