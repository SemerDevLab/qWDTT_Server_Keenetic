# Supported Keenetic Entware architectures only.
@(
    @{Name="mipsel"; GOARCH="mipsle"; GOMIPS="softfloat"; PackageArch="mipsel-3.4"},
    @{Name="armv7"; GOARCH="arm"; GOARM="7"; PackageArch="armv7-3.2"},
    @{Name="aarch64"; GOARCH="arm64"; PackageArch="aarch64-3.10"}
)
