#!/bin/bash

# Скрипт сборки кастомного ядра Debian/Ubuntu для T2 Mac
# Оптимизирован для полноценной работы OpenStack с поддержкой:
# - Keystone, Glance, Nova
# - Ceph, Cinder (блочное хранилище)
# - Neutron (BGP, STT, ML2, OVS, Kuryr, Cilium, VXLAN, EVPN, IPSec/IKEv2)
# - Heat, Magnum
# - Расширенные сетевые возможности для SDN/NFV

set -eu -o pipefail

### Environment setup
export DEBIAN_FRONTEND=noninteractive

### Functions
check_config() {
    local config=$1
    if ! grep -q "^$config=" .config; then
        echo "Warning: $config not set in final config"
        return 1
    fi
    return 0
}

get_next_version () {
    echo $PKGREL
}

### Base configuration
apt-get update
apt-get install -y lsb-release

KERNEL_VERSION=6.12.1
PKGREL=1
DISTRO=$(lsb_release -i | cut -d ":" -f 2 | xargs)
CODENAME=$(lsb_release -c | cut -d ":" -f 2 | xargs)

if [[ ${DISTRO} = Debian ]]; then
    CONFIG=debian
else
    CONFIG=ubuntu
fi

KERNEL_REPOSITORY=https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux-stable.git
REPO_PATH=$(pwd)
WORKING_PATH=/root/work
KERNEL_PATH="${WORKING_PATH}/linux-kernel"

### Debug information
echo "=== Build Configuration ==="
echo "Kernel version: ${KERNEL_VERSION}"
echo "Config distro: ${CONFIG}"
echo "Working path: ${WORKING_PATH}"
echo "Kernel repository: ${KERNEL_REPOSITORY}"
echo "Current path: ${REPO_PATH}"
echo "CPU threads: $(nproc --all)"
grep 'model name' /proc/cpuinfo | uniq

### Cleanup and prepare
rm -rfv ./*.deb
mkdir -p "${WORKING_PATH}" && cd "${WORKING_PATH}"
cp -rf "${REPO_PATH}"/{patches,templates} "${WORKING_PATH}"
rm -rf "${KERNEL_PATH}"

### Install dependencies
apt-get install -y build-essential fakeroot libncurses-dev bison flex libssl-dev libelf-dev \
    openssl dkms libudev-dev libpci-dev libiberty-dev autoconf wget xz-utils git \
    libcap-dev bc rsync cpio debhelper kernel-wedge curl gawk dwarves zstd python3

### Clone kernel
git clone --depth 1 --single-branch --branch "v${KERNEL_VERSION}" \
    "${KERNEL_REPOSITORY}" "${KERNEL_PATH}"

cd "${KERNEL_PATH}" || exit

### Patch preparation
echo >&2 "===]> Info: Creating patch file... "
KERNEL_VERSION="${KERNEL_VERSION}" WORKING_PATH="${WORKING_PATH}" "${REPO_PATH}/patch_driver.sh"

### Apply patches
cd "${KERNEL_PATH}" || exit
echo >&2 "===]> Info: Applying patches... "
[ ! -d "${WORKING_PATH}/patches" ] && {
    echo 'Patches directory not found!'
    exit 1
}

while IFS= read -r file; do
    echo "==> Adding $file"
    patch -p1 <"$file"
done < <(find "${WORKING_PATH}/patches" -type f -name "*.patch" | sort)

### Build preparation
cd "${KERNEL_PATH}"
make clean

# Configure base settings
sed -i 's/CONFIG_VERSION_SIGNATURE=.*/CONFIG_VERSION_SIGNATURE=""/g' "${WORKING_PATH}/templates/default-config-${CONFIG}"
sed -i 's/CONFIG_SYSTEM_TRUSTED_KEYS=.*/CONFIG_SYSTEM_TRUSTED_KEYS=""/g' "${WORKING_PATH}/templates/default-config-${CONFIG}"
sed -i 's/CONFIG_SYSTEM_REVOCATION_KEYS=.*/CONFIG_SYSTEM_REVOCATION_KEYS=""/g' "${WORKING_PATH}/templates/default-config-${CONFIG}"
sed -i 's/CONFIG_CONSOLE_LOGLEVEL_DEFAULT=.*/CONFIG_CONSOLE_LOGLEVEL_DEFAULT=4/g' "${WORKING_PATH}/templates/default-config-${CONFIG}"
sed -i 's/CONFIG_CONSOLE_LOGLEVEL_QUIET=.*/CONFIG_CONSOLE_LOGLEVEL_QUIET=1/g' "${WORKING_PATH}/templates/default-config-${CONFIG}"
sed -i 's/CONFIG_MESSAGE_LOGLEVEL_DEFAULT=.*/CONFIG_MESSAGE_LOGLEVEL_DEFAULT=4/g' "${WORKING_PATH}/templates/default-config-${CONFIG}"

cp -v "${WORKING_PATH}/templates/default-config-${CONFIG}" "${KERNEL_PATH}/.config"

### Kernel Configuration

# === Base System Features ===
./scripts/config --enable CONFIG_PREEMPT
./scripts/config --enable CONFIG_HZ_1000
./scripts/config --enable CONFIG_HIGH_RES_TIMERS
./scripts/config --enable CONFIG_MEMCG
./scripts/config --enable CONFIG_NAMESPACES
./scripts/config --enable CONFIG_NET_NS
./scripts/config --enable CONFIG_PID_NS
./scripts/config --enable CONFIG_IPC_NS
./scripts/config --enable CONFIG_UTS_NS
./scripts/config --enable CONFIG_CGROUPS
./scripts/config --enable CONFIG_KEYS
./scripts/config --enable CONFIG_KEYS_COMPAT

# === OpenStack Network Features ===
# Open vSwitch
./scripts/config --module CONFIG_OPENVSWITCH
./scripts/config --module CONFIG_OPENVSWITCH_GRE
./scripts/config --module CONFIG_OPENVSWITCH_VXLAN
./scripts/config --module CONFIG_OPENVSWITCH_GENEVE

# Network Scheduling and QoS
./scripts/config --enable CONFIG_NET_SCHED
./scripts/config --enable CONFIG_NET_SCH_HTB
./scripts/config --enable CONFIG_NET_SCH_FQ
./scripts/config --enable CONFIG_NET_SCH_FQ_CODEL
./scripts/config --module CONFIG_NET_SCH_INGRESS
./scripts/config --module CONFIG_NET_ACT_POLICE
./scripts/config --module CONFIG_NET_ACT_GACT

# Advanced Networking
./scripts/config --enable CONFIG_NET_CLS_ACT
./scripts/config --enable CONFIG_IP_ADVANCED_ROUTER
./scripts/config --enable CONFIG_IP_MULTIPLE_TABLES
./scripts/config --enable CONFIG_IP_FIB_TRIE_STATS
./scripts/config --enable CONFIG_IP_ROUTE_MULTIPATH
./scripts/config --enable CONFIG_IP_ROUTE_MULTIPATH_CACHED

# Tunneling and Overlay
./scripts/config --module CONFIG_NET_IPGRE
./scripts/config --module CONFIG_NET_IPGRE_DEMUX
./scripts/config --enable CONFIG_OVERLAY_FS
./scripts/config --enable CONFIG_OVERLAY_FS_REDIRECT_DIR
./scripts/config --enable CONFIG_OVERLAY_FS_REDIRECT_ALWAYS_FOLLOW

# MPLS Support
./scripts/config --enable CONFIG_MPLS
./scripts/config --enable CONFIG_MPLS_ROUTING
./scripts/config --enable CONFIG_MPLS_IPTUNNEL

# BGP/EVPN Support
./scripts/config --enable CONFIG_NET_L3_MASTER_DEV
./scripts/config --enable CONFIG_NET_VRF
./scripts/config --enable CONFIG_VXLAN_GBP

# Load Balancing
./scripts/config --module CONFIG_IP_VS
./scripts/config --module CONFIG_IP_VS_RR

# Network Security
./scripts/config --module CONFIG_INET_ESP
./scripts/config --module CONFIG_INET_IPCOMP
./scripts/config --module CONFIG_XFRM_USER
./scripts/config --module CONFIG_XFRM_ALGO
./scripts/config --enable CONFIG_INET_ESP_OFFLOAD
./scripts/config --enable CONFIG_INET_GRO
./scripts/config --enable CONFIG_INET6_GRO
./scripts/config --enable CONFIG_NET_TSO

# Bridge and Netfilter
./scripts/config --module CONFIG_BRIDGE
./scripts/config --module CONFIG_BRIDGE_NETFILTER
./scripts/config --module CONFIG_NETFILTER_ADVANCED
./scripts/config --module CONFIG_NETFILTER_XT_MATCH_MULTIPORT
./scripts/config --module CONFIG_NETFILTER_XT_TARGET_TEE
./scripts/config --module CONFIG_NF_CONNTRACK
./scripts/config --module CONFIG_NF_NAT

# Hardware Offloading
./scripts/config --enable CONFIG_NET_SWITCHDEV
./scripts/config --enable CONFIG_NET_TC_SKB_EXT
./scripts/config --enable CONFIG_HSR

# === Cilium/BPF Features ===
./scripts/config --enable CONFIG_BPF
./scripts/config --enable CONFIG_BPF_SYSCALL
./scripts/config --enable CONFIG_BPF_JIT
./scripts/config --enable CONFIG_HAVE_EBPF_JIT
./scripts/config --enable CONFIG_BPF_EVENTS
./scripts/config --enable CONFIG_NETFILTER_XT_MATCH_BPF
./scripts/config --enable CONFIG_NET_CLS_BPF
./scripts/config --enable CONFIG_NET_ACT_BPF
./scripts/config --enable CONFIG_BPF_STREAM_PARSER
./scripts/config --enable CONFIG_INET_UDP_DIAG
./scripts/config --enable CONFIG_INET_DIAG_DESTROY

# === Storage Features ===
# Ceph/RBD
./scripts/config --module CONFIG_BLK_DEV_RBD
./scripts/config --module CONFIG_CEPH_LIB
./scripts/config --enable CONFIG_CEPH_LIB_PRETTYDEBUG

# Device Mapper
./scripts/config --module CONFIG_DM_MULTIPATH
./scripts/config --module CONFIG_DM_UEVENT

# === Virtualization Features ===
./scripts/config --module CONFIG_KVM
./scripts/config --module CONFIG_KVM_INTEL
./scripts/config --enable CONFIG_VIRTUALIZATION
./scripts/config --module CONFIG_VHOST_NET
./scripts/config --module CONFIG_VHOST_SCSI
./scripts/config --module CONFIG_VHOST
./scripts/config --module CONFIG_TUN

# === Security Features ===
./scripts/config --module CONFIG_CRYPTO_ECDH
./scripts/config --module CONFIG_CRYPTO_ECHAINIV
./scripts/config --module CONFIG_CRYPTO_GCM
./scripts/config --module CONFIG_CRYPTO_GHASH
./scripts/config --module CONFIG_CRYPTO_SHA256
./scripts/config --module CONFIG_CRYPTO_AES

# === Performance Monitoring and Debug ===
./scripts/config --enable CONFIG_FTRACE
./scripts/config --enable CONFIG_FTRACE_SYSCALLS
./scripts/config --enable CONFIG_STACK_TRACER
./scripts/config --enable CONFIG_FUNCTION_TRACER
./scripts/config --enable CONFIG_NET_DROP_MONITOR
./scripts/config --enable CONFIG_KPROBE_EVENTS
./scripts/config --enable CONFIG_UPROBE_EVENTS
./scripts/config --enable CONFIG_NET_RX_BUSY_POLL
./scripts/config --enable CONFIG_BQL
./scripts/config --enable CONFIG_NET_FLOW_LIMIT

# === Network Performance ===
./scripts/config --enable CONFIG_TCP_CONG_BBR
./scripts/config --enable CONFIG_NET_SCH_NETEM

# Apply configuration
make olddefconfig

# === T2 Mac Specific Drivers ===
./scripts/config --module CONFIG_HID_APPLETB_BL
./scripts/config --module CONFIG_HID_APPLETB_KBD
./scripts/config --module CONFIG_DRM_APPLETBDRM
./scripts/config --module CONFIG_BT_HCIBCM4377
./scripts/config --module CONFIG_APFS_FS

# Clear SCM version
echo "" > "${KERNEL_PATH}/.scmversion"

### Build Debian Packages
echo >&2 "===]> Info: Building kernel packages... "
make -j "$(getconf _NPROCESSORS_ONLN)" deb-pkg LOCALVERSION=-${PKGREL}-t2-"${CODENAME}" KDEB_PKGVERSION="$(make kernelversion)-$(get_next_version)"

### Copy Artifacts
echo >&2 "===]> Info: Copying debs and calculating SHA256 ... "
cp -rfv "${KERNEL_PATH}/.config" "/tmp/artifacts/kernel_config_${KERNEL_VERSION}-${CODENAME}"
cp -rfv ../*.deb /tmp/artifacts/

# Handle version-specific naming
if [[ (${#KERNEL_VERSION} = 3) || (${#KERNEL_VERSION} = 4) ]]; then
    mv "/tmp/artifacts/linux-libc-dev_${KERNEL_VERSION}.0-${PKGREL}_amd64.deb" "/tmp/artifacts/linux-libc-dev_${KERNEL_VERSION}.0-${PKGREL}-${CODENAME}_amd64.deb"
else
    mv "/tmp/artifacts/linux-libc-dev_${KERNEL_VERSION}-${PKGREL}_amd64.deb" "/tmp/artifacts/linux-libc-dev_${KERNEL_VERSION}-${PKGREL}-${CODENAME}_amd64.deb"
fi

# Generate checksums
sha256sum ../*.deb > /tmp/artifacts/sha256-"${CODENAME}"

echo >&2 "===]> Build completed successfully!"
