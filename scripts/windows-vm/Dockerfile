FROM dockurr/windows:6.06@sha256:16fd7c39a3e48bb946d29c59dc6015942e5b900a1fa5d7e5552053bfc48ee2ea
# The pinned upstream image kills QEMU after 30 seconds without a firmware
# marker. Slow nested-KVM starts need more time; healthy boots do not wait.
RUN python3 -c 'from pathlib import Path; p=Path("/run/entry.sh"); s=p.read_text(); old="waitForBoot \"$pid\" 30 &"; assert s.count(old)==1, "unexpected upstream boot monitor"; p.write_text(s.replace(old,"waitForBoot \"$pid\" 120 &"))'
COPY --chmod=755 entry.sh /opt/netflow/entry.sh
COPY --chmod=755 download-media.sh /opt/netflow/download-media.sh
COPY --chmod=644 bridge.py /opt/netflow/bridge.py
COPY --chmod=644 test_monitor.py /opt/netflow/test_monitor.py
COPY install.bat /oem/install.bat
ENV VERSION=10l DISK_SIZE=32G DISK_FMT=qcow2 ALLOCATE=N RAM_SIZE=4G CPU_CORES=1 NETWORK=slirp IP=10.233.42.2 DNSMASQ_DISABLE=Y SAMBA=N SHORTCUT=N VERIFY=Y REMOVE=Y CONNECTIONS=16
ENTRYPOINT ["/usr/bin/tini", "-s", "--", "/opt/netflow/entry.sh"]
