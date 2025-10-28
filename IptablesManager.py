class IPtablesManager:
    def __init__(self, chain: str):
        self.chain = chain
        self.commands: List[str] = []

    def setupChain(self):
        """Ensure chain exists and is linked to INPUT/FORWARD."""
        self.commands += [
            f"iptables -N {self.chain} 2>/dev/null || true",
            f"iptables -C INPUT   -j {self.chain} 2>/dev/null || iptables -I INPUT   1 -j {self.chain}",
            f"iptables -C FORWARD -j {self.chain} 2>/dev/null || iptables -I FORWARD 1 -j {self.chain}"
        ]
        logger.debug(f"Chain setup commands added for {self.chain}")

    def deleteChain(self):
        """Flush and delete the chain (if exists)."""
        self.commands += [
            f"iptables -F {self.chain} 2>/dev/null || true",
            f"iptables -D INPUT   -j {self.chain} 2>/dev/null || true",
            f"iptables -D FORWARD -j {self.chain} 2>/dev/null || true",
            f"iptables -X {self.chain} 2>/dev/null || true"
        ]
        logger.warning(f"Delete chain commands queued for {self.chain}")

    def createRule(self, ip: str, meta: Dict):
        """Create a DROP rule for an IP with comment metadata."""
        comment = f"cs:id={meta.get('id','')};scn={meta.get('scenario','')};orig={meta.get('origin','')}"
        comment = comment.replace('"', "'")
        self.commands.append(
            f'if iptables -m comment -h >/dev/null 2>&1; then '
            f'iptables -A {self.chain} -s {ip} -m comment --comment "{comment}" -j DROP 2>/dev/null || iptables -A {self.chain} -s {ip} -j DROP; '
            f'else iptables -A {self.chain} -s {ip} -j DROP; fi'
        )
        logger.debug(f"Rule created for {ip} ({comment})")

    def delete(self, ip: str):
        """Delete a specific IP rule from the chain."""
        self.commands.append(f"iptables -D {self.chain} -s {ip} -j DROP 2>/dev/null || true")
        logger.info(f"Queued delete for IP {ip}")

    def add(self, ip: str, meta: Dict):
        """Add wrapper — just calls createRule()."""
        self.createRule(ip, meta)

    def commit(self) -> str:
        """Return the assembled shell script for remote execution."""
        script = [f"iptables -F {self.chain} 2>/dev/null || true"]
        script.extend(self.commands)
        script.append(f'echo "Applied $(iptables -L {self.chain} -n | grep DROP | wc -l) IP(s) to {self.chain}."')
        logger.debug("Commit script assembled.")
        return "\n".join(script) + "\n"
