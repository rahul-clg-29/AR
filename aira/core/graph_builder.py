"""
AIRA Temporal Causal Attack Graph Builder
Constructs directed provenance graphs from canonical security events and computes
backward root-cause lineage and forward blast-radius reachability.
"""

from typing import List, Dict, Any, Set, Tuple, Optional
import networkx as nx
from aira.core.models import CanonicalEvent, EventType


class AttackGraphBuilder:
    """
    Builds a causal provenance graph of system entities (Processes, Network Sockets,
    Files, and Registry modifications) to reconstruct attack paths and context.
    """

    def __init__(self):
        self.graph = nx.DiGraph()
        self.process_lookup: Dict[Tuple[str, int], str] = {}  # (host, pid) -> node_id

    def _process_node_id(self, host: str, pid: int, image: str) -> str:
        img_name = image.replace("\\", "/").split("/")[-1] if image else "unknown"
        return f"proc:{host}:{pid}:{img_name}"

    def _net_node_id(self, dst_ip: str, dst_port: int) -> str:
        return f"net:{dst_ip}:{dst_port}"

    def _file_node_id(self, host: str, path: str) -> str:
        return f"file:{host}:{path.lower()}"

    def _reg_node_id(self, host: str, key_path: str) -> str:
        return f"reg:{host}:{key_path.lower()}"

    def add_event(self, event: CanonicalEvent):
        """
        Incrementally adds a single CanonicalEvent into the causal provenance graph.
        """
        host = event.host
        ts = event.timestamp.isoformat()
        rid = event.record_id

        if event.event_type == EventType.PROCESS_CREATE and event.process:
            proc = event.process
            proc_node = self._process_node_id(host, proc.pid, proc.image)
            self.process_lookup[(host, proc.pid)] = proc_node

            self.graph.add_node(
                proc_node,
                node_type="process",
                pid=proc.pid,
                image=proc.image,
                command_line=proc.command_line,
                user=proc.user,
                host=host,
                first_seen=ts,
                last_seen=ts,
            )

            # Connect parent to child if parent exists
            if proc.parent_pid:
                parent_node = self.process_lookup.get((host, proc.parent_pid))
                if not parent_node:
                    # Create parent placeholder node
                    parent_node = self._process_node_id(host, proc.parent_pid, proc.parent_image or "unknown")
                    self.graph.add_node(
                        parent_node,
                        node_type="process",
                        pid=proc.parent_pid,
                        image=proc.parent_image or "unknown",
                        command_line=proc.parent_command_line or "",
                        user=proc.user,
                        host=host,
                        first_seen=ts,
                        last_seen=ts,
                    )
                    self.process_lookup[(host, proc.parent_pid)] = parent_node

                self.graph.add_edge(
                    parent_node,
                    proc_node,
                    relation="SPAWNED",
                    timestamp=ts,
                    record_id=rid,
                    details=f"Spawned {proc.image} ({proc.pid})"
                )

        elif event.event_type == EventType.NETWORK_CONNECT and event.network and event.process:
            proc = event.process
            net = event.network
            proc_node = self.process_lookup.get((host, proc.pid)) or self._process_node_id(host, proc.pid, proc.image)
            net_node = self._net_node_id(net.dst_ip, net.dst_port)

            if proc_node not in self.graph:
                self.graph.add_node(proc_node, node_type="process", pid=proc.pid, image=proc.image, host=host)

            self.graph.add_node(
                net_node,
                node_type="network",
                dst_ip=net.dst_ip,
                dst_port=net.dst_port,
                protocol=net.protocol
            )

            self.graph.add_edge(
                proc_node,
                net_node,
                relation="CONNECTED_TO",
                timestamp=ts,
                record_id=rid,
                details=f"Outbound connection to {net.dst_ip}:{net.dst_port}/{net.protocol}"
            )

        elif event.event_type == EventType.FILE_CREATE and event.file and event.process:
            proc = event.process
            f = event.file
            proc_node = self.process_lookup.get((host, proc.pid)) or self._process_node_id(host, proc.pid, proc.image)
            file_node = self._file_node_id(host, f.path)

            if proc_node not in self.graph:
                self.graph.add_node(proc_node, node_type="process", pid=proc.pid, image=proc.image, host=host)

            self.graph.add_node(
                file_node,
                node_type="file",
                path=f.path,
                hashes=f.hashes,
                host=host
            )

            self.graph.add_edge(
                proc_node,
                file_node,
                relation="WROTE_FILE",
                timestamp=ts,
                record_id=rid,
                details=f"Dropped file {f.path}"
            )

        elif event.event_type == EventType.REGISTRY_SET and event.registry and event.process:
            proc = event.process
            reg = event.registry
            proc_node = self.process_lookup.get((host, proc.pid)) or self._process_node_id(host, proc.pid, proc.image)
            reg_node = self._reg_node_id(host, reg.key_path)

            if proc_node not in self.graph:
                self.graph.add_node(proc_node, node_type="process", pid=proc.pid, image=proc.image, host=host)

            self.graph.add_node(
                reg_node,
                node_type="registry",
                key_path=reg.key_path,
                value_data=reg.value_data,
                host=host
            )

            self.graph.add_edge(
                proc_node,
                reg_node,
                relation="MODIFIED_REGISTRY",
                timestamp=ts,
                record_id=rid,
                details=f"Set registry {reg.key_path} -> {reg.value_data}"
            )

        elif event.event_type == EventType.PROCESS_ACCESS and event.process:
            proc = event.process
            proc_node = self.process_lookup.get((host, proc.pid)) or self._process_node_id(host, proc.pid, proc.image)
            if proc_node not in self.graph:
                self.graph.add_node(proc_node, node_type="process", pid=proc.pid, image=proc.image, host=host)

    def build_graph(self, events: List[CanonicalEvent]) -> nx.DiGraph:
        """
        Populate the directed graph with nodes and causal edges from chronological events.
        """
        self.graph.clear()
        self.process_lookup.clear()

        for event in events:
            self.add_event(event)

        # Correlate cross-host lateral movement bridges
        self._correlate_lateral_movement(events)

        return self.graph

    def _correlate_lateral_movement(self, events: List[CanonicalEvent]):
        """
        Cross-Host Causal Chaining:
        Correlates internal administrative connections (SMB/RPC/WMI/WinRM) from Host-A
        with subsequent authentication, service spawning, or execution on Host-B.
        """
        ip_to_host: Dict[str, str] = {}
        for e in events:
            if e.network and e.network.src_ip and not e.network.src_ip.startswith("127."):
                ip_to_host[e.network.src_ip] = e.host

        admin_ports = {445, 135, 5985, 5986, 3389, 22}

        for e in events:
            if e.event_type == EventType.NETWORK_CONNECT and e.network and e.process:
                dst_ip = e.network.dst_ip
                dst_port = e.network.dst_port

                is_internal = (
                    dst_ip.startswith("10.") or
                    dst_ip.startswith("192.168.") or
                    (dst_ip.startswith("172.") and 16 <= int(dst_ip.split(".")[1]) <= 31)
                )

                if is_internal and dst_port in admin_ports:
                    target_host = ip_to_host.get(dst_ip)
                    if not target_host or target_host == e.host:
                        for ev in events:
                            if ev.host != e.host and ev.network and (ev.network.src_ip == dst_ip or ev.network.dst_ip == dst_ip):
                                target_host = ev.host
                                break
                    if not target_host or target_host == e.host:
                        other_hosts = [h for h in {ev.host for ev in events} if h != e.host]
                        if other_hosts:
                            target_host = other_hosts[0]

                    if not target_host or target_host == e.host:
                        continue

                    net_node = self._net_node_id(dst_ip, dst_port)
                    target_candidates = []
                    t_e = e.timestamp.replace(tzinfo=None) if e.timestamp.tzinfo else e.timestamp
                    for ev in events:
                        t_ev = ev.timestamp.replace(tzinfo=None) if ev.timestamp.tzinfo else ev.timestamp
                        if ev.host == target_host and t_ev >= t_e:
                            delta_sec = (t_ev - t_e).total_seconds()
                            if 0 <= delta_sec <= 300:
                                if ev.event_type == EventType.PROCESS_CREATE and ev.process:
                                    target_candidates.append(ev)

                    if target_candidates:
                        pivot_event = target_candidates[0]
                        pivot_proc = pivot_event.process
                        pivot_node = self.process_lookup.get((target_host, pivot_proc.pid)) or self._process_node_id(target_host, pivot_proc.pid, pivot_proc.image)

                        anchor_node = pivot_node
                        if pivot_proc.parent_pid:
                            parent_node = self.process_lookup.get((target_host, pivot_proc.parent_pid))
                            if parent_node and parent_node in self.graph:
                                anchor_node = parent_node

                        if net_node in self.graph and anchor_node in self.graph:
                            proto_name = "SMB" if dst_port == 445 else "WMI/RPC" if dst_port == 135 else "WinRM" if dst_port in [5985, 5986] else "RDP"
                            self.graph.add_edge(
                                net_node,
                                anchor_node,
                                relation="LATERAL_MOVEMENT",
                                protocol=proto_name,
                                port=dst_port,
                                source_host=e.host,
                                target_host=target_host,
                                timestamp=pivot_event.timestamp.isoformat(),
                                record_id=f"{e.record_id}->{pivot_event.record_id}",
                                details=f"Cross-host lateral pivot: {e.host} connected to {target_host} ({dst_ip}:{dst_port}/{proto_name}), executing {pivot_proc.image}"
                            )

    def find_root_causes(self, target_node: str) -> List[str]:
        """
        Backward provenance traversal: find ancestor nodes with in-degree 0.
        """
        if target_node not in self.graph:
            return []

        ancestors = nx.ancestors(self.graph, target_node) | {target_node}
        root_nodes = [node for node in ancestors if self.graph.in_degree(node) == 0]
        return root_nodes

    def find_blast_radius(self, target_node: str) -> List[str]:
        """
        Forward reachability: find all child processes, sockets, and files touched.
        """
        if target_node not in self.graph:
            return []

        descendants = list(nx.descendants(self.graph, target_node))
        return descendants

    def extract_causal_subgraph(self, suspicious_nodes: List[str]) -> nx.DiGraph:
        """
        Extract the full causal closure (ancestors + descendants) around a set of suspicious nodes.
        """
        nodes_to_include: Set[str] = set()
        for node in suspicious_nodes:
            if node in self.graph:
                nodes_to_include.add(node)
                nodes_to_include.update(nx.ancestors(self.graph, node))
                nodes_to_include.update(nx.descendants(self.graph, node))

        return self.graph.subgraph(nodes_to_include).copy()

    def filter_noise(self, suspicious_nodes: List[str]) -> Tuple[nx.DiGraph, Dict[str, Any]]:
        """
        Causal Subgraph Pruning: isolates the attack subgraph from benign background enterprise noise.
        Returns the pruned subgraph and quantitative noise reduction metrics.
        """
        subgraph = self.extract_causal_subgraph(suspicious_nodes)
        total_raw_nodes = self.graph.number_of_nodes()
        attack_nodes_count = subgraph.number_of_nodes()
        noise_nodes_filtered = total_raw_nodes - attack_nodes_count

        total_raw_edges = self.graph.number_of_edges()
        attack_edges_count = subgraph.number_of_edges()
        noise_edges_filtered = total_raw_edges - attack_edges_count

        noise_reduction_pct = round((noise_nodes_filtered / total_raw_nodes * 100), 1) if total_raw_nodes > 0 else 0.0

        metrics = {
            "total_raw_nodes": total_raw_nodes,
            "attack_nodes_count": attack_nodes_count,
            "noise_nodes_filtered": noise_nodes_filtered,
            "noise_reduction_pct": noise_reduction_pct,
            "total_raw_edges": total_raw_edges,
            "attack_edges_count": attack_edges_count,
            "noise_edges_filtered": noise_edges_filtered,
            "attack_subgraph_nodes": list(subgraph.nodes()),
        }
        return subgraph, metrics

    def get_summary(self) -> Dict[str, Any]:
        """
        Summary metrics of the constructed graph.
        """
        types_count: Dict[str, int] = {}
        for _, data in self.graph.nodes(data=True):
            t = data.get("node_type", "unknown")
            types_count[t] = types_count.get(t, 0) + 1

        relations_count: Dict[str, int] = {}
        for _, _, data in self.graph.edges(data=True):
            r = data.get("relation", "unknown")
            relations_count[r] = relations_count.get(r, 0) + 1

        return {
            "total_nodes": self.graph.number_of_nodes(),
            "total_edges": self.graph.number_of_edges(),
            "node_distribution": types_count,
            "relation_distribution": relations_count
        }
