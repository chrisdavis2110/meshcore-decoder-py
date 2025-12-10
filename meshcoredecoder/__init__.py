"""MeshCore Decoder - Python implementation"""
from .decoder.packet_decoder import MeshCorePacketDecoder

# Main class export (shorter name for convenience)
MeshCoreDecoder = MeshCorePacketDecoder

__all__ = ['MeshCoreDecoder', 'MeshCorePacketDecoder']
__version__ = "0.2.2"
