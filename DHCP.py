from scapy.layers.dhcp import BOOTP, DHCP
from scapy.layers.inet import UDP


from models import RouterPort


class DHCPManger:
    def handle(self, port: RouterPort, packet: UDP) -> None:
        message = packet.payload
        if not isinstance(message, BOOTP) or not isinstance(message.payload, DHCP):
            return
        if message.options != b"\x63\x82\x53\x63":
            return

        options = message.payload.original or bytes(message.payload)
        position = 0
        message_type = None
        while position < len(options):
            code = options[position]
            position += 1
            if code == 0:
                continue
            if code == 255:
                break

            if position == len(options):
                return
            length = options[position]
            position += 1
            if position + length > len(options):
                return

            if code == 53:
                if length != 1:
                    return
                message_type = options[position]
            position += length

        if message_type is None:
            return
