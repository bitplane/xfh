"""XPK PPMQ decompression.

Derived from Ancient's PPMQDecompressor, Copyright (c) 2017-2026
Teemu Suutari, under the BSD 2-Clause License.
"""

from dataclasses import dataclass
from typing import TypeAlias

from xfh.codecs import register
from xfh.codecs._range import RangeDecoder
from xfh.codecs._streams import BitReader, ByteInput
from xfh.errors import CorruptDataError


class _Inclusion:
    def __init__(self) -> None:
        self.values = [True] * 256

    def reset(self) -> None:
        self.values[:] = [True] * 256

    def exclude(self, symbol: int) -> None:
        self.values[symbol] = False

    def decode(self, value: int) -> tuple[int, int]:
        low = 0
        for symbol, included in enumerate(self.values):
            if included:
                if value == low:
                    return symbol, low
                low += 1
        raise CorruptDataError("invalid PPMQ fallback symbol")

    @property
    def total(self) -> int:
        return sum(self.values)


@dataclass(slots=True)
class _Node:
    frequency: int
    symbol: int


@dataclass(slots=True)
class _Context:
    escape: int
    nodes: list[_Node]


_Key: TypeAlias = int | tuple[int, int] | tuple[int, int, int]


class _ContextModel:
    def __init__(
        self,
        decoder: RangeDecoder,
        inclusion: _Inclusion,
        key,
        *,
        singleton: bool,
    ):
        self.decoder = decoder
        self.inclusion = inclusion
        self.key = key
        self.singleton = singleton
        self.contexts: dict[_Key, _Context] = {}
        self.delayed: _Key | None = None
        if singleton:
            self.binary_frequencies = [[1] * 18 for _ in range(32)]
            self.binary_totals = [
                [2 if count == 0 else count * 4 + 1 for count in range(18)] for _ in range(32)
            ]

    def _total(self, context: _Context) -> int:
        return sum(node.frequency for node in context.nodes if self.inclusion.values[node.symbol])

    def _exclude_all(self, context: _Context) -> None:
        for node in context.nodes:
            self.inclusion.exclude(node.symbol)

    def _scale(self, context: _Context, known_total: int) -> None:
        if known_total + context.escape != 0x4000:
            return
        context.escape = (context.escape >> 1) + 1
        scaled = []
        for node in context.nodes:
            node.frequency >>= 1
            if node.frequency:
                scaled.append(node)
        context.nodes = scaled

    def _decode_node(self, context: _Context, target: int) -> tuple[_Node, int]:
        low = 0
        for index, node in enumerate(context.nodes):
            if not self.inclusion.values[node.symbol]:
                continue
            if target < low + node.frequency:
                context.nodes.insert(0, context.nodes.pop(index))
                return context.nodes[0], low
            low += node.frequency
        raise CorruptDataError("invalid PPMQ context symbol")

    def _decode_singleton(self, key: _Key, context: _Context) -> int | None:
        node = context.nodes[0]
        count = min(node.frequency, 17)
        assert isinstance(key, tuple) and len(key) == 3
        index = key[0] & 0x1F
        frequencies = self.binary_frequencies[index]
        totals = self.binary_totals[index]
        if totals[count] > 16300:
            frequencies[count] >>= 1
            totals[count] >>= 1
            if not frequencies[count]:
                frequencies[count] = 1
                totals[count] += 20
        if self.inclusion.values[node.symbol]:
            frequency = frequencies[count]
            total = totals[count]
            value = self.decoder.decode(total)
            if value < frequency:
                self.decoder.scale(0, frequency, total)
                self.inclusion.exclude(node.symbol)
            else:
                self.decoder.scale(frequency, total, total)
                node.frequency += 1
                totals[count] += 20
                return node.symbol
        context.escape += 1
        frequencies[count] += 20
        totals[count] += 20
        self.delayed = key
        return None

    def decode(self, history: int, history5: int) -> int | None:
        key = self.key(history, history5)
        context = self.contexts.get(key)
        if context is None:
            self.delayed = key
            return None
        if self.singleton and len(context.nodes) == 1:
            return self._decode_singleton(key, context)

        known_total = self._total(context)
        total = known_total + context.escape
        value = self.decoder.decode(total)
        if value < context.escape:
            self.decoder.scale(0, context.escape, total)
            self._exclude_all(context)
            context.escape += 1
            self._scale(context, known_total)
            self.delayed = key
            return None

        node, low = self._decode_node(context, value - context.escape)
        self.decoder.scale(
            context.escape + low,
            context.escape + low + node.frequency,
            total,
        )
        if node.frequency == 1 and context.escape > 1:
            context.escape -= 1
        node.frequency += 1
        self._scale(context, known_total + 1)
        return node.symbol

    def mark(self, symbol: int) -> None:
        if self.delayed is None:
            return
        context = self.contexts.get(self.delayed)
        if context is None:
            self.contexts[self.delayed] = _Context(1, [_Node(1, symbol)])
        else:
            context.nodes.insert(0, _Node(1, symbol))
        self.delayed = None


class _OrderZero:
    def __init__(self, decoder: RangeDecoder, inclusion: _Inclusion):
        self.decoder = decoder
        self.inclusion = inclusion
        self.frequencies = [0] * 256
        self.escape = 1

    def decode(self, history: int, history5: int) -> int:
        del history, history5
        known_total = sum(
            frequency
            for symbol, frequency in enumerate(self.frequencies)
            if self.inclusion.values[symbol]
        )
        total = known_total + self.escape
        value = self.decoder.decode(total)
        if value < self.escape:
            self.decoder.scale(0, self.escape, total)
            for symbol, frequency in enumerate(self.frequencies):
                if frequency:
                    self.inclusion.exclude(symbol)
            included = self.inclusion.total
            if not included:
                raise CorruptDataError("PPMQ excluded every fallback symbol")
            value = self.decoder.decode(included)
            symbol, low = self.inclusion.decode(value)
            self.decoder.scale(low, low + 1, included)
            self.frequencies[symbol] = 1
            self.escape += 1
            return symbol

        low = 0
        for symbol, frequency in enumerate(self.frequencies):
            if not self.inclusion.values[symbol]:
                continue
            if value - self.escape < low + frequency:
                break
            low += frequency
        else:
            raise CorruptDataError("invalid PPMQ order-zero symbol")
        self.decoder.scale(
            self.escape + low,
            self.escape + low + frequency,
            total,
        )
        if frequency == 1 and self.escape > 1:
            self.escape -= 1
        self.frequencies[symbol] += 1
        return symbol

    def mark(self, symbol: int) -> None:
        del symbol


@register("PPMQ")
def decompress_ppmq(payload: bytes, output_size: int, previous: bytes = b"") -> bytes:
    """Decode one PPMQ prediction-by-partial-matching chunk."""

    del previous
    if len(payload) < min(output_size, 5):
        raise CorruptDataError("truncated PPMQ prefix")
    output = bytearray(payload[: min(output_size, 5)])
    if len(output) == output_size:
        return bytes(output)
    if len(payload) < 7:
        raise CorruptDataError("truncated PPMQ arithmetic stream")

    source = ByteInput(payload[5:] + bytes(16))
    bits = BitReader(source.word, 32)
    decoder = RangeDecoder(bits)
    inclusion = _Inclusion()
    history = int.from_bytes(output[-4:], "big")
    history5 = output[-5]

    def key2a(value: int, fifth: int) -> _Key:
        return value, (value ^ (value >> 15)) & 0xFFFF, fifth

    def key2b(value: int, fifth: int) -> _Key:
        del fifth
        return value, (value ^ (value >> 15)) & 0xFFFF, 0

    def key1a(value: int, fifth: int) -> _Key:
        del fifth
        return value & 0xFFFFFF, (value ^ (value >> 7)) & 0xFFFF

    def key1b(value: int, fifth: int) -> _Key:
        del fifth
        return value & 0xFFFF, value & 0xFFFF

    def key1c(value: int, fifth: int) -> _Key:
        del fifth
        return value & 0xFF, value & 0xFF

    models = [
        _ContextModel(decoder, inclusion, key2a, singleton=True),
        _ContextModel(decoder, inclusion, key2b, singleton=True),
        _ContextModel(decoder, inclusion, key1a, singleton=False),
        _ContextModel(decoder, inclusion, key1b, singleton=False),
        _ContextModel(decoder, inclusion, key1c, singleton=False),
        _OrderZero(decoder, inclusion),
    ]

    while len(output) < output_size:
        inclusion.reset()
        for index, model in enumerate(models):
            symbol = model.decode(history, history5)
            if symbol is None:
                continue
            for higher_model in models[:index]:
                higher_model.mark(symbol)
            history5 = (history >> 24) & 0xFF
            history = ((history << 8) | symbol) & 0xFFFF_FFFF
            output.append(symbol)
            break
        else:
            raise CorruptDataError("PPMQ model chain produced no symbol")
    return bytes(output)
