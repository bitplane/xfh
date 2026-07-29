"""XPK SASC and SHSC decompression.

Derived from Ancient's SXSCDecompressor, Copyright (c) 2017-2026
Teemu Suutari, under the BSD 2-Clause License.
"""

from dataclasses import dataclass, field

from xfh.codecs import register
from xfh.codecs._range import RangeDecoder
from xfh.codecs._streams import BitReader, ByteInput, copy_forward
from xfh.errors import CorruptDataError


class _AdaptiveTable:
    def __init__(self, size: int, initial: int):
        self.size = size
        self.values = [initial] * size + [0] * (size - 1)
        self._rebuild()

    @property
    def total(self) -> int:
        return self.values[-1]

    def _rebuild(self) -> None:
        for target, source in zip(
            range(self.size, self.size * 2 - 1),
            range(0, (self.size - 1) * 2, 2),
            strict=True,
        ):
            self.values[target] = self.values[source] + self.values[source + 1]

    def update(self, maximum: int, symbol: int, amount: int) -> None:
        index = symbol
        while index < self.size * 2 - 1:
            self.values[index] += amount
            index = (index >> 1) + self.size
        if self.total >= maximum:
            for index in range(self.size):
                if self.values[index] > 1:
                    self.values[index] >>= 1
            self._rebuild()

    def decode(self, value: int) -> tuple[int, int]:
        if not 0 <= value < self.total:
            raise CorruptDataError("invalid SXSC arithmetic symbol")
        low = 0
        index = self.size * 2 - 4
        while index >= self.size:
            child = (index - self.size) << 1
            if value - low >= self.values[index]:
                low += self.values[index]
                child += 2
            index = child
        if value - low >= self.values[index]:
            low += self.values[index]
            index += 1
        return index, low


def _two_step(
    decoder: RangeDecoder,
    initial: _AdaptiveTable,
    dynamic: _AdaptiveTable,
    threshold: int,
    maximum: int,
    step: int,
    update_range: int,
) -> tuple[int, int]:
    value = decoder.decode(dynamic.total + threshold)
    if value < dynamic.total:
        symbol, low = dynamic.decode(value)
        decoder.scale(low, low + dynamic.values[symbol], dynamic.total + threshold)
    else:
        decoder.scale(dynamic.total, dynamic.total + threshold, dynamic.total + threshold)
        value = decoder.decode(initial.total)
        symbol, low = initial.decode(value)
        decoder.scale(low, low + initial.values[symbol], initial.total)
        initial.update(0xFFFF, symbol, -initial.values[symbol])
        threshold = threshold + step if initial.total else 0
        start = max(0, symbol - update_range)
        stop = min(symbol + update_range, initial.size - 1)
        for candidate in range(start, stop):
            if initial.values[candidate]:
                initial.update(maximum, candidate, 1)
    dynamic.update(maximum, symbol, step)
    if dynamic.values[symbol] == step * 3:
        threshold = threshold - step if threshold > step else 1
    return symbol, threshold


def _decode_sasc(data: bytes, output_size: int) -> bytes:
    if len(data) < 2:
        raise CorruptDataError("truncated SASC arithmetic stream")
    source = ByteInput(data + bytes(3))
    initial = source.word(2)
    decoder = RangeDecoder(BitReader(source.word, 8), initial)

    decision = [[40, 40] for _ in range(4)]
    decision_position = 0
    literals_initial = _AdaptiveTable(256, 1)
    literals_dynamic = _AdaptiveTable(256, 0)
    literal_threshold = 1
    distance_codes = _AdaptiveTable(16, 0)
    counts_initial = _AdaptiveTable(64, 1)
    counts_dynamic = _AdaptiveTable(64, 0)
    count_threshold = 8
    distance_codes.update(6000, 0, 24)
    distance_index = 0
    output = bytearray()

    while True:
        literal_frequency, copy_frequency = decision[decision_position]
        total = literal_frequency + copy_frequency
        value = decoder.decode(total + 1)
        if value == total:
            break
        literal = value < literal_frequency
        low = 0 if literal else literal_frequency
        high = literal_frequency if literal else total
        decoder.scale(low, high, total + 1)
        decision[decision_position][0 if literal else 1] += 40
        if total >= 6000:
            decision[decision_position][0] = max(1, decision[decision_position][0] >> 1)
            decision[decision_position][1] = max(1, decision[decision_position][1] >> 1)
        decision_position = ((decision_position << 1) & 2) | (0 if literal else 1)

        if literal:
            symbol, literal_threshold = _two_step(
                decoder,
                literals_initial,
                literals_dynamic,
                literal_threshold,
                1000,
                1,
                8,
            )
            if len(output) >= output_size:
                raise CorruptDataError("decoded SASC chunk exceeds declared size")
            output.append(symbol)
            continue

        while len(output) > 1 << distance_index and distance_index < 15:
            distance_index += 1
            distance_codes.update(6000, distance_index, 24)
        value = decoder.decode(distance_codes.total)
        distance_bits, low = distance_codes.decode(value)
        decoder.scale(low, low + distance_codes.values[distance_bits], distance_codes.total)
        distance_codes.update(6000, distance_bits, 24)
        distance = distance_bits
        if distance_bits >= 2:
            minimum = 1 << (distance_bits - 1)
            distance_range = (
                min(len(output), 31200) - minimum if distance_index == distance_bits else minimum
            )
            if distance_range <= 0:
                raise CorruptDataError("invalid SASC distance range")
            distance = decoder.decode(distance_range)
            decoder.scale(distance, distance + 1, distance_range)
            distance += minimum
        distance += 1

        count, count_threshold = _two_step(
            decoder,
            counts_initial,
            counts_dynamic,
            count_threshold,
            6000,
            8,
            4,
        )
        if count == 15:
            count = 783
        elif count >= 16:
            extra = decoder.decode(16)
            decoder.scale(extra, extra + 1, 16)
            count = ((count - 16) << 4) + extra + 15
        copy_forward(output, distance, count + 3, output_size)

    if len(output) != output_size:
        raise CorruptDataError("SASC end marker precedes declared output size")
    return bytes(output)


@dataclass(slots=True)
class _HscModel:
    context: list[int] = field(default_factory=lambda: [0] * 4)
    hash_pointer: int = 0
    expiry_previous: int = 0
    expiry_next: int = 0
    frequency_total: int = 0
    escape_frequency: int = 0
    context_length: int = 0xFF
    character_count: int = 0
    refresh_counter: int = 0


@dataclass(slots=True)
class _HscFrequency:
    frequency: int = 0
    next: int = 0xFFFF
    character: int = 0


@dataclass(slots=True)
class _HscHash:
    data: int = 0xFFFF
    random: int = 0


def _decode_shsc(data: bytes, output_size: int) -> bytes:
    if len(data) < 2:
        raise CorruptDataError("truncated SHSC arithmetic stream")
    source = ByteInput(data + bytes(3))
    decoder = RangeDecoder(BitReader(source.word, 8), source.word(2))

    max_context_length = 4
    drop_count = 2500
    models = [_HscModel() for _ in range(10000)]
    for index, model in enumerate(models):
        model.expiry_previous = (index - 1) & 0xFFFF
        model.expiry_next = index + 1
    frequencies = [_HscFrequency() for _ in range(32760)]
    for index in range(10000, 32759):
        frequencies[index].next = index + 1
    hashes = [_HscHash() for _ in range(0x4000)]
    random_value = 10
    for item in hashes:
        integer = random_value // 127773
        fraction = random_value % 127773
        temporary = 16807 * fraction - 2836 * integer
        random_value = temporary + 0x7FFF_FFFF if temporary < 0 else temporary
        item.random = random_value & 0x3FFF

    current_context = [0] * 4
    hash_stack = [0] * 5
    first_expiry = 0
    last_expiry = 9999
    free_block_pointer = 10000
    release_block = 0
    character_mask = [False] * 256
    character_mask_stack: list[int] = []
    initial_escape = [16, 15, 15, 15, 15]
    escape_counter = 0
    context_pointers = [0] * 5
    frequency_indices = [0] * 5
    output = bytearray()

    def checked_index(index: int, size: int, message: str) -> int:
        if not 0 <= index < size:
            raise CorruptDataError(message)
        return index

    def chain(start: int, *, model_chain: bool = False):
        index = start
        for _ in range(0x8000):
            if index == 0xFFFF:
                return
            checked_index(index, len(models if model_chain else frequencies), "invalid SHSC chain")
            yield index
            index = models[index].hash_pointer if model_chain else frequencies[index].next
        raise CorruptDataError("cyclic SHSC chain")

    def context_hash(block: list[int], length: int) -> int:
        result = 0
        for index in range(length):
            result = hashes[(block[index] + result) & 0x3FFF].random
        return result

    def find_next(search_length: int) -> tuple[int, int]:
        for length in range(search_length - 1, -1, -1):
            for index in chain(hashes[hash_stack[length]].data, model_chain=True):
                model = models[index]
                if (
                    length == model.context_length
                    and current_context[:length] == model.context[:length]
                ):
                    return index, length
        return 0xFFFF, search_length

    def escape_frequency(value: int, index: int) -> int:
        model = models[index]
        if model.frequency_total == 1:
            return 2 if initial_escape[model.context_length] >= 16 else 1
        if model.character_count == 0xFF:
            return 1
        temporary = model.character_count * 2 + 2
        if model.character_count and temporary >= model.frequency_total:
            value = value * temporary // model.frequency_total
            if model.character_count + 1 == model.frequency_total:
                value += temporary >> 2
        return max(value, 1)

    while True:
        for index in range(4):
            hash_stack[index + 1] = hashes[
                (current_context[index] + hash_stack[index]) & 0x3FFF
            ].random
        while character_mask_stack:
            character_mask[character_mask_stack.pop()] = False
        context_index, search_length = find_next(5)
        minimum_length = models[context_index].context_length + 1 if context_index != 0xFFFF else 0
        stack_size = 0
        character = 256

        while True:
            if context_index == 0xFFFF:
                total = 257 - len(character_mask_stack)
                value = decoder.decode(total)
                rank = 0
                for character in range(257):
                    if character < 256 and character_mask[character]:
                        continue
                    if rank >= value:
                        break
                    rank += 1
                decoder.scale(rank, rank + 1, total)
                break

            model = models[context_index]
            known = 0
            escape = 0
            cumulative = 0
            selected_frequency = 0
            had_mask = bool(character_mask_stack)

            if had_mask:
                for frequency_index in chain(context_index):
                    frequency = frequencies[frequency_index]
                    if not character_mask[frequency.character]:
                        known += frequency.frequency
                        if frequency.frequency < 3:
                            escape += 1
                escape = escape_frequency(escape, context_index)
                shift = 0
                include_masked = False
            else:
                known = model.frequency_total
                escape = escape_frequency(model.escape_frequency, context_index)
                shift = (
                    2
                    if escape_counter >= 5 and known < 5 and escape_counter == 10
                    else 1
                    if escape_counter >= 5
                    else 0
                )
                include_masked = True

            scaled_known = known << shift
            value = decoder.decode(scaled_known + escape) >> shift
            selected_index = 0xFFFF
            for frequency_index in chain(context_index):
                frequency = frequencies[frequency_index]
                if include_masked or not character_mask[frequency.character]:
                    if cumulative + frequency.frequency <= value:
                        cumulative += frequency.frequency
                    else:
                        selected_frequency = frequency.frequency << shift
                        selected_index = frequency_index
                        break
            cumulative <<= shift

            insert_position = stack_size if had_mask else 0
            if selected_index == 0xFFFF:
                decoder.scale(scaled_known, scaled_known + escape, scaled_known + escape)
                if model.frequency_total == 1 and initial_escape[model.context_length] < 32:
                    initial_escape[model.context_length] += 1
                previous_index = 0
                for frequency_index in chain(context_index):
                    frequency = frequencies[frequency_index]
                    if include_masked or not character_mask[frequency.character]:
                        if len(character_mask_stack) == 256:
                            raise CorruptDataError("SHSC character mask overflow")
                        character_mask_stack.append(frequency.character)
                        character_mask[frequency.character] = True
                    previous_index = frequency_index
                context_pointers[insert_position] = context_index | 0x8000
                frequency_indices[insert_position] = previous_index
                character = 256
                escaped = True
            else:
                decoder.scale(
                    cumulative,
                    cumulative + selected_frequency,
                    scaled_known + escape,
                )
                if model.frequency_total == 1 and initial_escape[model.context_length]:
                    initial_escape[model.context_length] -= 1
                context_pointers[insert_position] = context_index
                frequency_indices[insert_position] = selected_index
                character = frequencies[selected_index].character
                escaped = False

            if had_mask:
                if stack_size == 5:
                    raise CorruptDataError("SHSC context stack overflow")
                if not escaped:
                    if escape_counter == 10:
                        raise CorruptDataError("invalid SHSC escape depth")
                    escape_counter += 1
                stack_size += 1
            else:
                stack_size = 1
                if escaped:
                    escape_counter = 0
                elif escape_counter < 10:
                    escape_counter += 1

            if character != 256:
                if context_index != first_expiry:
                    if context_index == last_expiry:
                        last_expiry = model.expiry_previous
                    else:
                        models[model.expiry_next].expiry_previous = model.expiry_previous
                        models[model.expiry_previous].expiry_next = model.expiry_next
                    models[first_expiry].expiry_previous = context_index
                    model.expiry_next = first_expiry
                    first_expiry = context_index
                break
            context_index, search_length = find_next(search_length)

        if character == 256:
            break

        while stack_size:
            stack_size -= 1
            frequency_index = frequency_indices[stack_size]
            pointer = context_pointers[stack_size]
            model_index = pointer & 0x7FFF
            checked_index(model_index, len(models), "invalid SHSC model pointer")
            model = models[model_index]
            if pointer & 0x8000:
                if free_block_pointer == 0xFFFF:
                    protected = {
                        context_pointers[index] & 0x7FFF for index in range(stack_size + 1)
                    }
                    for _ in range(10000):
                        release_block = release_block + 1 if release_block != 9999 else 0
                        if (
                            frequencies[release_block].next != 0xFFFF
                            and release_block not in protected
                        ):
                            break
                    else:
                        raise CorruptDataError("SHSC frequency pool exhausted")

                    released_frequency = frequencies[release_block]
                    released_model = models[release_block]
                    divisor = released_frequency.frequency
                    for index in chain(released_frequency.next):
                        divisor = min(divisor, frequencies[index].frequency)
                    stop = False
                    divisor += 1
                    if released_frequency.frequency < divisor:
                        index = released_frequency.next
                        for _ in range(0x8000):
                            checked_index(index, len(frequencies), "invalid SHSC release chain")
                            if (
                                frequencies[index].frequency >= divisor
                                or frequencies[index].next == 0xFFFF
                            ):
                                break
                            index = frequencies[index].next
                        else:
                            raise CorruptDataError("cyclic SHSC release chain")
                        replacement = frequencies[index]
                        released_frequency.frequency = replacement.frequency
                        released_frequency.character = replacement.character
                        following = replacement.next
                        replacement.next = free_block_pointer
                        free_block_pointer = released_frequency.next
                        released_frequency.next = following
                        if following == 0xFFFF:
                            released_model.character_count = 0
                            released_model.frequency_total = released_frequency.frequency
                            released_model.escape_frequency = (
                                1 if released_frequency.frequency < 3 else 0
                            )
                            stop = True
                    if not stop:
                        released_model.character_count = 0
                        released_frequency.frequency //= divisor
                        released_model.frequency_total = released_frequency.frequency
                        released_model.escape_frequency = (
                            1 if released_frequency.frequency < 3 else 0
                        )
                        previous = release_block
                        index = released_frequency.next
                        for _ in range(0x8000):
                            if index == 0xFFFF:
                                break
                            following = frequencies[index].next
                            if frequencies[index].frequency < divisor:
                                frequencies[previous].next = following
                                frequencies[index].next = free_block_pointer
                                free_block_pointer = index
                            else:
                                released_model.character_count += 1
                                frequencies[index].frequency //= divisor
                                value = frequencies[index].frequency
                                if value < 3:
                                    released_model.escape_frequency += 1
                                released_model.frequency_total += value
                                previous = index
                            index = following
                        else:
                            raise CorruptDataError("cyclic SHSC scaling chain")

                checked_index(free_block_pointer, len(frequencies), "invalid SHSC free block")
                frequencies[frequency_index].next = free_block_pointer
                frequency_index = free_block_pointer
                free_block_pointer = frequencies[free_block_pointer].next
                frequency = frequencies[frequency_index]
                frequency.frequency = 1
                frequency.next = 0xFFFF
                frequency.character = character
                model.escape_frequency += 1
                model.character_count = (model.character_count + 1) & 0xFF
            else:
                frequency = frequencies[frequency_index]
                frequency.frequency += 1
                if frequency.frequency == 3:
                    model.escape_frequency -= 1

            model.frequency_total += 1
            if model.frequency_total // (model.character_count + 1) > frequency.frequency * 2:
                model.refresh_counter = (model.refresh_counter - 1) & 0xFF
            elif model.refresh_counter < 4:
                model.refresh_counter += 1
            if not model.refresh_counter or model.frequency_total >= 8000:
                model.refresh_counter = (model.refresh_counter + 1) & 0xFF
                model.escape_frequency = 0
                model.frequency_total = 0
                for index in chain(model_index):
                    item = frequencies[index]
                    if item.frequency > 1:
                        item.frequency >>= 1
                    model.frequency_total += item.frequency
                    if item.frequency < 3:
                        model.escape_frequency += 1

        for context_length in range(max_context_length, minimum_length - 1, -1):
            replaced_index = last_expiry
            model = models[replaced_index]
            frequency = frequencies[replaced_index]
            last_expiry = model.expiry_previous
            models[first_expiry].expiry_previous = replaced_index
            model.expiry_next = first_expiry
            first_expiry = replaced_index

            if model.context_length != 0xFF:
                if model.context_length == 4:
                    drop_count -= 1
                    if not drop_count:
                        max_context_length = 3
                hash_value = context_hash(model.context, model.context_length)
                if hashes[hash_value].data == replaced_index:
                    hashes[hash_value].data = model.hash_pointer
                else:
                    index = hashes[hash_value].data
                    for _ in range(0x8000):
                        checked_index(index, len(models), "invalid SHSC hash chain")
                        if models[index].hash_pointer == replaced_index:
                            models[index].hash_pointer = model.hash_pointer
                            break
                        index = models[index].hash_pointer
                    else:
                        raise CorruptDataError("cyclic SHSC hash chain")
                if frequency.next != 0xFFFF:
                    index = frequency.next
                    for _ in range(0x8000):
                        checked_index(index, len(frequencies), "invalid SHSC frequency chain")
                        if frequencies[index].next == 0xFFFF:
                            frequencies[index].next = free_block_pointer
                            free_block_pointer = frequency.next
                            break
                        index = frequencies[index].next
                    else:
                        raise CorruptDataError("cyclic SHSC frequency chain")

            frequency.next = 0xFFFF
            frequency.frequency = 1
            frequency.character = character
            model.escape_frequency = 1
            model.frequency_total = 1
            model.context_length = context_length
            model.character_count = 0
            model.refresh_counter = 4
            model.context[:] = current_context
            hash_value = context_hash(current_context, context_length)
            model.hash_pointer = hashes[hash_value].data
            hashes[hash_value].data = replaced_index

        if len(output) >= output_size:
            raise CorruptDataError("decoded SHSC chunk exceeds declared size")
        output.append(character)
        current_context[1:] = current_context[:3]
        current_context[0] = character

    if len(output) != output_size:
        raise CorruptDataError("SHSC end marker precedes declared output size")
    return bytes(output)


def _apply_delta(data: bytes, mode: int) -> bytes:
    if mode == 0:
        return data
    if mode == 1:
        output = bytearray()
        accumulator = 0
        for value in data:
            accumulator = (accumulator + value) & 0xFF
            output.append(accumulator)
        return bytes(output)
    if mode not in (2, 3):
        raise CorruptDataError(f"unsupported SXSC delta mode {mode}")
    output = bytearray(len(data))
    half = len(data) >> 1
    accumulator = 0
    for source_index, destination_index in enumerate(range(0, len(data) - 1, 2)):
        if mode == 2:
            accumulator = (accumulator + data[source_index]) & 0xFF
            output[destination_index] = accumulator
            output[destination_index + 1] = data[half + source_index]
        else:
            output[destination_index] = data[half + source_index]
            accumulator = (accumulator + data[source_index]) & 0xFF
            output[destination_index + 1] = accumulator
    if len(data) & 1:
        output[-1] = data[-1]
    return bytes(output)


@register("SASC")
def decompress_sasc(payload: bytes, output_size: int, previous: bytes = b"") -> bytes:
    """Decode one SASC arithmetic-LZ chunk."""

    del previous
    if not payload:
        raise CorruptDataError("truncated SASC stream")
    return _apply_delta(_decode_sasc(payload[1:], output_size), payload[0])


@register("SHSC")
def decompress_shsc(payload: bytes, output_size: int, previous: bytes = b"") -> bytes:
    """Decode one SHSC finite-context arithmetic chunk."""

    del previous
    if not payload:
        raise CorruptDataError("truncated SHSC stream")
    return _apply_delta(_decode_shsc(payload[1:], output_size), payload[0])
