# Generates a gamesense signature.
# @author picocode
# @category gamesense
# @keybinding Ctrl-G
# @menupath
# @toolbar

from __future__ import print_function
import collections
import ghidra.program.model.lang.OperandType as OperandType
import ghidra.program.model.lang.Register as Register
import ghidra.program.model.address.AddressSet as AddressSet


BytePattern = collections.namedtuple('BytePattern', ['is_wildcard','byte'])


def gamesense_sig(self):
    return (r'\x{:02X}'.format(self.byte) if not self.is_wildcard else r'\xCC')


BytePattern.sig_str = gamesense_sig

def shouldMaskOperand(ins, opIndex):
    optype = ins.getOperandType(opIndex)
    return optype & OperandType.DYNAMIC or optype & OperandType.ADDRESS


def getMaskedInstruction(ins):
    mask = [0] * ins.length

    proto = ins.getPrototype()
    for op in range(proto.getNumOperands()):
        if shouldMaskOperand(ins, op):
            mask = [m | v & 0xFF for (m, v) in zip(mask,
                proto.getOperandValueMask(op).getBytes())]

    for (m, b) in zip(mask, ins.getBytes()):
        if m == 0xFF:
            yield BytePattern(is_wildcard=True, byte=None)
        else:
            yield BytePattern(byte=b & 0xFF, is_wildcard=False)


if __name__ == '__main__':
    fm = currentProgram.getFunctionManager()
    fn = fm.getFunctionContaining(currentAddress)
    if not fn:
        raise Exception('NOT IN A FUNCTION')

    cm = currentProgram.getCodeManager()
    ins = cm.getInstructionContaining(currentAddress)

    pattern = ''
    byte_pattern = []
    matches = []

    while fm.getFunctionContaining(ins.getAddress()) == fn:
        for entry in getMaskedInstruction(ins):
            byte_pattern.append(entry)
            if entry.is_wildcard:
                pattern += '.'
            else:
                pattern += r'\x{:02x}'.format(entry.byte)
        ins = ins.getNext()

        if 0 < len(matches) < 128:
            match_set = AddressSet()
            for addr in matches:
                match_set.add(addr, addr.add(len(byte_pattern)))
            matches = findBytes(match_set, pattern, 128, 1)
        else:
            matches = findBytes((matches[0] if len(matches) else None),pattern, 128)

        if len(matches) < 2:
            break
    if not len(matches) == 1:
        print('SIGNATURE MATCHED', len(matches), 'LOCATIONS:', *matches)
        raise Exception('COULD NOT FIND UNIQUE SIGNATURE')
    else:
        print('\nSignature for', fn.getName(), 'in ', currentProgram.getName())
        print(''.join(b.sig_str() for b in byte_pattern))
