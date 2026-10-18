"""Public API. The native backend has process-global state and is not reentrant."""
from enum import IntEnum
import math
import operator
import os
import threading

from . import _native


class Parameters(IntEnum):
    STD128 = 0
    STD128_3 = 1
    STD128_LMKCDEY = 2
    STD128_3_LMKCDEY = 3
    STD192 = 4
    STD192_3 = 5
    STD192_LMKCDEY = 6
    STD192_3_LMKCDEY = 7
    STD256 = 8
    STD256_3 = 9
    STD256_LMKCDEY = 10
    STD256_3_LMKCDEY = 11
    TOY = 12


_current = None


def _width(bits):
    bits = operator.index(bits)
    if not 1 <= bits <= 64:
        raise ValueError("bits must be in [1, 64]")
    return bits


def _raw(value, bits, signed):
    value = operator.index(value)
    low = -(1 << (bits - 1)) if signed else 0
    high = (1 << (bits - int(signed))) - 1
    if not low <= value <= high:
        raise OverflowError(f"value must be in [{low}, {high}]")
    return value & ((1 << bits) - 1)


def _active():
    if _current is None:
        raise RuntimeError("Create a Context before constructing encrypted values")
    _current._check()
    return _current


class Context:
    """One active context per process. Use ``with Context(...)`` for cleanup.

    The default uses real encryption with upstream STD128_3 parameters.
    ``simulation=True`` explicitly selects the upstream plaintext simulator.
    """

    def __init__(self, *, parameters=Parameters.STD128_3, simulation=False,
                 optimized=True):
        global _current
        if _current is not None:
            raise RuntimeError("Only one ComputeFHE context may be active")
        self.parameters = Parameters(parameters)
        if type(simulation) is not bool or type(optimized) is not bool:
            raise TypeError("simulation and optimized must be bool")
        self.simulation = simulation
        self._owner = (os.getpid(), threading.get_ident())
        self._closed = True
        _native.init(int(self.parameters), optimized, simulation)
        self._closed = False
        _current = self

    def _check(self):
        if self._closed or _current is not self:
            raise RuntimeError("This value's ComputeFHE context is closed")
        if self._owner != (os.getpid(), threading.get_ident()):
            raise RuntimeError("Use ComputeFHE only in the creating process and thread")

    def close(self):
        global _current
        if not self._closed:
            self._check()
            _native.finalize()
            self._closed = True
            _current = None

    def __enter__(self):
        self._check()
        return self

    def __exit__(self, *exc):
        self.close()

    def integer(self, value=0, *, bits=32, signed=True, encrypted=True):
        self._check()
        return EncryptedInt(value, bits=bits, signed=signed, encrypted=encrypted)

    def fixed(self, value=0, *, bits=32, frac=16, signed=True, encrypted=True):
        self._check()
        return EncryptedFixed(value, bits=bits, frac=frac, signed=signed,
                              encrypted=encrypted)


class _Value:
    __hash__ = None

    @classmethod
    def _wrap(cls, value, context):
        obj = object.__new__(cls)
        obj._value, obj._context = value, context
        return obj

    @property
    def bits(self):
        return self._value.bits

    @property
    def signed(self):
        return self._value.signed

    def __bool__(self):
        raise TypeError("Encrypted values cannot control Python if/and/or; use select() or decrypt()")

    def __int__(self):
        raise TypeError("Use decrypt() explicitly")

    def __float__(self):
        raise TypeError("Use decrypt() explicitly")

    def __repr__(self):
        extra = f", frac={self.frac}" if isinstance(self, EncryptedFixed) else ""
        return f"{type(self).__name__}(bits={self.bits}, signed={self.signed}{extra})"

    def _compatible(self, other):
        self._context._check()
        other._context._check()
        if self._context is not other._context:
            raise ValueError("Values belong to different contexts")
        if self.bits != other.bits or self.signed != other.signed:
            raise TypeError("Operands must have matching widths and signedness; use cast()")

    def _comparison(self, other, op):
        other = self._coerce(other)
        if other is NotImplemented:
            return NotImplemented
        fn = _native.fixed_compare if isinstance(self, EncryptedFixed) else _native.compare
        return EncryptedInt._wrap(fn(op, self._value, other._value), self._context)

    def __eq__(self, other): return self._comparison(other, "eq")
    def __ne__(self, other): return self._comparison(other, "ne")
    def __lt__(self, other): return self._comparison(other, "lt")
    def __le__(self, other): return self._comparison(other, "le")
    def __gt__(self, other): return self._comparison(other, "gt")
    def __ge__(self, other): return self._comparison(other, "ge")
    def __add__(self, other): return self._binary(other, "add")
    def __radd__(self, other): return self._binary(other, "add", reverse=True)
    def __sub__(self, other): return self._binary(other, "sub")
    def __rsub__(self, other): return self._binary(other, "sub", reverse=True)
    def __mul__(self, other): return self._binary(other, "mul")
    def __rmul__(self, other): return self._binary(other, "mul", reverse=True)


class EncryptedInt(_Value):
    """Fixed-width integer. Arithmetic wraps modulo 2**bits; literals must fit."""

    def __init__(self, value=0, *, bits=32, signed=True, encrypted=True):
        self._context = _active()
        bits = _width(bits)
        if type(signed) is not bool or type(encrypted) is not bool:
            raise TypeError("signed and encrypted must be bool")
        self._value = _native.integer(_raw(value, bits, signed), bits, signed, encrypted)

    def decrypt(self):
        self._context._check()
        raw = _native.decrypt_int(self._value)
        if self.signed and raw & (1 << (self.bits - 1)):
            raw -= 1 << self.bits
        return raw

    def cast(self, *, bits=None, signed=None):
        """Sign/zero extend or truncate, then reinterpret the requested signedness."""
        self._context._check()
        bits = self.bits if bits is None else _width(bits)
        signed = self.signed if signed is None else signed
        if type(signed) is not bool:
            raise TypeError("signed must be bool")
        return EncryptedInt._wrap(_native.cast(self._value, bits, signed), self._context)

    def _coerce(self, other):
        self._context._check()
        if isinstance(other, EncryptedInt):
            self._compatible(other)
            return other
        if isinstance(other, int):
            return EncryptedInt(other, bits=self.bits, signed=self.signed, encrypted=False)
        return NotImplemented

    def _binary(self, other, op, reverse=False):
        other = self._coerce(other)
        if other is NotImplemented:
            return NotImplemented
        a, b = (other, self) if reverse else (self, other)
        fn = _native.bitwise if op in ("and", "or", "xor", "mod") else _native.arithmetic
        return EncryptedInt._wrap(fn(op, a._value, b._value), self._context)

    def __and__(self, other): return self._binary(other, "and")
    def __rand__(self, other): return self._binary(other, "and", True)
    def __or__(self, other): return self._binary(other, "or")
    def __ror__(self, other): return self._binary(other, "or", True)
    def __xor__(self, other): return self._binary(other, "xor")
    def __rxor__(self, other): return self._binary(other, "xor", True)

    def __invert__(self):
        self._context._check()
        return EncryptedInt._wrap(_native.invert(self._value), self._context)

    def __neg__(self):
        self._context._check()
        return EncryptedInt._wrap(_native.negate(self._value), self._context)

    def _shift(self, amount, left):
        self._context._check()
        amount = operator.index(amount)
        if amount < 0:
            raise ValueError("negative shift count")
        if amount >= self.bits:
            if not left and self.signed:
                return select(self < 0, self._coerce(-1), self._coerce(0))
            return self._coerce(0)
        return EncryptedInt._wrap(_native.shift(self._value, amount, left), self._context)

    def __lshift__(self, amount): return self._shift(amount, True)
    def __rshift__(self, amount): return self._shift(amount, False)

    def __divmod__(self, other):
        if isinstance(other, int) and other == 0:
            raise ZeroDivisionError("integer division by zero")
        other = self._coerce(other)
        if other is NotImplemented:
            return NotImplemented
        if not self.signed:
            return self._binary(other, "div"), self._binary(other, "mod")
        # Upstream DivU is unsigned. Compute magnitudes homomorphically and
        # restore Python's floor-division semantics without inspecting secrets.
        a_neg, b_neg = self < 0, other < 0
        a = select(a_neg, -self, self).cast(signed=False)
        b = select(b_neg, -other, other).cast(signed=False)
        q = a._binary(b, "div").cast(signed=True)
        remainder = a._binary(b, "mod")
        different_signs = a_neg ^ b_neg
        q = select(different_signs, -q, q)
        q = select(different_signs & (remainder != 0), q - 1, q)
        return q, self - q * other

    def __floordiv__(self, other):
        result = self.__divmod__(other)
        return NotImplemented if result is NotImplemented else result[0]

    def __mod__(self, other):
        result = self.__divmod__(other)
        return NotImplemented if result is NotImplemented else result[1]

    def __rfloordiv__(self, other):
        other = self._coerce(other)
        return NotImplemented if other is NotImplemented else other // self

    def __rmod__(self, other):
        other = self._coerce(other)
        return NotImplemented if other is NotImplemented else other % self


class EncryptedFixed(_Value):
    """Fixed-point values; conversion truncates toward zero at 2**-frac."""

    def __init__(self, value=0, *, bits=32, frac=16, signed=True, encrypted=True):
        self._context = _active()
        bits, frac = _width(bits), operator.index(frac)
        if not 0 <= frac < bits:
            raise ValueError("frac must be in [0, bits)")
        if type(signed) is not bool or type(encrypted) is not bool:
            raise TypeError("signed and encrypted must be bool")
        if not isinstance(value, (int, float)):
            raise TypeError("fixed-point values must be int or float")
        if not math.isfinite(value):
            raise ValueError("fixed-point values must be finite")
        scaled = math.trunc(value * (1 << frac))
        raw = _raw(scaled, bits, signed)
        self._value = _native.fixed(raw, bits, frac, signed, encrypted)

    @property
    def frac(self):
        return self._value.frac

    def decrypt(self):
        self._context._check()
        raw = _native.decrypt_fixed(self._value)
        if self.signed and raw & (1 << (self.bits - 1)):
            raw -= 1 << self.bits
        return raw / (1 << self.frac)

    def _coerce(self, other):
        self._context._check()
        if isinstance(other, EncryptedFixed):
            self._compatible(other)
            if self.frac != other.frac:
                raise TypeError("Operands must have matching fractional widths")
            return other
        if isinstance(other, (int, float)):
            return EncryptedFixed(other, bits=self.bits, frac=self.frac,
                                  signed=self.signed, encrypted=False)
        return NotImplemented

    def _binary(self, other, op, reverse=False):
        other = self._coerce(other)
        if other is NotImplemented:
            return NotImplemented
        a, b = (other, self) if reverse else (self, other)
        return EncryptedFixed._wrap(_native.fixed_arithmetic(op, a._value, b._value), self._context)

    def __neg__(self):
        self._context._check()
        return EncryptedFixed._wrap(_native.fixed_negate(self._value), self._context)


def select(condition, when_true, when_false):
    """Evaluate a native multiplexer. Both branches are already computed."""
    if not isinstance(condition, EncryptedInt) or condition.bits != 1 or condition.signed:
        raise TypeError("condition must be an encrypted unsigned one-bit value")
    condition._context._check()
    if not isinstance(when_true, (EncryptedInt, EncryptedFixed)):
        if not isinstance(when_false, (EncryptedInt, EncryptedFixed)):
            raise TypeError("At least one branch must be an encrypted value")
        when_true = when_false._coerce(when_true)
    if when_true is NotImplemented:
        raise TypeError("Unsupported branch type")
    when_false = when_true._coerce(when_false)
    if when_false is NotImplemented:
        raise TypeError("Branches must have compatible types")
    if when_true._context is not condition._context:
        raise ValueError("Condition and branches belong to different contexts")
    fixed = isinstance(when_true, EncryptedFixed)
    cls, fn = (EncryptedFixed, _native.fixed_select) if fixed else (EncryptedInt, _native.select)
    return cls._wrap(fn(condition._value, when_true._value, when_false._value), condition._context)


class EncryptedVector:
    """Homogeneous values with oblivious O(n) encrypted reads and writes.

    An out-of-range encrypted index reads zero and writes nothing. Negative
    plaintext indices follow Python's sequence convention.
    """

    def __init__(self, values):
        self._context = _active()
        self._values = list(values)
        if not self._values or not isinstance(self._values[0], (EncryptedInt, EncryptedFixed)):
            raise ValueError("Provide a nonempty sequence of encrypted values")
        first = self._values[0]
        for value in self._values:
            if not isinstance(value, type(first)) and not (
                isinstance(first, EncryptedInt) and isinstance(value, EncryptedInt)
            ):
                raise TypeError("Vector elements must have the same type")
            first._coerce(value)

    def __len__(self):
        return len(self._values)

    def _index(self, index):
        self._context._check()
        index._context._check()
        if index._context is not self._context:
            raise ValueError("Index belongs to a different context")
        maximum = (1 << (index.bits - int(index.signed))) - 1
        if len(self) - 1 > maximum:
            raise ValueError("Index type cannot represent all vector positions")

    def __getitem__(self, index):
        self._context._check()
        if not isinstance(index, EncryptedInt):
            return self._values[operator.index(index)]
        self._index(index)
        result = self._values[0]._coerce(0)
        for position, value in enumerate(self._values):
            result = select(index == position, value, result)
        return result

    def __setitem__(self, index, value):
        self._context._check()
        value = self._values[0]._coerce(value)
        if value is NotImplemented:
            raise TypeError("Unsupported vector value")
        if not isinstance(index, EncryptedInt):
            self._values[operator.index(index)] = value
            return
        self._index(index)
        self._values = [select(index == position, value, old)
                        for position, old in enumerate(self._values)]


def _integer_type(name, bits, signed):
    def init(self, value=0, *, encrypted=True):
        EncryptedInt.__init__(self, value, bits=bits, signed=signed, encrypted=encrypted)
    return type(name, (EncryptedInt,), {"__init__": init, "__module__": "computefhe"})


Ebool = _integer_type("Ebool", 1, False)
Eint8 = _integer_type("Eint8", 8, True)
Euint8 = _integer_type("Euint8", 8, False)
Eint16 = _integer_type("Eint16", 16, True)
Euint16 = _integer_type("Euint16", 16, False)
Eint32 = _integer_type("Eint32", 32, True)
Euint32 = _integer_type("Euint32", 32, False)
Eint64 = _integer_type("Eint64", 64, True)
Euint64 = _integer_type("Euint64", 64, False)
