"""Importing this module registers every tool in the application.

Adding a new module here is the only wiring a new set of tools needs.
"""
from . import analysis      # noqa: F401
from . import classical     # noqa: F401
from . import classical_extra  # noqa: F401
from . import encodings     # noqa: F401
from . import enigma        # noqa: F401
from . import hashing       # noqa: F401
from . import identify      # noqa: F401
from . import interop       # noqa: F401
from . import keys          # noqa: F401
from . import live          # noqa: F401
from . import modern        # noqa: F401
from . import radio         # noqa: F401
from . import signals       # noqa: F401
from . import solver        # noqa: F401
from . import stego         # noqa: F401
from . import tokens        # noqa: F401

from .core import REGISTRY, by_category  # noqa: F401
